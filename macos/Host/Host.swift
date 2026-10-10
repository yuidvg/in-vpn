import AppKit
import Darwin
import Network
import NetworkExtension
import SystemExtensions

private let providerID = "jp.diverge.invpn.proxy"

private func finish<T: Encodable>(_ value: T, code: Int32 = 0) -> Never {
    let encoded = (try? JSONEncoder().encode(value)) ?? Data("{\"success\":false,\"reason\":\"encoding_failed\"}".utf8)
    FileHandle.standardOutput.write(encoded + Data([10]))
    exit(code)
}

private func failure(_ reason: String, code: Int32 = 1) -> Never {
    finish(NativeReply(success: false, reason: reason), code: code)
}

private func progress(_ message: String) {
    FileHandle.standardError.write(Data((message + "\n").utf8))
}

// The delegate owns an OS activation request until macOS reports completion.
private final class Activation: NSObject, OSSystemExtensionRequestDelegate {
    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction { .replace }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        progress("Allow InVPN in System Settings > General > Login Items & Extensions > Network Extensions.")
    }

    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        finish(NativeReply(success: result == .completed,
                           reason: result == .completed ? "extension_activated" : "reboot_required"))
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        let value = error as NSError
        progress("activation_error_domain=\(value.domain) code=\(value.code)")
        finish(NativeReply(success: false, reason: "extension_activation_failed",
                           errorDomain: value.domain, errorCode: value.code), code: 1)
    }
}

private func privateRouteFile(_ path: String) -> RouteInput {
    guard path.hasPrefix("/") else { failure("route_file_must_be_absolute", code: 2) }
    let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
    guard descriptor >= 0 else { failure("route_file_unreadable") }
    defer { close(descriptor) }
    var attributes = stat()
    guard fstat(descriptor, &attributes) == 0,
          attributes.st_mode & S_IFMT == S_IFREG,
          attributes.st_uid == getuid(), attributes.st_mode & 0o077 == 0,
          attributes.st_size > 0, attributes.st_size <= 65536 else {
        failure("route_file_requires_private_regular_file")
    }
    let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
    guard let data = try? file.readToEnd(),
          let route = try? JSONDecoder().decode(RouteInput.self, from: data),
          route.pid > 0, route.port != 0,
          route.secret.utf8.count >= 32, route.secret.utf8.count <= 256 else {
        failure("invalid_route_file", code: 2)
    }
    return route
}

private func send(_ request: ProviderRequest, session: NETunnelProviderSession,
                  completion: @escaping (Data?) -> Void) {
    guard let encoded = try? JSONEncoder().encode(request) else { failure("encoding_failed") }
    do { try session.sendProviderMessage(encoded, responseHandler: completion) }
    catch { failure("provider_message_failed") }
}

private func waitUntilReady(_ manager: NETransparentProxyManager, deadline: Date) {
    guard Date() < deadline else { failure("provider_ready_timeout") }
    guard let session = manager.connection as? NETunnelProviderSession else { failure("provider_session_missing") }
    if session.status == .connected {
        send(ProviderRequest(operation: "status", route: nil, pid: nil), session: session) { data in
            if let data, let reply = try? JSONDecoder().decode(NativeReply.self, from: data), reply.success, reply.ready == true {
                finish(reply)
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) { waitUntilReady(manager, deadline: deadline) }
        }
    } else if session.status == .invalid || session.status == .disconnecting {
        failure("provider_disconnected")
    } else {
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) { waitUntilReady(manager, deadline: deadline) }
    }
}

@main
struct Host {
    private static let activation = Activation()

    static func main() {
        let arguments = Array(CommandLine.arguments.dropFirst())
        guard let action = arguments.first,
              ["activate", "status", "start", "route", "unroute", "events", "remove"].contains(action) else {
            failure("usage_activate_status_start_route_unroute_events_remove", code: 2)
        }
        _ = NSApplication.shared
        // A missing IPC response must never leave the command launcher gated
        // indefinitely. OS approval can be retried after this deadline.
        DispatchQueue.main.asyncAfter(deadline: .now() + (action == "activate" ? 120 : 60)) { failure("native_command_timeout") }
        if action == "activate" {
            guard arguments.count == 1 else { failure("unexpected_arguments", code: 2) }
            let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: providerID, queue: .main)
            request.delegate = activation
            OSSystemExtensionManager.shared.submitRequest(request)
        } else {
            NETransparentProxyManager.loadAllFromPreferences { managers, error in
                guard error == nil else { failure("configuration_load_failed") }
                let existing = managers?.first { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == providerID }
                if action == "start" {
                    guard arguments.count == 3, IPv4Address(arguments[1]) != nil,
                          let port = UInt16(arguments[2]), port != 0, port != 53 else {
                        failure("start_requires_literal_ipv4_and_non_dns_tcp_port", code: 2)
                    }
                    let manager = existing ?? NETransparentProxyManager()
                    if manager.connection.status == .connected || manager.connection.status == .connecting {
                        let current = (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
                        guard current?["ip"] as? String == arguments[1], current?["port"] as? Int == Int(port) else {
                            failure("another_destination_active")
                        }
                        waitUntilReady(manager, deadline: Date().addingTimeInterval(45))
                        return
                    }
                    let configuration = NETunnelProviderProtocol()
                    configuration.providerBundleIdentifier = providerID
                    configuration.serverAddress = "InVPN experimental scoped TCP"
                    configuration.providerConfiguration = ["ip": arguments[1], "port": Int(port)]
                    manager.protocolConfiguration = configuration
                    manager.localizedDescription = "InVPN (experimental scoped TCP)"
                    manager.isEnabled = true
                    manager.saveToPreferences { error in
                        guard error == nil else { failure("configuration_save_failed") }
                        manager.loadFromPreferences { error in
                            guard error == nil else { failure("configuration_reload_failed") }
                            do { try manager.connection.startVPNTunnel() }
                            catch { failure("provider_start_failed") }
                            waitUntilReady(manager, deadline: Date().addingTimeInterval(45))
                        }
                    }
                } else if action == "remove" {
                    guard arguments.count == 1 else { failure("unexpected_arguments", code: 2) }
                    guard let manager = existing else {
                        finish(NativeReply(success: true, reason: "configuration_absent", ready: false, configured: false))
                    }
                    manager.connection.stopVPNTunnel()
                    manager.removeFromPreferences { error in
                        guard error == nil else { failure("configuration_remove_failed") }
                        finish(NativeReply(success: true, reason: "configuration_removed", ready: false, configured: false))
                    }
                } else if let manager = existing {
                    guard let session = manager.connection as? NETunnelProviderSession else { failure("provider_session_missing") }
                    if action == "status" && session.status != .connected {
                        finish(NativeReply(success: true, reason: "provider_disconnected", ready: false, configured: true))
                    }
                    guard session.status == .connected else { failure("provider_not_connected") }
                    let request: ProviderRequest
                    switch action {
                    case "route":
                        guard arguments.count == 2 else { failure("route_requires_private_json_path", code: 2) }
                        let input = privateRouteFile(arguments[1])
                        guard let identity = ProcessIdentity.current(pid: input.pid) else { failure("process_identity_unavailable") }
                        let route = Route(pid: input.pid, port: input.port, secret: input.secret, identity: identity)
                        request = ProviderRequest(operation: "route", route: route, pid: nil)
                    case "unroute":
                        guard arguments.count == 2, let pid = Int32(arguments[1]), pid > 0 else { failure("unroute_requires_pid", code: 2) }
                        request = ProviderRequest(operation: "unroute", route: nil, pid: pid)
                    default:
                        guard arguments.count == 1 else { failure("unexpected_arguments", code: 2) }
                        request = ProviderRequest(operation: action, route: nil, pid: nil)
                    }
                    send(request, session: session) { data in
                        guard let data else { failure("provider_response_missing") }
                        if action == "events" {
                            guard let reply = try? JSONDecoder().decode(EventsReply.self, from: data), reply.success else { failure("invalid_provider_response") }
                            finish(reply)
                        }
                        guard let reply = try? JSONDecoder().decode(NativeReply.self, from: data) else { failure("invalid_provider_response") }
                        finish(reply, code: reply.success ? 0 : 1)
                    }
                } else if action == "status" {
                    finish(NativeReply(success: true, reason: "configuration_absent", ready: false, configured: false))
                } else { failure("configuration_absent") }
            }
        }
        NSApplication.shared.run()
    }
}
