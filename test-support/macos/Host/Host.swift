import AppKit
import NetworkExtension
import Network
import SystemExtensions

private let providerID = "jp.diverge.invpn.feasibility.proxy"

private func progress(_ message: String) {
    FileHandle.standardError.write(Data((message + "\n").utf8))
}

private func finish(_ message: String, code: Int32 = 0) -> Never {
    print(message)
    fflush(stdout)
    exit(code)
}

// Retained delegate represents the lifetime of an OS activation request.
final class Activation: NSObject, OSSystemExtensionRequestDelegate {
    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction { .replace }
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        print("OS_USER_APPROVAL_REQUIRED: Allow InVPN Feasibility in System Settings > General > Login Items & Extensions > Network Extensions")
        fflush(stdout)
    }
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) { finish("activation_result=\(result.rawValue)") }
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) { finish("activation_error=\(error)", code: 1) }
}

@main
struct Host {
    private static let activation = Activation()

    static func main() {
        let args = Array(CommandLine.arguments.dropFirst())
        guard let action = args.first else { finish("Usage: activate | deactivate | start PORT [BLOCK_PID] [IP] [dns] | select PID | events | status | crash | stop | remove", code: 2) }
        _ = NSApplication.shared
        if action == "guard-start" || action == "guard-remove" {
            let manager = NEFilterManager.shared()
            manager.loadFromPreferences { error in
                if let error { finish("guard_load_error=\(error)", code: 1) }
                if action == "guard-remove" {
                    manager.removeFromPreferences { error in
                        if let error { finish("guard_remove_error=\(error)", code: 1) }
                        finish("guard_configuration_removed")
                    }
                    return
                }
                guard args.count >= 4, IPv4Address(args[1]) != nil, let port = Int(args[2]), port > 0, let pid = Int(args[3]), pid > 0 else { finish("guard-start IP PORT PID [CRASH_SECONDS]", code: 2) }
                let config = NEFilterProviderConfiguration()
                config.filterSockets = true
                config.filterDataProviderBundleIdentifier = "jp.diverge.invpn.feasibility.guard"
                config.vendorConfiguration = ["ip": args[1], "port": port, "pid": pid, "crashAfter": args.count > 4 ? Double(args[4]) ?? 0 : 0]
                manager.providerConfiguration = config
                manager.localizedDescription = "InVPN Feasibility Guard (one test endpoint)"
                manager.isEnabled = true
                manager.saveToPreferences { error in
                    if let error { finish("guard_save_error=\(error)", code: 1) }
                    finish("guard_saved; verify enforcement separately")
                }
            }
        } else if action == "activate" || action == "deactivate" || action == "guard-activate" {
            let providerID = action == "guard-activate" ? "jp.diverge.invpn.feasibility.guard" : providerID
            let request = action != "deactivate"
                ? OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: providerID, queue: .main)
                : OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: providerID, queue: .main)
            request.delegate = activation
            OSSystemExtensionManager.shared.submitRequest(request)
        } else {
            NETransparentProxyManager.loadAllFromPreferences { managers, error in
                if let error { finish("load_error=\(error)", code: 1) }
                let existing = managers?.first { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == providerID }
                if action == "start" {
                    guard args.count >= 2, let port = UInt16(args[1]), port != 0, port != 53 else { finish("Use a nonzero non-DNS test receiver port", code: 2) }
                    let ip = args.count > 3 ? args[3] : "127.0.0.1"
                    guard IPv4Address(ip) != nil else { finish("Destination must be a declared test endpoint", code: 2) }
                    let manager = existing ?? NETransparentProxyManager()
                    let config = NETunnelProviderProtocol()
                    config.providerBundleIdentifier = providerID
                    config.serverAddress = "in-vpn feasibility test endpoint"
                    config.providerConfiguration = ["port": Int(port), "blockPID": args.count > 2 ? Int(args[2]) ?? -1 : -1, "ip": ip, "dnsProbe": args.count > 4 && args[4] == "dns"]
                    manager.protocolConfiguration = config
                    manager.localizedDescription = "InVPN Feasibility (one test endpoint)"
                    manager.isEnabled = true
                    progress("saving_configuration")
                    manager.saveToPreferences { error in
                        if let error { finish("save_error=\(error)", code: 1) }
                        progress("saved_configuration")
                        manager.loadFromPreferences { error in
                            if let error { finish("reload_error=\(error)", code: 1) }
                            do { try manager.connection.startVPNTunnel(); finish("start_requested; verify connected status and callbacks separately") }
                            catch { finish("start_error=\(error)", code: 1) }
                        }
                    }
                } else if let manager = existing {
                    switch action {
                    case "stop": manager.connection.stopVPNTunnel(); finish("stop_requested")
                    case "remove":
                        manager.connection.stopVPNTunnel()
                        manager.removeFromPreferences { error in
                            if let error { finish("remove_error=\(error)", code: 1) }
                            finish("configuration_removed")
                        }
                    case "events", "status", "select", "crash", "route":
                        guard let session = manager.connection as? NETunnelProviderSession else { finish("no_session", code: 1) }
                        let message: String
                        if action == "route" {
                            guard args.count == 2, let data = try? Data(contentsOf: URL(fileURLWithPath: args[1])), let value = String(data: data, encoding: .utf8) else { finish("route requires a local JSON file", code: 2) }
                            message = value
                        } else if action == "select" {
                            guard args.count == 2, let pid = Int32(args[1]), pid > 0 else { finish("select requires a positive test PID", code: 2) }
                            message = "select:\(pid)"
                        } else { message = action }
                        do {
                            try session.sendProviderMessage(Data(message.utf8)) { data in
                                finish(data.flatMap { String(data: $0, encoding: .utf8) } ?? "no_response", code: data == nil ? 1 : 0)
                            }
                        } catch { finish("message_error=\(error)", code: 1) }
                    default: finish("unknown_action", code: 2)
                    }
                } else { finish("no_configuration", code: 1) }
            }
        }
        NSApplication.shared.run()
    }
}
