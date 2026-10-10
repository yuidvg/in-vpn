import Foundation
import Network
import NetworkExtension

private struct RegisteredRoute {
    let value: Route
    let auditGeneration: UInt32?
}

// NEProvider requires reference identity. This boundary owns OS flows and a
// lock-protected registry; observations contain metadata, never audit tokens.
final class InVPNProvider: NETransparentProxyProvider {
    private let lock = NSLock()
    private var routes: [Int32: RegisteredRoute] = [:]
    private var relays: [UUID: TCPRelay] = [:]
    private var events: [FlowEvent] = []
    private var ready = false
    private var destinationIP = ""
    private var destinationPort: UInt16 = 0

    override func startProxy(options: [String: Any]?, completionHandler: @escaping (Error?) -> Void) {
        let configuration = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        guard let ip = configuration?["ip"] as? String, let ipv4 = IPv4Address(ip),
              let portNumber = configuration?["port"] as? Int,
              let port = UInt16(exactly: portNumber), port != 0, port != 53 else {
            completionHandler(NSError(domain: "InVPN", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "A literal IPv4 address and non-DNS TCP port are required."]))
            return
        }
        let bytes = Array(ipv4.rawValue)
        let tailA = (UInt16(bytes[0]) << 8) | UInt16(bytes[1])
        let tailB = (UInt16(bytes[2]) << 8) | UInt16(bytes[3])
        let nat64 = "64:ff9b::\(String(tailA, radix: 16)):\(String(tailB, radix: 16))"
        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.includedNetworkRules = [
            NENetworkRule(destinationNetworkEndpoint: .hostPort(host: NWEndpoint.Host(ip), port: NWEndpoint.Port(integerLiteral: port)), prefix: 32, protocol: .TCP),
            NENetworkRule(destinationNetworkEndpoint: .hostPort(host: NWEndpoint.Host(nat64), port: NWEndpoint.Port(integerLiteral: port)), prefix: 128, protocol: .TCP)
        ]
        settings.excludedNetworkRules = []
        setTunnelNetworkSettings(settings) { error in
            self.lock.lock()
            self.destinationIP = ip
            self.destinationPort = port
            self.ready = error == nil
            self.lock.unlock()
            completionHandler(error)
        }
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        // audit_token_t consists of eight uint32 words; word 5 is PID and word
        // 7 is PID generation. Neither the token nor generation is exported.
        let identity = flow.metaData.sourceAppAuditToken.flatMap { token -> (Int32, UInt32)? in
            guard token.count == 32 else { return nil }
            return token.withUnsafeBytes {
                (Int32(bitPattern: $0.loadUnaligned(fromByteOffset: 20, as: UInt32.self)),
                 $0.loadUnaligned(fromByteOffset: 28, as: UInt32.self))
            }
        }
        let pid = identity?.0
        lock.lock()
        let registered = pid.flatMap { routes[$0] }
        let ip = destinationIP
        let port = destinationPort
        lock.unlock()
        guard let registered, let identity else {
            record(pid: pid, decision: "unselected_direct", tcp: flow is NEAppProxyTCPFlow)
            return false
        }
        // Once a PID is selected, attribution errors are consumed and closed.
        // The extension itself can still fail open when macOS restarts it.
        guard let tcp = flow as? NEAppProxyTCPFlow,
              ProcessIdentity.current(pid: identity.0) == registered.value.identity,
              registered.auditGeneration == nil || registered.auditGeneration == identity.1 else {
            record(pid: pid, decision: "selected_identity_rejected", tcp: flow is NEAppProxyTCPFlow)
            close(flow, error: ECONNREFUSED)
            return true
        }
        let id = UUID()
        let relay = TCPRelay(flow: tcp, route: registered.value, destinationIP: ip, destinationPort: port) { [weak self] in
            guard let self else { return }
            self.lock.lock(); self.relays.removeValue(forKey: id); self.lock.unlock()
        }
        lock.lock()
        // A concurrent unroute acknowledgement must stay final. Revalidate the
        // registration under the same lock used to bind its audit generation
        // and reserve the relay; a stale snapshot never recreates a route.
        guard ready, let current = routes[identity.0],
              current.value.pid == registered.value.pid,
              current.value.identity == registered.value.identity,
              current.value.port == registered.value.port,
              current.value.secret == registered.value.secret,
              current.auditGeneration == nil || current.auditGeneration == identity.1 else {
            lock.unlock()
            record(pid: pid, decision: "selected_registration_changed", tcp: true)
            close(flow, error: ECONNREFUSED)
            return true
        }
        routes[identity.0] = RegisteredRoute(value: current.value, auditGeneration: identity.1)
        relays[id] = relay
        lock.unlock()
        record(pid: pid, decision: "selected_relay", tcp: true)
        relay.start()
        return true
    }

    private func record(pid: Int32?, decision: String, tcp: Bool) {
        lock.lock()
        if events.count == 10000 { events.removeFirst() }
        events.append(FlowEvent(time: Date().timeIntervalSince1970, pid: pid,
                                protocolName: tcp ? "tcp" : "other", decision: decision))
        lock.unlock()
    }

    private func close(_ flow: NEAppProxyFlow, error: Int32) {
        let value = NSError(domain: NSPOSIXErrorDomain, code: Int(error))
        flow.closeReadWithError(value)
        flow.closeWriteWithError(value)
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        guard let message = try? JSONDecoder().decode(ProviderRequest.self, from: messageData) else {
            completionHandler?(try? JSONEncoder().encode(NativeReply(success: false, reason: "invalid_message")))
            return
        }
        let reply: NativeReply
        switch message.operation {
        case "route":
            guard let route = message.route, route.pid > 0, route.port != 0,
                  route.secret.utf8.count >= 32, route.secret.utf8.count <= 256,
                  ProcessIdentity.current(pid: route.pid) == route.identity else {
                completionHandler?(try? JSONEncoder().encode(NativeReply(success: false, reason: "process_identity_unavailable")))
                return
            }
            lock.lock()
            guard ready else {
                lock.unlock()
                completionHandler?(try? JSONEncoder().encode(NativeReply(success: false, reason: "provider_not_ready")))
                return
            }
            // One command root is selected per native session. Descendants are
            // intentionally outside this experimental contract.
            guard routes.isEmpty || routes[route.pid] != nil else {
                lock.unlock()
                completionHandler?(try? JSONEncoder().encode(NativeReply(success: false, reason: "another_root_selected")))
                return
            }
            routes[route.pid] = RegisteredRoute(value: route, auditGeneration: nil)
            lock.unlock()
            reply = NativeReply(success: true, reason: "route_registered", ready: true)
        case "unroute":
            guard let pid = message.pid else {
                completionHandler?(try? JSONEncoder().encode(NativeReply(success: false, reason: "invalid_pid")))
                return
            }
            lock.lock(); let removed = routes.removeValue(forKey: pid) != nil; lock.unlock()
            reply = NativeReply(success: removed, reason: removed ? "route_removed" : "route_not_found")
        case "status":
            lock.lock()
            reply = NativeReply(success: true, ready: ready, configured: true, providerPID: getpid(),
                                routeCount: routes.count, eventCount: events.count,
                                activeFlows: relays.count, destination: "\(destinationIP):\(destinationPort)")
            lock.unlock()
        case "events":
            lock.lock(); let snapshot = events; lock.unlock()
            completionHandler?(try? JSONEncoder().encode(EventsReply(success: true, events: snapshot)))
            return
        default: reply = NativeReply(success: false, reason: "unknown_operation")
        }
        completionHandler?(try? JSONEncoder().encode(reply))
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        lock.lock()
        ready = false
        routes = [:]
        let active = Array(relays.values)
        lock.unlock()
        active.forEach { $0.cancel() }
        completionHandler()
    }
}
