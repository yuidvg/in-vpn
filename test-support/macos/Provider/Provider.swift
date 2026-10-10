import Foundation
import Network
import NetworkExtension

private struct Observation: Codable {
    let time: Double
    let token: String?
    let pid: UInt32?
    let protocolName: String
    let decision: String
    let signingIdentifier: String
}

private struct ProviderState: Codable {
    let ready: Bool
    let settings: String
    let eventCount: Int
    let providerPID: Int32
}

// NEProvider requires inheritance. Lock protects callback-owned observation state.
final class ProbeProvider: NETransparentProxyProvider {
    private let lock = NSLock()
    private var observations: [Observation] = []
    private var blockPID = -1
    private var routes: [Int: RelayRoute] = [:]
    private var relays: [UUID: ProbeRelay] = [:]
    private var ready = false
    private var appliedSettings = ""

    override func startProxy(options: [String: Any]?, completionHandler: @escaping (Error?) -> Void) {
        let config = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        guard let port = config?["port"] as? Int, port > 0, port != 53, port <= 65535 else {
            completionHandler(NSError(domain: "InVPNProbe", code: 1)); return
        }
        blockPID = config?["blockPID"] as? Int ?? -1
        let ip = config?["ip"] as? String ?? "127.0.0.1"
        guard IPv4Address(ip) != nil else {
            completionHandler(NSError(domain: "InVPNProbe", code: 3)); return
        }
        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        // Separate TCP/UDP destination rules diagnose the earlier .any rule.
        // Matching remains confined to one declared test address and port.
        let endpoint = NWHostEndpoint(hostname: ip, port: String(port))
        settings.includedNetworkRules = [NENetworkRule(destinationNetwork: endpoint, prefix: 32, protocol: .TCP), NENetworkRule(destinationNetwork: endpoint, prefix: 32, protocol: .UDP)]
        // This Mac's system curl reaches the test IPv4 literal through NAT64.
        // Match only that observed destination, never the entire NAT64 prefix.
        if ip == "1.1.1.1" {
            let nat64 = NWHostEndpoint(hostname: "64:ff9b::101:101", port: String(port))
            settings.includedNetworkRules? += [NENetworkRule(destinationNetwork: nat64, prefix: 128, protocol: .TCP), NENetworkRule(destinationNetwork: nat64, prefix: 128, protocol: .UDP)]
        }
        if config?["dnsProbe"] as? Bool == true {
            let domain = NWHostEndpoint(hostname: "invpn-feasibility.example.com", port: "53")
            settings.includedNetworkRules? += [NENetworkRule(destinationHost: domain, protocol: .TCP), NENetworkRule(destinationHost: domain, protocol: .UDP)]
        }
        settings.excludedNetworkRules = []
        setTunnelNetworkSettings(settings) { error in
            self.lock.lock()
            self.ready = error == nil
            self.appliedSettings = "destination=\(ip):\(port)/32; nat64=\(ip == "1.1.1.1" ? "64:ff9b::101:101/128" : "none"); dnsProbe=\(config?["dnsProbe"] as? Bool == true); protocols=TCP,UDP; direction=outbound; excluded=[]; build=10"
            self.lock.unlock()
            completionHandler(error)
        }
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        let token = flow.metaData.sourceAppAuditToken
        // Darwin audit_token_t has eight uint32 fields; field 5 is pid.
        // Full token is retained; bare PID selection is an F01-only test fixture.
        let pid: UInt32? = token.flatMap { data in
            guard data.count == 32 else { return nil }
            return data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 20, as: UInt32.self) }
        }
        lock.lock()
        let route = pid.flatMap { value in
            routes[Int(value)] ?? routes.values.first { $0.selection == "session" && getsid(Int32(value)) == Int32($0.pid) }
        }
        let blocked = pid.map { Int($0) == blockPID } ?? false
        lock.unlock()
        let record = Observation(time: Date().timeIntervalSince1970, token: token?.base64EncodedString(), pid: pid, protocolName: flow is NEAppProxyTCPFlow ? "tcp" : "udp", decision: route != nil ? "relay" : blocked ? "accept_and_close" : "decline_direct", signingIdentifier: flow.metaData.sourceAppSigningIdentifier)
        lock.lock()
        if observations.count < 10000 { observations.append(record) }
        lock.unlock()
        if let route {
            let id = UUID()
            let relay = ProbeRelay(flow: flow, route: route) { [weak self] in
                self?.lock.lock(); self?.relays.removeValue(forKey: id); self?.lock.unlock()
            }
            lock.lock(); relays[id] = relay; lock.unlock()
            relay.start()
            return true
        }
        if blocked {
            let error = NSError(domain: NSPOSIXErrorDomain, code: Int(ECONNREFUSED))
            flow.closeReadWithError(error)
            flow.closeWriteWithError(error)
            return true
        }
        return false
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        if let route = try? JSONDecoder().decode(RelayRoute.self, from: messageData), route.pid > 0, route.port > 0, route.secret.count >= 32 {
            lock.lock(); routes[route.pid] = route; lock.unlock()
            completionHandler?(Data("route_registered".utf8)); return
        }
        if messageData == Data("crash".utf8) {
            completionHandler?(Data("test_crash_scheduled".utf8))
            DispatchQueue.global().asyncAfter(deadline: .now() + 0.2) { abort() }
            return
        }
        if let message = String(data: messageData, encoding: .utf8), message.hasPrefix("select:"), let pid = Int(message.dropFirst(7)), pid > 0 {
            lock.lock()
            blockPID = pid
            observations = []
            lock.unlock()
            completionHandler?(Data("selected_test_pid".utf8)); return
        }
        if messageData == Data("status".utf8) {
            lock.lock()
            let state = ProviderState(ready: ready, settings: appliedSettings, eventCount: observations.count, providerPID: getpid())
            lock.unlock()
            completionHandler?(try? JSONEncoder().encode(state)); return
        }
        guard messageData == Data("events".utf8) else { completionHandler?(nil); return }
        lock.lock()
        let snapshot = observations
        lock.unlock()
        completionHandler?(try? JSONEncoder().encode(snapshot))
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) { completionHandler() }
}
