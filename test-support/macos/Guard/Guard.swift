import Foundation
import Network
import NetworkExtension

// Separate extension process tests whether filtering can independently guard
// the one declared receiver port. All unrelated traffic uses the default allow.
final class GuardProvider: NEFilterDataProvider {
    private var blockedPID: UInt32 = 0
    private var crashTask: DispatchWorkItem?
    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        let config = filterConfiguration.vendorConfiguration ?? [:]
        guard let port = config["port"] as? Int, port > 0,
              let ip = config["ip"] as? String, IPv4Address(ip) != nil,
              let pid = config["pid"] as? Int, pid > 0 else {
            completionHandler(NSError(domain: "InVPNGuard", code: 1)); return
        }
        blockedPID = UInt32(pid)
        let endpoint = NWHostEndpoint(hostname: ip, port: String(port))
        let network = NENetworkRule(destinationNetwork: endpoint, prefix: 32, protocol: .any)
        let rule = NEFilterRule(networkRule: network, action: .filterData)
        apply(NEFilterSettings(rules: [rule], defaultAction: .allow)) { error in
            completionHandler(error)
            if error == nil, let seconds = config["crashAfter"] as? Double, seconds > 0 {
                let task = DispatchWorkItem { abort() }
                self.crashTask = task
                DispatchQueue.global().asyncAfter(deadline: .now() + seconds, execute: task)
            }
        }
    }
    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        crashTask?.cancel(); crashTask = nil
        completionHandler()
    }
    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        let pid: UInt32? = flow.sourceAppAuditToken.flatMap { token in
            guard token.count == 32 else { return nil }
            return token.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 20, as: UInt32.self) }
        }
        return pid == blockedPID ? .drop() : .allow()
    }
}
