import Foundation
import NetworkExtension

// A compile-only subclass. It is not packaged, signed, installed, or activated.
// Reference semantics and inheritance are required by NetworkExtension.
final class CompileProbeProvider: NETransparentProxyProvider {
    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        let token: Data? = flow.metaData.sourceAppAuditToken
        _ = token
        return false
    }
}
