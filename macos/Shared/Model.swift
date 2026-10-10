import Foundation

struct ProcessIdentity: Codable, Equatable {
    let seconds: UInt64
    let microseconds: UInt64

    static func current(pid: Int32) -> ProcessIdentity? {
        var seconds: UInt64 = 0
        var microseconds: UInt64 = 0
        guard invpn_process_identity(pid, &seconds, &microseconds) == 1 else { return nil }
        return ProcessIdentity(seconds: seconds, microseconds: microseconds)
    }
}

struct RouteInput: Codable {
    let pid: Int32
    let port: UInt16
    let secret: String
}

struct Route: Codable {
    let pid: Int32
    let port: UInt16
    let secret: String
    let identity: ProcessIdentity
}

struct ProviderRequest: Codable {
    let operation: String
    let route: Route?
    let pid: Int32?
}

struct NativeReply: Codable {
    let success: Bool
    let reason: String?
    let ready: Bool?
    let configured: Bool?
    let providerPID: Int32?
    let routeCount: Int?
    let eventCount: Int?
    let activeFlows: Int?
    let destination: String?
    let errorDomain: String?
    let errorCode: Int?

    init(success: Bool, reason: String? = nil, ready: Bool? = nil,
         configured: Bool? = nil, providerPID: Int32? = nil,
         routeCount: Int? = nil, eventCount: Int? = nil,
         activeFlows: Int? = nil, destination: String? = nil,
         errorDomain: String? = nil, errorCode: Int? = nil) {
        self.success = success; self.reason = reason; self.ready = ready
        self.configured = configured; self.providerPID = providerPID
        self.routeCount = routeCount; self.eventCount = eventCount
        self.activeFlows = activeFlows; self.destination = destination
        self.errorDomain = errorDomain; self.errorCode = errorCode
    }
}

struct FlowEvent: Codable {
    let time: Double
    let pid: Int32?
    let protocolName: String
    let decision: String
}

struct EventsReply: Codable {
    let success: Bool
    let events: [FlowEvent]
}
