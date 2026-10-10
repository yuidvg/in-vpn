import Foundation
import Network
import NetworkExtension

struct RelayRoute: Codable {
    let pid: Int
    let port: UInt16
    let secret: String
    let selection: String?
}

private struct RelayHeader: Codable {
    let secret: String
    let proto: String
    let host: String
    let port: String
}

private struct Datagram: Codable {
    let host: String
    let port: String
    let payload: Data
}

// Owns one asynchronous OS flow and its diagnostic bridge connection.
// The bridge is a test fixture; this is not a production relay protocol.
final class ProbeRelay {
    private let flow: NEAppProxyFlow
    private let connection: NWConnection
    private let route: RelayRoute
    private let queue = DispatchQueue(label: "invpn.probe.relay")
    private let ended: () -> Void
    private var finished = false

    init(flow: NEAppProxyFlow, route: RelayRoute, ended: @escaping () -> Void) {
        self.flow = flow
        self.route = route
        self.ended = ended
        connection = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(integerLiteral: route.port), using: .tcp)
    }

    func start() {
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready: self.authenticate()
            case .failed: self.finish()
            default: break
            }
        }
        connection.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 30) { [weak self] in self?.finish() }
    }

    private func authenticate() {
        let endpoint = (flow as? NEAppProxyTCPFlow)?.remoteEndpoint as? NWHostEndpoint
        let header = RelayHeader(secret: route.secret, proto: flow is NEAppProxyTCPFlow ? "tcp" : "udp", host: endpoint?.hostname ?? "", port: endpoint?.port ?? "0")
        guard let data = try? JSONEncoder().encode(header) else { finish(); return }
        connection.send(content: data + Data([10]), completion: .contentProcessed { error in
            if error != nil { self.finish(); return }
            self.exact(1) { ack in
                guard ack == Data([0]) else { self.finish(); return }
                self.flow.open(withLocalEndpoint: nil) { error in
                    if error != nil { self.finish(); return }
                    if let tcp = self.flow as? NEAppProxyTCPFlow {
                        self.tcpUp(tcp); self.tcpDown(tcp)
                    } else if let udp = self.flow as? NEAppProxyUDPFlow {
                        self.udpUp(udp); self.udpDown(udp)
                    } else { self.finish() }
                }
            }
        })
    }

    private func exact(_ count: Int, prefix: Data = Data(), completion: @escaping (Data?) -> Void) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: count - prefix.count) { data, _, done, error in
            let value = prefix + (data ?? Data())
            if value.count == count { completion(value) }
            else if done || error != nil { completion(nil) }
            else { self.exact(count, prefix: value, completion: completion) }
        }
    }

    private func tcpUp(_ tcp: NEAppProxyTCPFlow) {
        tcp.readData { data, error in
            guard error == nil, let data else { self.finish(); return }
            self.connection.send(content: data, contentContext: .defaultMessage, isComplete: data.isEmpty, completion: .contentProcessed { error in
                if error != nil { self.finish() }
                else if !data.isEmpty { self.tcpUp(tcp) }
            })
        }
    }

    private func tcpDown(_ tcp: NEAppProxyTCPFlow) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, done, error in
            guard error == nil else { self.finish(); return }
            guard let data, !data.isEmpty else { self.finish(); return }
            tcp.write(data) { error in
                if error != nil || done { self.finish() }
                else { self.tcpDown(tcp) }
            }
        }
    }

    private func udpUp(_ udp: NEAppProxyUDPFlow) {
        udp.readDatagrams { data, endpoints, error in
            guard error == nil, let data, let endpoints, !data.isEmpty, data.count == endpoints.count else { self.finish(); return }
            let packets = zip(data, endpoints).compactMap { payload, endpoint -> Data? in
                guard let endpoint = endpoint as? NWHostEndpoint,
                      let json = try? JSONEncoder().encode(Datagram(host: endpoint.hostname, port: endpoint.port, payload: payload)), json.count <= 100000 else { return nil }
                var length = UInt32(json.count).bigEndian
                return withUnsafeBytes(of: &length) { Data($0) } + json
            }
            guard packets.count == data.count else { self.finish(); return }
            self.connection.send(content: packets.reduce(Data(), +), completion: .contentProcessed { error in
                if error != nil { self.finish() } else { self.udpUp(udp) }
            })
        }
    }

    private func udpDown(_ udp: NEAppProxyUDPFlow) {
        exact(4) { prefix in
            guard let prefix else { self.finish(); return }
            let count = prefix.reduce(0) { ($0 << 8) | Int($1) }
            guard count > 0, count <= 100000 else { self.finish(); return }
            self.exact(count) { data in
                guard let data, let packet = try? JSONDecoder().decode(Datagram.self, from: data) else { self.finish(); return }
                udp.writeDatagrams([packet.payload], sentBy: [NWHostEndpoint(hostname: packet.host, port: packet.port)]) { error in
                    if error != nil { self.finish() } else { self.udpDown(udp) }
                }
            }
        }
    }

    private func finish() {
        queue.async {
            guard !self.finished else { return }
            self.finished = true
            self.connection.stateUpdateHandler = nil
            self.connection.cancel()
            self.flow.closeReadWithError(nil)
            self.flow.closeWriteWithError(nil)
            self.ended()
        }
    }
}
