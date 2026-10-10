import Foundation
import Network
import NetworkExtension

private struct BridgeHeader: Codable {
    let secret: String
    let proto: String
    let host: String
    let port: UInt16
}

// Owns one TCP flow and one loopback connection. All mutable transfer state is
// serialized on queue. Only connection/authentication has a deadline.
final class TCPRelay {
    private let flow: NEAppProxyTCPFlow
    private let connection: NWConnection
    private let header: BridgeHeader
    private let queue = DispatchQueue(label: "jp.diverge.invpn.relay")
    private let ended: () -> Void
    private var finished = false
    private var upstreamEOF = false
    private var downstreamEOF = false
    private var handshakeTask: DispatchWorkItem?

    init(flow: NEAppProxyTCPFlow, route: Route, destinationIP: String,
         destinationPort: UInt16, ended: @escaping () -> Void) {
        self.flow = flow
        self.ended = ended
        self.header = BridgeHeader(secret: route.secret, proto: "tcp", host: destinationIP, port: destinationPort)
        self.connection = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(integerLiteral: route.port), using: .tcp)
    }

    func start() {
        queue.async { [self] in
            guard !self.finished else { return }
            let timeout = DispatchWorkItem { [weak self] in self?.finish(error: ETIMEDOUT) }
            self.handshakeTask = timeout
            self.queue.asyncAfter(deadline: .now() + 10, execute: timeout)
            self.connection.stateUpdateHandler = { [weak self] state in
                guard let self, !self.finished else { return }
                switch state {
                case .ready: self.authenticate()
                case .failed, .cancelled: self.finish(error: ECONNRESET)
                default: break
                }
            }
            self.connection.start(queue: self.queue)
        }
    }

    func cancel() { queue.async { self.finish(error: ECANCELED) } }

    private func authenticate() {
        guard let data = try? JSONEncoder().encode(header) else { finish(error: EINVAL); return }
        connection.send(content: data + Data([10]), completion: .contentProcessed { error in
            guard !self.finished else { return }
            guard error == nil else { self.finish(error: ECONNRESET); return }
            self.connection.receive(minimumIncompleteLength: 1, maximumLength: 1) { data, _, done, error in
                guard !self.finished else { return }
                guard error == nil, !done, data == Data([0]) else { self.finish(error: ECONNREFUSED); return }
                self.flow.open(withLocalFlowEndpoint: nil) { error in
                    self.queue.async {
                        guard !self.finished else { return }
                        guard error == nil else { self.finish(error: ECONNRESET); return }
                        self.handshakeTask?.cancel()
                        self.handshakeTask = nil
                        self.readApplication()
                        self.readBridge()
                    }
                }
            }
        })
    }

    private func readApplication() {
        flow.readData { data, error in
            self.queue.async {
                guard !self.finished else { return }
                guard error == nil else { self.finish(error: ECONNRESET); return }
                let eof = data?.isEmpty ?? true
                self.connection.send(content: eof ? nil : data,
                    contentContext: eof ? .finalMessage : .defaultMessage,
                    isComplete: eof, completion: .contentProcessed { error in
                        guard !self.finished else { return }
                        guard error == nil else { self.finish(error: ECONNRESET); return }
                        if eof { self.upstreamEOF = true; self.finishIfBothEOF() }
                        else { self.readApplication() }
                    })
            }
        }
    }

    private func readBridge() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, eof, error in
            guard !self.finished else { return }
            guard error == nil else { self.finish(error: ECONNRESET); return }
            let complete = {
                if eof {
                    self.downstreamEOF = true
                    self.flow.closeWriteWithError(nil)
                    self.finishIfBothEOF()
                } else { self.readBridge() }
            }
            if let data, !data.isEmpty {
                self.flow.write(data) { error in
                    self.queue.async {
                        guard !self.finished else { return }
                        if error != nil { self.finish(error: ECONNRESET) }
                        else { complete() }
                    }
                }
            } else if eof { complete() }
            else { self.readBridge() }
        }
    }

    private func finishIfBothEOF() {
        if upstreamEOF && downstreamEOF { finish(error: nil) }
    }

    private func finish(error: Int32?) {
        guard !finished else { return }
        finished = true
        handshakeTask?.cancel()
        handshakeTask = nil
        connection.stateUpdateHandler = nil
        connection.cancel()
        let value = error.map { NSError(domain: NSPOSIXErrorDomain, code: Int($0)) }
        flow.closeReadWithError(value)
        flow.closeWriteWithError(value)
        ended()
    }
}
