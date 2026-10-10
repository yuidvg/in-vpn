# InVPN native experimental app

This standalone app forwards TCP from one selected command root to one declared
IPv4 address and port. It uses product source only; it does not link the
feasibility targets. It is an experimental transport, not a complete security
boundary.

Compile without requesting profiles or changing the Mac:

```sh
python3 macos/build.py --unsigned
```

Build with the previously authorized development team:

```sh
python3 macos/build.py --team YOUR_TEAM_ID
```

The result is `.local/build/native/Build/Products/Debug/InVPN.app`. The build
script never installs or activates the app. The system extension must be
installed as part of `/Applications/InVPN.app` and allowed in macOS before it
can forward traffic. Developer ID distribution is unverified.

The native executable emits one JSON response on stdout, diagnostics on stderr,
and a nonzero exit status for errors. Activation failures include only the OS
error domain and numeric code, without user-info dictionaries. The Host and
Provider declare a shared application group required as the prefix of the
Provider's Mach service name:

| Command | Contract |
| --- | --- |
| `activate` | Request system-extension activation; macOS may require approval. |
| `status` | Return `ready`, `configured`, and Provider metadata when connected. |
| `start IPv4 PORT` | Save one exact TCP destination rule and its well-known NAT64 `/128` counterpart. Return success only after Provider readiness acknowledgement. Port 53 is rejected. |
| `route /absolute/private.json` | Register `{ "pid": PID, "port": BRIDGE_PORT, "secret": SECRET }` after validating private file ownership/mode and process identity. Return acknowledgement only after storage. |
| `unroute PID` | Remove the exact root registration; return acknowledgement only if it existed. Does not close already established flows. |
| `events` | Return bounded in-memory decision metadata. Audit tokens and relay credentials are never included. |
| `remove` | Stop the Provider and remove this app's configuration. The command launcher must first terminate its selected root. |

Selection uses the command PID with its observed BSD start time. The Provider
also binds the first selected flow's audit PID generation and checks later
flows. This guards against ordinary PID reuse; the observation race and macOS
permissions remain part of the experimental contract. There is no child-process
or POSIX-session selection. A selected flow with an identity or relay error is
closed while the Provider is running.

Other processes and all traffic outside the declared TCP destination retain
normal routing. UDP, DNS, ICMP, descendants, application-managed DNS, general
IPv6, and VPN-wide traffic are not captured. The NAT64 rule covers only
`64:ff9b::/96` and the declared IPv4 address; other synthesis prefixes are not
supported. Provider termination can restore direct routing: the implementation
does not provide crash containment or DNS isolation. Same-user native IPC
authorization has not been established as an adversarial security boundary.

The relay uses a random-secret authenticated loopback TCP bridge, with a
ten-second connection/authentication deadline and no fixed transfer lifetime.
Both TCP directions preserve EOF independently; resource state is serialized on
one queue. Long-lived sessions and all half-close combinations still need
runtime qualification.
