from . import __version__


def capabilities():
    return {
        "version": __version__, "status": "partial", "default_mode": "isolated",
        "modes": {
            "isolated": {"available": False, "reason": "descendant tracking, DNS isolation and crash containment are unresolved"},
            "proxy": {"available": True, "runtime_validation": "observed on development Mac; see docs/implementation.md", "scope": "proxy-aware tools and inherited proxy environment in shells", "direct_traffic_blocked": False},
            "transparent": {"available": True, "experimental": True, "runtime_validation": "product Extension OS approval pending", "requires": "installed, signed and user-approved InVPN.app", "scope": "root PID TCP to one declared IPv4 address and port; exact well-known NAT64 counterpart", "direct_traffic_blocked": False},
        },
        "capabilities": {
            "cwd_files_path_arguments_stdio": "implemented",
            "proxy_aware_tcp": "implemented",
            "proxy_supplied_names_resolved_in_vpn": "implemented",
            "known_pid_scoped_tcp": "experimental",
            "transparent_all_destinations": "unavailable",
            "descendant_transparent_routing": "unavailable",
            "standard_dns_isolation": "unavailable",
            "crash_containment": "unavailable",
            "transparent_udp_quic_icmp": "unavailable",
            "general_ipv6": "unverified",
            "parallel_different_profiles_proxy": "implemented",
            "parallel_transparent_sessions": "unavailable",
            "same_profile_parallel_sessions": "rejected",
            "inherited_socket_stdio": "rejected",
            "delegated_daemon_traffic": "outside_scope",
            "background_child_lifetime": "unavailable",
            "sleep_network_changes_tailscale_coexistence": "unverified",
            "developer_id_distribution": "unverified",
        },
    }


def warning(mode, destination=None):
    if mode == "proxy":
        return ("in-vpn: partial PROXY mode: only tools honoring HTTP/SOCKS proxy settings use the VPN. "
                "Other sockets and system DNS may use the normal network. Direct traffic is not blocked. "
                "The backend ends when the root command exits; background descendants are not maintained.")
    return (f"in-vpn: EXPERIMENTAL transparent TCP: root PID only, destination {destination}. "
            "Children, other destinations, UDP and system DNS use their existing routes. "
            "Provider failure can restore direct traffic. This mode does not provide VPN isolation.")
