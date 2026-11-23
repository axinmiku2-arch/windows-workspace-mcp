"""Fixed, locally approved Windows diagnostics. Never accepts PowerShell source."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import ipaddress
import os
from pathlib import Path
import re

import core

HOSTS_FIELD = "windows_toolbox_ping_hosts"
MAX_HOSTS = 20
PORT_LIST_LIMIT = 64
TIMEOUT_SECONDS = 10
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)
_DECIMALS = re.compile(r"(?:0|[1-9][0-9]{0,8})", re.ASCII)

PRESETS = {
    "windows_ipconfig": {"label": "Windows 网络接口摘要", "parameters": {}},
    "windows_listening_ports": {"label": "Windows 本机侦听端口", "parameters": {}},
    "windows_ping": {"label": "Windows 固定 Ping（本机白名单）", "parameters": {
        "host": {"type": "string", "description": "One exact host approved in the local Ping allowlist."},
    }},
}

# Source text, classes and method calls are static. No remote value is inserted
# into PowerShell source or CLI syntax. No authorized workspace is used as CWD.
_PREFIX = "$ErrorActionPreference='Stop'; $PSModuleAutoLoadingPreference='None'; "
_SCRIPTS = {
    "windows_ipconfig": r"""
        $interfaces = [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()
        $up = 0; $v4 = 0; $v6 = 0
        foreach ($nic in $interfaces) {
            if ($nic.OperationalStatus -ne [Net.NetworkInformation.OperationalStatus]::Up) { continue }
            $up++; $has4 = $false; $has6 = $false
            foreach ($entry in $nic.GetIPProperties().UnicastAddresses) {
                if ($entry.Address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) { $has4 = $true }
                if ($entry.Address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) { $has6 = $true }
            }
            if ($has4) { $v4++ }; if ($has6) { $v6++ }
        }
        [Console]::WriteLine(('DOT_IP_V1|{0}|{1}|{2}|{3}' -f $interfaces.Length,$up,$v4,$v6))
    """,
    "windows_listening_ports": r"""
        $info = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
        $tcp = [System.Collections.Generic.SortedSet[int]]::new()
        $udp = [System.Collections.Generic.SortedSet[int]]::new()
        foreach ($ep in $info.GetActiveTcpListeners()) { [void]$tcp.Add($ep.Port) }
        foreach ($ep in $info.GetActiveUdpListeners()) { [void]$udp.Add($ep.Port) }
        $tcpSeen = 0; $udpSeen = 0
        $tcpShort = foreach ($port in $tcp) { $port; if ((++$tcpSeen) -ge 64) { break } }
        $udpShort = foreach ($port in $udp) { $port; if ((++$udpSeen) -ge 64) { break } }
        [Console]::WriteLine(('DOT_PORTS_V1|{0}|{1}|{2}|{3}' -f $tcp.Count,($tcpShort -join ','),$udp.Count,($udpShort -join ',')))
    """,
    "windows_ping": r"""
        $target = [Environment]::GetEnvironmentVariable('DOT_TOOLBOX_PING_HOST')
        $address = $null
        try {
            if ([Environment]::GetEnvironmentVariable('DOT_TOOLBOX_PING_HOST_KIND') -eq 'address') {
                $candidates = @([Net.IPAddress]::Parse($target))
            }
            else { $candidates = [Net.Dns]::GetHostAddresses($target + '.') }
        } catch { [Console]::WriteLine('DOT_PING_V1|unresolved'); exit 0 }
        foreach ($candidate in $candidates) {
            if ($candidate.IsIPv4MappedToIPv6) { $candidate = $candidate.MapToIPv4() }
            if ($candidate.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
                $octets = $candidate.GetAddressBytes()
                if ($octets[0] -eq 0 -or $octets[0] -ge 224) { continue }
            } elseif ($candidate.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
                if ($candidate.IsIPv6Multicast -or $candidate.Equals([Net.IPAddress]::IPv6Any)) { continue }
            } else { continue }
            $address = $candidate; break
        }
        if ($null -eq $address) { [Console]::WriteLine('DOT_PING_V1|unresolved'); exit 0 }
        $ping = [Net.NetworkInformation.Ping]::new()
        $bytes = [byte[]]::new(16)
        $values = @()
        try {
            for ($i = 0; $i -lt 2; $i++) {
                try {
                    $reply = $ping.Send($address, 800, $bytes)
                    if ($reply.Status -eq [Net.NetworkInformation.IPStatus]::Success) {
                        $values += ('reply:' + $reply.RoundtripTime)
                    } elseif ($reply.Status -eq [Net.NetworkInformation.IPStatus]::TimedOut) {
                        $values += 'timeout'
                    } else { $values += 'no_reply' }
                } catch { $values += 'no_reply' }
            }
        } finally { $ping.Dispose() }
        [Console]::WriteLine(('DOT_PING_V1|{0}|{1}' -f $values[0],$values[1]))
    """,
}


def _unicast(ip):
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if isinstance(ip, ipaddress.IPv4Address):
        return 0 < (int(ip) >> 24) < 224
    return not (ip.is_unspecified or ip.is_multicast)


def canonical_host(value):
    if (not isinstance(value, str) or not 1 <= len(value) <= 253 or not value.isascii()
            or not re.fullmatch(r"[A-Za-z0-9.:-]+", value, re.ASCII)):
        raise ValueError("Use one plain IPv4, IPv6 or fully qualified ASCII DNS name.")
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        fqdn = value.lower()
        labels = fqdn.split(".")
        if len(labels) > 1 and labels[-1][:1].isalpha() and all(_HOST_LABEL.fullmatch(p) for p in labels):
            return fqdn
        raise ValueError("Use one plain IPv4, IPv6 or fully qualified ASCII DNS name.") from None
    if not _unicast(ip):
        raise ValueError("Ping requires a unicast IPv4 or IPv6 address.")
    return str(ip)


def _host_list(items):
    if not isinstance(items, list) or len(items) > MAX_HOSTS:
        raise ValueError(f"Ping 白名单最多允许 {MAX_HOSTS} 个精确主机。")
    return list(dict.fromkeys(canonical_host(item) for item in items))


def ping_hosts(cfg=None):
    cfg = core.load_config() if cfg is None else cfg
    try:
        return _host_list(cfg.get(HOSTS_FIELD, []))
    except ValueError:
        return []  # malformed local configuration fails closed, never partly allowed


def save_ping_hosts(hosts):
    """Only the local manager calls this. No worker operation edits the allowlist."""
    values = _host_list(hosts)
    core.update_config(**{HOSTS_FIELD: values})
    return values


def parameters(preset, value, cfg):
    if preset not in PRESETS:
        raise ValueError("Unknown fixed Windows toolbox preset.")
    if preset == "windows_ping":
        if not isinstance(value, dict) or set(value) != {"host"}:
            raise ValueError("Ping requires exactly the host parameter.")
        host = canonical_host(value["host"])
        if host not in ping_hosts(cfg):
            raise ValueError("Ping host is not in the local Windows allowlist.")
        return {"host": host}
    if value is not None and (not isinstance(value, dict) or value):
        raise ValueError("This Windows diagnostic does not accept parameters.")
    return {}


def _system_directory():
    if os.name != "nt":
        raise OSError("Fixed Windows diagnostics require a Windows worker.")
    query = ctypes.WinDLL("kernel32.dll", use_last_error=True).GetSystemDirectoryW
    query.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    query.restype = wintypes.UINT
    result = ctypes.create_unicode_buffer(32_768)
    length = query(result, len(result))
    if not 0 < length < len(result):
        raise OSError("The Windows worker could not locate its system directory.")
    return Path(result.value)


def launch_spec(preset, values, cfg):
    checked = parameters(preset, values, cfg)
    system = _system_directory()
    ps = system / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if not ps.is_file():
        raise OSError("Windows PowerShell is unavailable for fixed diagnostics.")
    root = str(system.parent)
    env = {"SYSTEMROOT": root, "WINDIR": root, "PATH": str(system), "PSModulePath": ""}
    if checked:
        host = checked["host"]
        env["DOT_TOOLBOX_PING_HOST"] = host
        try:
            ipaddress.ip_address(host)
            env["DOT_TOOLBOX_PING_HOST_KIND"] = "address"
        except ValueError:
            env["DOT_TOOLBOX_PING_HOST_KIND"] = "dns"
    return [str(ps), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", _PREFIX + _SCRIPTS[preset]], system, env


def _number(value, ceiling):
    if not _DECIMALS.fullmatch(value) or int(value) > ceiling:
        raise ValueError("Unexpected output from the fixed Windows diagnostic.")
    return int(value)


def _ports(csv, count):
    ports = [_number(item, 65535) for item in csv.split(",")] if csv else []
    if ports != sorted(set(ports)) or 0 in ports or len(ports) != min(count, PORT_LIST_LIMIT):
        raise ValueError("Unexpected port summary from the fixed Windows diagnostic.")
    return ports


def structured_result(preset, output):
    try:
        fields = output.decode("ascii").strip().split("|")
    except UnicodeDecodeError:
        raise ValueError("Unexpected output from the fixed Windows diagnostic.") from None
    if preset == "windows_ipconfig" and len(fields) == 5 and fields[0] == "DOT_IP_V1":
        total, up, v4, v6 = [_number(item, 1_000_000) for item in fields[1:]]
        if max(v4, v6) <= up <= total:
            return {"interfaces": total, "up_interfaces": up, "up_with_ipv4": v4, "up_with_ipv6": v6}
    if preset == "windows_listening_ports" and len(fields) == 5 and fields[0] == "DOT_PORTS_V1":
        tcp, udp = _number(fields[1], 65535), _number(fields[3], 65535)
        return {"tcp_listening_ports": _ports(fields[2], tcp), "udp_bound_ports": _ports(fields[4], udp),
                "tcp_unique_count": tcp, "udp_unique_count": udp,
                "truncated": max(tcp, udp) > PORT_LIST_LIMIT}
    if preset == "windows_ping" and fields[0] == "DOT_PING_V1":
        if fields[1:] == ["unresolved"]:
            return {"status": "no_eligible_address", "sent_attempts": 0, "attempts": []}
        if len(fields) == 3:
            attempts = []
            for item in fields[1:]:
                if item in {"timeout", "no_reply"}:
                    attempts.append({"status": item})
                elif item.startswith("reply:"):
                    attempts.append({"status": "reply", "round_trip_ms": _number(item[6:], 10_000)})
                else:
                    break
            if len(attempts) == 2:
                return {"status": "reply" if any(a["status"] == "reply" for a in attempts) else "no_reply",
                        "sent_attempts": 2, "attempts": attempts}
    raise ValueError("Unexpected output from the fixed Windows diagnostic.")
