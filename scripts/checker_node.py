#!/usr/bin/env python3
"""Lightweight multi-layer domain ban checker for VPS nodes.

Performs three detection layers per domain:
  1. DNS  — compare local/country resolver vs global (8.8.8.8, 1.1.1.1)
  2. TLS  — SNI-based blocking detection via TLS handshake
  3. HTTP — full HTTPS GET with block-page keyword detection

Designed to run on minimal VPS instances with Python 3.10+ stdlib only
(classify.py is the sole local dependency).

Usage:
    python3 checker_node.py --config /home/checker/config.json \\
                            --list /home/checker/lists/th.txt
"""

from __future__ import annotations

import argparse
import http.client
import json
import socket
import ssl
import struct
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from classify import (
    BLOCK_KEYWORDS,
    BLOCK_PAGE_HOSTS,
    BODY_PREVIEW_LIMIT,
    CHALLENGE_STRONG_KEYWORDS,
    contains_any,
    extract_title,
    is_block_code,
    is_block_page_host,
    is_cloudflare_waf,
    is_domain_down,
    is_sibling_domain_redirect,
    load_domains,
)

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

GLOBAL_DNS = ["8.8.8.8", "1.1.1.1"]

def _is_bogon_ip(ip: str) -> bool:
    """Return True if the IP is a dead/loopback/private address.

    ISPs in MY/TH/NP return these when DNS-poisoning a domain:
      - 0.0.0.0 / 127.0.0.1 — explicit null/loopback
      - 10.x, 172.16-31.x, 192.168.x — RFC1918 private (ISP internal block page)
      - 169.254.x — link-local (APIPA)
    Any of these from an ISP resolver for a domain that resolves publicly = poisoned.
    """
    _EXACT = {"0.0.0.0", "127.0.0.1", "::1", "::"}
    if ip in _EXACT:
        return True
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        o = [int(p) for p in parts]
    except ValueError:
        return False
    if o[0] == 10:
        return True
    if o[0] == 172 and 16 <= o[1] <= 31:
        return True
    if o[0] == 192 and o[1] == 168:
        return True
    if o[0] == 169 and o[1] == 254:
        return True
    return False

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
)


@dataclass
class DnsResult:
    signal: str = "DNS_OK"
    local_ips: list[str] = field(default_factory=list)
    global_ips: list[str] = field(default_factory=list)
    detail: str = ""


@dataclass
class TlsResult:
    signal: str = "TLS_OK"
    cert_match: bool = True
    detail: str = ""


@dataclass
class HttpResult:
    signal: str = "HTTP_OK"
    status_code: int = 0
    final_url: str = ""
    detail: str = ""


@dataclass
class DomainResult:
    domain: str = ""
    timestamp: str = ""
    country: str = ""
    node_id: str = ""
    dns: DnsResult = field(default_factory=DnsResult)
    tls: TlsResult = field(default_factory=TlsResult)
    http: HttpResult = field(default_factory=HttpResult)
    verdict: str = "OK"
    confidence: str = "high"


@dataclass
class NodeReport:
    node_id: str = ""
    country: str = ""
    timestamp: str = ""
    healthy: bool = True
    health_detail: str = ""
    results: list[DomainResult] = field(default_factory=list)


# ---------------------------------------------------------------------------
# DNS Layer — raw UDP A-record queries
# ---------------------------------------------------------------------------

def _build_dns_query(domain: str, query_id: int = 0x1234) -> bytes:
    """Build a minimal DNS A-record query packet."""
    # Header: ID, flags (standard query, recursion desired), 1 question
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    # Question section
    question = b""
    for label in domain.split("."):
        encoded = label.encode("ascii")
        question += struct.pack("B", len(encoded)) + encoded
    question += b"\x00"  # root label
    question += struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return header + question


def _parse_dns_response(data: bytes) -> list[str]:
    """Extract A-record IPs from a DNS response packet."""
    if len(data) < 12:
        return []
    # Skip header, parse answer count
    _flags = struct.unpack(">H", data[2:4])[0]
    qdcount = struct.unpack(">H", data[4:6])[0]
    ancount = struct.unpack(">H", data[6:8])[0]

    # Check for NXDOMAIN (RCODE = 3)
    rcode = _flags & 0x000F
    if rcode == 3:
        return []  # NXDOMAIN

    offset = 12
    # Skip question section
    for _ in range(qdcount):
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if length >= 192:  # pointer
                offset += 2
                break
            offset += 1 + length
        offset += 4  # QTYPE + QCLASS

    # Parse answer section
    ips: list[str] = []
    for _ in range(ancount):
        if offset >= len(data):
            break
        # Name (may be pointer)
        if data[offset] >= 192:
            offset += 2
        else:
            while offset < len(data) and data[offset] != 0:
                if data[offset] >= 192:
                    offset += 2
                    break
                offset += 1 + data[offset]
            else:
                offset += 1
        if offset + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        if rtype == 1 and rdlength == 4 and offset + 4 <= len(data):
            ip = ".".join(str(b) for b in data[offset:offset + 4])
            ips.append(ip)
        offset += rdlength
    return ips


def dns_resolve(domain: str, server: str, timeout: float = 5.0) -> list[str]:
    """Resolve domain A records using a specific DNS server via UDP."""
    try:
        query = _build_dns_query(domain)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(query, (server, 53))
            data, _ = sock.recvfrom(1024)
            return _parse_dns_response(data)
        finally:
            sock.close()
    except socket.timeout:
        return []
    except Exception:
        return []


def dns_resolve_system(domain: str) -> list[str]:
    """Resolve using the system's default DNS resolver."""
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        return list({r[4][0] for r in results})
    except socket.gaierror:
        return []
    except Exception:
        return []


def _same_prefix(ip_a: str, ip_b: str, mask_bits: int = 16) -> bool:
    """Check if two IPv4 addresses share the same /mask_bits prefix."""
    try:
        parts_a = [int(x) for x in ip_a.split(".")]
        parts_b = [int(x) for x in ip_b.split(".")]
        int_a = (parts_a[0] << 24) | (parts_a[1] << 16) | (parts_a[2] << 8) | parts_a[3]
        int_b = (parts_b[0] << 24) | (parts_b[1] << 16) | (parts_b[2] << 8) | parts_b[3]
        mask = (0xFFFFFFFF << (32 - mask_bits)) & 0xFFFFFFFF
        return (int_a & mask) == (int_b & mask)
    except (ValueError, IndexError):
        return False


def _ips_are_related(local_ips: set[str], global_ips: set[str]) -> bool:
    """Check if local and global IPs are in similar ranges (CDN/anycast).

    CDN services (Facebook, Google, Cloudflare, etc.) serve different IPs
    from different regions. Exact IP match is unreliable — instead, check
    if the IPs share the same /16 network prefix, which indicates they
    belong to the same organization's IP allocation.
    """
    for local_ip in local_ips:
        for global_ip in global_ips:
            if _same_prefix(local_ip, global_ip, 16):
                return True
    return False


def check_dns(domain: str, local_resolvers: list[str], global_resolvers: list[str]) -> DnsResult:
    """DNS layer: compare local/country resolution vs global."""
    result = DnsResult()

    # Resolve via system default
    system_ips = dns_resolve_system(domain)

    # Resolve via country-specific resolvers
    local_ips: set[str] = set(system_ips)
    for resolver in local_resolvers:
        local_ips.update(dns_resolve(domain, resolver))

    # Resolve via global resolvers
    global_ips: set[str] = set()
    for resolver in global_resolvers:
        global_ips.update(dns_resolve(domain, resolver))

    result.local_ips = sorted(local_ips)
    result.global_ips = sorted(global_ips)

    # ISP returned only dead/private IPs — fast-path poisoning (Gemini: 100% banned)
    if local_ips and all(_is_bogon_ip(ip) for ip in local_ips):
        result.signal = "DNS_POISONED"
        result.detail = f"ISP DNS returned dead/private IPs: {sorted(local_ips)}"
        return result

    # No global resolution — domain may not exist
    if not global_ips:
        if not local_ips:
            result.signal = "DNS_NXDOMAIN"
            result.detail = "Domain does not resolve globally or locally"
        else:
            result.signal = "DNS_OK"
            result.detail = "Resolves locally but not globally (unusual)"
        return result

    # Global resolves but local does not
    if not local_ips:
        result.signal = "DNS_NXDOMAIN"
        result.detail = "Global resolves but local/country DNS returns nothing"
        return result

    # Both resolve — check if IPs overlap exactly
    if local_ips & global_ips:
        result.signal = "DNS_OK"
        return result

    # No exact overlap — check if IPs are in the same /16 range.
    # CDN/anycast services (Facebook, Google, etc.) return different IPs
    # from different regions. Same /16 means same organization, not poisoning.
    if _ips_are_related(local_ips, global_ips):
        result.signal = "DNS_OK"
        result.detail = "IPs differ but share network prefix (CDN/anycast)"
        return result

    # Truly different IPs with no relationship — likely DNS poisoning
    result.signal = "DNS_POISONED"
    result.detail = f"Local IPs {result.local_ips} differ from global {result.global_ips}"
    return result


# ---------------------------------------------------------------------------
# TLS / SNI Layer
# ---------------------------------------------------------------------------

def _tls_attempt(
    ip: str, domain: str, port: int, timeout: float, send_sni: bool
) -> TlsResult:
    """Single TLS connection attempt with or without SNI.

    TCP connect and TLS handshake are separated into distinct phases so we can
    tell the difference between an IP-level block (firewall drops the TCP SYN)
    and an SNI/DPI block (TCP succeeds but the handshake is killed or stalled).
    """
    result = TlsResult()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    # ── Phase 1: TCP connect ────────────────────────────────────────────────
    # A timeout here means the IP itself is unreachable/blacklisted (IP block).
    # A reset/refused here means the port is actively closed.
    try:
        sock.connect((ip, port))
    except socket.timeout:
        result.signal = "IP_BLOCKED"
        result.cert_match = False
        result.detail = f"TCP connect to {ip}:{port} timed out — IP-level block"
        try:
            sock.close()
        except Exception:
            pass
        return result
    except OSError as e:
        result.signal = "TLS_ERROR"
        result.cert_match = False
        result.detail = f"TCP connect failed: {e}"
        try:
            sock.close()
        except Exception:
            pass
        return result

    # ── Phase 2: TLS handshake (TCP succeeded) ──────────────────────────────
    # A timeout or reset here is SNI/DPI-specific — the firewall reads the
    # domain name from the ClientHello and stalls or kills the connection.
    if send_sni:
        ctx = ssl.create_default_context()
    else:
        # No SNI: DPI firewall cannot read the hostname from the ClientHello
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        sni_hostname = domain if send_sni else None
        with ctx.wrap_socket(sock, server_hostname=sni_hostname) as ssock:
            if send_sni:
                cert = ssock.getpeercert()
                san_domains: set[str] = set()
                for san_type, san_value in cert.get("subjectAltName", []):
                    if san_type == "DNS":
                        san_domains.add(san_value.lower())

                domain_lower = domain.lower()
                cert_match = False
                for san in san_domains:
                    if san == domain_lower:
                        cert_match = True
                        break
                    if san.startswith("*.") and domain_lower.endswith(san[1:]):
                        cert_match = True
                        break

                result.cert_match = cert_match
                if not cert_match:
                    result.signal = "TLS_MITM"
                    result.detail = f"Certificate SANs {sorted(san_domains)} do not match {domain}"
                else:
                    result.signal = "TLS_OK"
            else:
                result.signal = "TLS_OK"
    except ConnectionResetError:
        result.signal = "SNI_BLOCKED" if send_sni else "TLS_ERROR"
        result.cert_match = False
        result.detail = "Connection reset during TLS handshake (DPI/SNI filter)"
    except socket.timeout:
        result.signal = "SNI_TIMEOUT" if send_sni else "TLS_ERROR"
        result.cert_match = False
        result.detail = "TLS handshake stalled — possible DPI interference"
    except ssl.SSLCertVerificationError as e:
        result.signal = "TLS_MITM"
        result.cert_match = False
        result.detail = f"SSL certificate verification failed: {e}"
    except ssl.SSLError as e:
        result.signal = "TLS_ERROR"
        result.cert_match = False
        result.detail = f"SSL error: {e}"
    except OSError as e:
        result.signal = "TLS_ERROR"
        result.cert_match = False
        result.detail = f"TLS connection error: {e}"
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return result


def check_tls_sni(ip: str, domain: str, port: int = 443, timeout: float = 10.0) -> TlsResult:
    """TLS layer: SNI-based blocking detection with IP-direct confirmation.

    First attempts a normal TLS handshake with SNI (domain name in ClientHello).
    If that fails with a reset or timeout, re-attempts WITHOUT SNI on the same IP.
    If the no-SNI attempt succeeds, the block is confirmed as SNI/DPI-specific
    (the firewall is reading the hostname from the handshake and dropping it).
    """
    result = _tls_attempt(ip, domain, port, timeout, send_sni=True)

    # SNI failure — confirm it's hostname-specific, not a general connectivity issue
    if result.signal in ("SNI_BLOCKED", "SNI_TIMEOUT"):
        no_sni = _tls_attempt(ip, domain, port, timeout / 2, send_sni=False)
        if no_sni.signal == "TLS_OK":
            result.signal = "SNI_BLOCKED"
            result.detail = "SNI block confirmed: direct IP connection succeeds, hostname rejected by DPI"

    return result


# ---------------------------------------------------------------------------
# HTTP Layer
# ---------------------------------------------------------------------------

def check_http(domain: str, timeout: float = 20.0, max_redirects: int = 5) -> HttpResult:
    """HTTP layer: full HTTPS GET with block-page keyword detection."""
    result = HttpResult()
    current_url = f"https://{domain}"

    for _redirect_i in range(max_redirects + 1):
        parsed = urlparse(current_url)
        host = parsed.hostname or domain
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        use_https = parsed.scheme != "http"

        try:
            if use_https:
                conn = http.client.HTTPSConnection(host, timeout=timeout)
            else:
                conn = http.client.HTTPConnection(host, timeout=timeout)

            headers = {
                "Host": host,
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "identity",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Cache-Control": "max-age=0",
                "Connection": "keep-alive",
            }
            conn.request("GET", path, headers=headers)
            resp = conn.getresponse()
            status = resp.status
            body = resp.read(BODY_PREVIEW_LIMIT).decode("utf-8", errors="replace")
            resp_headers = {k.lower(): v for k, v in resp.getheaders()}
            conn.close()

            result.status_code = status
            result.final_url = current_url

            # Follow redirects
            if status in (301, 302, 303, 307, 308) and "location" in resp_headers:
                location = resp_headers["location"]
                if location.startswith("/"):
                    scheme = "https" if use_https else "http"
                    current_url = f"{scheme}://{host}{location}"
                elif location.startswith("http"):
                    current_url = location
                else:
                    current_url = f"https://{host}/{location}"
                continue

            # Analyze response
            title = extract_title(body)
            body_title = f"{title}\n{body}".lower()
            headers_str = "\n".join(f"{k}: {v}" for k, v in resp_headers.items())

            # Check for redirect to known block page hosts
            final_host = (urlparse(current_url).hostname or "").lower()
            if is_block_page_host(final_host):
                result.signal = "HTTP_BLOCKED"
                result.detail = f"Redirected to block page host: {final_host}"
                return result

            # Redirect to sibling domain (e.g. uea8th8.com → uea8th9.com)
            # means the original domain is banned and replaced
            if is_sibling_domain_redirect(domain, final_host):
                result.signal = "HTTP_BLOCKED"
                result.detail = f"Redirected to sibling domain: {final_host} (original banned)"
                return result

            if contains_any(body_title, BLOCK_KEYWORDS):
                result.signal = "HTTP_BLOCKED"
                result.detail = "Block keywords detected in response body"
                return result

            if contains_any(body_title, CHALLENGE_STRONG_KEYWORDS):
                result.signal = "HTTP_CHALLENGE"
                result.detail = "Challenge/CAPTCHA page detected"
                return result

            # Cloudflare WAF is NOT an ISP block — origin-side protection
            if is_cloudflare_waf(headers_str, body, str(status)):
                result.signal = "HTTP_WAF"
                result.detail = "Cloudflare WAF/protection page (not ISP block)"
                return result

            if is_block_code(str(status)):
                result.signal = "HTTP_BLOCKED"
                result.detail = f"HTTP {status} block status code"
                return result

            # Domain is parked/expired — not banned, just down
            if is_domain_down(str(status), headers_str, body):
                result.signal = "HTTP_DOWN"
                result.detail = "Domain appears parked/expired/for-sale"
                return result

            if 200 <= status <= 399:
                result.signal = "HTTP_OK"
                return result

            result.signal = "HTTP_ERROR"
            result.detail = f"HTTP {status}"
            return result

        except socket.timeout:
            result.signal = "HTTP_TIMEOUT"
            result.detail = "Connection timed out"
            return result
        except ssl.SSLError as e:
            result.signal = "HTTP_ERROR"
            result.detail = f"SSL error: {e}"
            return result
        except OSError as e:
            result.signal = "HTTP_ERROR"
            result.detail = f"Connection error: {e}"
            return result
        except Exception as e:
            result.signal = "HTTP_ERROR"
            result.detail = f"Unexpected error: {e}"
            return result

    result.signal = "HTTP_REDIRECT_LOOP"
    result.detail = f"Too many redirects (>{max_redirects})"
    return result


# ---------------------------------------------------------------------------
# Verdict aggregation
# ---------------------------------------------------------------------------

def aggregate_verdict(dns: DnsResult, tls: TlsResult, http: HttpResult) -> tuple[str, str]:
    """Combine three layer signals into a final (verdict, confidence) tuple."""
    # DNS-level ban — but cross-check with TLS.
    # If DNS says poisoned but TLS handshake succeeds with a valid cert,
    # the domain is actually reachable via a different CDN node, not banned.
    # A valid TLS cert proves the resolved IP belongs to the real domain owner.
    if dns.signal in ("DNS_POISONED", "DNS_NXDOMAIN"):
        if tls.signal == "TLS_OK" and tls.cert_match:
            # DNS differs but TLS proves the IP is legitimately owned by the domain.
            # This is normal CDN/anycast behavior, not DNS poisoning.
            pass
        else:
            return "BAN", "high"

    # TLS/SNI-level ban
    if tls.signal == "IP_BLOCKED":
        # Specific IP timed out but HTTP still got through via a different CDN IP
        if dns.signal == "DNS_OK" and http.signal == "HTTP_OK":
            return "OK", "medium"
        return "BAN", "high"   # IP itself is blacklisted at firewall level
    if tls.signal == "SNI_BLOCKED":
        return "BAN", "high"   # TCP works but DPI kills on hostname
    if tls.signal == "TLS_MITM":
        return "BAN", "high"

    # HTTP-level ban
    if http.signal == "HTTP_BLOCKED":
        return "BAN", "high"
    if http.signal == "HTTP_REDIRECT_BLOCK":
        return "BAN", "medium"

    # All OK
    if dns.signal == "DNS_OK" and tls.signal == "TLS_OK" and http.signal == "HTTP_OK":
        return "OK", "high"

    # HTTP fully accessible despite TLS timeout — domain is reachable.
    # SNI_TIMEOUT on a specific IP is likely CDN routing, not a block.
    # HTTP_OK proves the domain responds correctly to a full request.
    if dns.signal == "DNS_OK" and http.signal == "HTTP_OK":
        return "OK", "medium"

    # DNS clean but both TLS and HTTP unreachable — network-level block.
    # Domain exists (DNS OK) but no connection method works = ISP blocking.
    if dns.signal == "DNS_OK" and tls.signal in ("SNI_TIMEOUT", "SNI_BLOCKED") and http.signal == "HTTP_TIMEOUT":
        return "BAN", "medium"

    # Domain is parked/expired — not banned by ISP, the domain itself is down
    if http.signal == "HTTP_DOWN":
        return "DOWN", "high"

    # Cloudflare WAF — origin-side block, not ISP ban
    if http.signal == "HTTP_WAF":
        return "SUSPECT", "medium"

    # Infrastructure issues — all layers timing out (IP_BLOCKED already returned above)
    timeout_signals = {"DNS_TIMEOUT", "SNI_TIMEOUT", "HTTP_TIMEOUT"}
    error_signals = {"TLS_ERROR", "HTTP_ERROR", "HTTP_REDIRECT_LOOP"}
    all_signals = {dns.signal, tls.signal, http.signal}
    if all_signals <= (timeout_signals | error_signals):
        return "ERROR", "low"

    # Challenge pages
    if http.signal == "HTTP_CHALLENGE":
        return "SUSPECT", "medium"

    # Mixed signals
    if dns.signal == "DNS_OK" and tls.signal == "TLS_OK":
        # DNS and TLS fine, HTTP has issues
        if http.signal in timeout_signals | error_signals:
            return "SUSPECT", "low"

    return "SUSPECT", "medium"


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

def check_node_health(
    control_domains: list[str],
    local_resolvers: list[str],
    global_resolvers: list[str],
) -> tuple[bool, str]:
    """Verify the node can reach control domains. Returns (healthy, detail)."""
    for domain in control_domains:
        dns = check_dns(domain, local_resolvers, global_resolvers)
        if dns.signal != "DNS_OK":
            continue
        # Try HTTP
        http = check_http(domain, timeout=15.0)
        if http.signal == "HTTP_OK":
            return True, f"Control {domain} reachable"
    return False, f"All control domains unreachable: {control_domains}"


# ---------------------------------------------------------------------------
# Main check flow
# ---------------------------------------------------------------------------

def check_domain_once(
    domain: str,
    country: str,
    node_id: str,
    local_resolvers: list[str],
    global_resolvers: list[str],
) -> DomainResult:
    """Run all three detection layers on a single domain (one attempt)."""
    result = DomainResult(
        domain=domain,
        timestamp=datetime.now(timezone.utc).isoformat(),
        country=country,
        node_id=node_id,
    )

    # Layer 1: DNS
    result.dns = check_dns(domain, local_resolvers, global_resolvers)

    # If DNS gives us no IPs at all, we can still try TLS/HTTP by name
    target_ip = ""
    if result.dns.local_ips:
        target_ip = result.dns.local_ips[0]
    elif result.dns.global_ips:
        target_ip = result.dns.global_ips[0]

    # Layer 2: TLS/SNI (only if we have an IP)
    if target_ip:
        result.tls = check_tls_sni(target_ip, domain)
    else:
        result.tls = TlsResult(signal="TLS_ERROR", cert_match=False, detail="No IP to connect to")

    # Layer 3: HTTP
    result.http = check_http(domain)

    # Aggregate
    result.verdict, result.confidence = aggregate_verdict(result.dns, result.tls, result.http)

    return result


def check_domain(
    domain: str,
    country: str,
    node_id: str,
    local_resolvers: list[str],
    global_resolvers: list[str],
    attempts: int = 3,
) -> DomainResult:
    """Run detection with retry logic — retries on SUSPECT/ERROR, not on BAN/OK.

    Uses majority voting across attempts to avoid false results from
    transient network hiccups. A domain needs 2/3 attempts to agree
    before the verdict is finalised.
    """
    results: list[DomainResult] = []

    for attempt_i in range(attempts):
        r = check_domain_once(domain, country, node_id, local_resolvers, global_resolvers)
        results.append(r)

        # Early exit on confident results — no need for more attempts
        if r.verdict == "BAN" and r.confidence == "high":
            break
        if r.verdict == "OK" and r.confidence == "high":
            break

        if attempt_i < attempts - 1:
            time.sleep(1.0)

    # Majority voting on verdict
    from collections import Counter
    verdict_counts = Counter(r.verdict for r in results)
    majority_verdict = verdict_counts.most_common(1)[0][0]

    # Pick the result that matches the majority verdict (prefer high confidence)
    matching = [r for r in results if r.verdict == majority_verdict]
    best = sorted(matching, key=lambda r: (r.confidence != "high", r.confidence != "medium"))[0]

    return best


def load_config(config_path: Path) -> dict:
    """Load node configuration from JSON file."""
    with config_path.open(encoding="utf-8") as f:
        return json.load(f)


def main() -> None:
    parser = argparse.ArgumentParser(description="Multi-layer domain ban checker node")
    parser.add_argument("--config", type=Path, required=True, help="Path to node config JSON")
    parser.add_argument("--list", type=Path, required=True, help="Path to domain list file")
    parser.add_argument("--output", type=Path, help="Output JSON path (default: config results_dir/latest.json)")
    args = parser.parse_args()

    config = load_config(args.config)
    country = config["country"]
    node_id = config["node_id"]
    local_resolvers = config.get("dns_resolvers", {}).get("local", [])
    global_resolvers = config.get("dns_resolvers", {}).get("global", GLOBAL_DNS)
    control_domains = config.get("control_domains", ["google.com", "cloudflare.com"])
    results_dir = Path(config.get("results_dir", "/home/checker/results"))

    domains = load_domains(args.list)
    if not domains:
        print(f"No domains to check in {args.list}", file=sys.stderr)
        sys.exit(0)

    # Health check
    healthy, health_detail = check_node_health(control_domains, local_resolvers, global_resolvers)

    report = NodeReport(
        node_id=node_id,
        country=country,
        timestamp=datetime.now(timezone.utc).isoformat(),
        healthy=healthy,
        health_detail=health_detail,
    )

    if not healthy:
        print(f"NODE_UNHEALTHY: {health_detail}", file=sys.stderr)
        # Still write the report so the central server knows
    else:
        for domain in domains:
            print(f"Checking {domain}...", file=sys.stderr)
            result = check_domain(domain, country, node_id, local_resolvers, global_resolvers)
            report.results.append(result)
            # Small delay between domains to avoid rate limiting
            time.sleep(0.5)

    # Write results
    output_path = args.output or results_dir / "latest.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(asdict(report), f, indent=2, ensure_ascii=False)

    # Also archive by date
    archive_path = results_dir / f"{datetime.now(timezone.utc).date().isoformat()}.json"
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with archive_path.open("w", encoding="utf-8") as f:
        json.dump(asdict(report), f, indent=2, ensure_ascii=False)

    # Summary
    if report.results:
        ban_count = sum(1 for r in report.results if r.verdict == "BAN")
        ok_count = sum(1 for r in report.results if r.verdict == "OK")
        error_count = sum(1 for r in report.results if r.verdict == "ERROR")
        suspect_count = sum(1 for r in report.results if r.verdict == "SUSPECT")
        print(
            f"country={country} domains={len(report.results)} "
            f"ban={ban_count} ok={ok_count} error={error_count} suspect={suspect_count}"
        )
    else:
        print(f"country={country} NODE_UNHEALTHY — no domains checked")


if __name__ == "__main__":
    main()
