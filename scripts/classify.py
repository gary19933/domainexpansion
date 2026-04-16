#!/usr/bin/env python3
"""Shared classification logic for domain ban detection.

Used by both checker_node.py (VPS multi-layer checker) and
check_domains.py (legacy proxy-based checker).
"""

import re
from urllib.parse import urlparse

LABEL_RE = re.compile(r"^[a-z0-9-]{1,63}$")
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

BODY_PREVIEW_LIMIT = 5000

BLOCK_KEYWORDS = [
    "access denied",
    "forbidden",
    "blocked",
    "restricted",
    "not available in your region",
    "this site can't be reached",
    "this site can\u2019t be reached",
    # Thai ISP / MDES block page indicators
    "\u0e1b\u0e34\u0e14\u0e01\u0e31\u0e49\u0e19",              # ปิดกั้น (blocked/censored)
    "\u0e40\u0e27\u0e47\u0e1a\u0e44\u0e0b\u0e15\u0e4c\u0e16\u0e39\u0e01\u0e1a\u0e25\u0e47\u0e2d\u0e01",  # เว็บไซต์ถูกบล็อก (website blocked)
    "\u0e1e.\u0e23.\u0e1a.\u0e04\u0e2d\u0e21\u0e1e\u0e34\u0e27\u0e40\u0e15\u0e2d\u0e23\u0e4c",      # พ.ร.บ.คอมพิวเตอร์ (Computer Act)
    "court order",
    "blocked by order",
    # Thai MDES / NBTC additional patterns
    "\u0e01\u0e23\u0e30\u0e17\u0e23\u0e27\u0e07\u0e14\u0e34\u0e08\u0e34\u0e17\u0e31\u0e25",          # กระทรวงดิจิทัล (Ministry of Digital)
    "mdes.go.th",
    "\u0e04\u0e33\u0e2a\u0e31\u0e48\u0e07\u0e28\u0e32\u0e25",                  # คำสั่งศาล (court order)
    "\u0e44\u0e21\u0e48\u0e2a\u0e32\u0e21\u0e32\u0e23\u0e16\u0e40\u0e02\u0e49\u0e32\u0e16\u0e36\u0e07",          # ไม่สามารถเข้าถึง (cannot access)
    "\u0e40\u0e27\u0e47\u0e1a\u0e44\u0e0b\u0e15\u0e4c\u0e19\u0e35\u0e49\u0e16\u0e39\u0e01\u0e23\u0e30\u0e07\u0e31\u0e1a",      # เว็บไซต์นี้ถูกระงับ (this website is suspended)
    "\u0e1e\u0e23\u0e30\u0e23\u0e32\u0e0a\u0e1a\u0e31\u0e0d\u0e0d\u0e31\u0e15\u0e34",                # พระราชบัญญัติ (Royal Act)
    # Thai ISP specific block pages
    "true online",
    "3bb",
    "website blocked by",
    "\u0e40\u0e27\u0e47\u0e1a\u0e44\u0e0b\u0e15\u0e4c\u0e17\u0e35\u0e48\u0e17\u0e48\u0e32\u0e19\u0e15\u0e49\u0e2d\u0e07\u0e01\u0e32\u0e23\u0e40\u0e02\u0e49\u0e32\u0e0a\u0e21",  # เว็บไซต์ที่ท่านต้องการเข้าชม (website you want to visit)
    # Malay MCMC block page indicators
    "laman web ini disekat",
    "disekat oleh",
    "suruhanjaya komunikasi dan multimedia",
    # Singapore IMDA block page indicators
    "ordered by the",
    "infocommunications media development authority",
]

# Known government / ISP block page hostnames.  When curl follows a redirect
# and lands on one of these hosts the domain is blocked, not simply broken.
BLOCK_PAGE_HOSTS = [
    # Thai MDES (Ministry of Digital Economy and Society)
    "block.mdes.go.th",
    "block-mdes.go.th",
    "mdes.go.th",
    # Thai ISP block pages — True Online / True Corp
    "warning.trueonline.com",
    "block.trueonline.com",
    "warning.truecorp.co.th",
    # Thai ISP — 3BB
    "blocked.3bb.co.th",
    "block.3bb.co.th",
    # Thai ISP — DTAC
    "blockpage.dtac.co.th",
    # Thai ISP — AIS
    "bfrblock.ais.co.th",
    "block.ais.co.th",
    "block.ais.th",
    # Thai ISP — TOT / NT (National Telecom)
    "block.tot.co.th",
    "block.ntplc.co.th",
    # Malaysia MCMC
    "block.mcmc.gov.my",
    "sekatan.mcmc.gov.my",
    # Singapore IMDA
    "block.imda.gov.sg",
]

CHALLENGE_STRONG_KEYWORDS = [
    "attention required",
    "captcha",
    "verify you are human",
    "checking your browser",
    "ddos protection",
]

CHALLENGE_WEAK_KEYWORDS = [
    "cloudflare",
]


# ---------------------------------------------------------------------------
# Domain helpers
# ---------------------------------------------------------------------------

def normalize_hostname(host: str) -> str:
    return (host or "").strip().strip(".").lower()


def is_same_domain_or_www(original_host: str, final_host: str) -> bool:
    orig = normalize_hostname(original_host)
    final = normalize_hostname(final_host)
    if not orig or not final:
        return False
    orig_base = orig[4:] if orig.startswith("www.") else orig
    final_base = final[4:] if final.startswith("www.") else final
    return orig_base == final_base


def is_valid_domain(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    if IPV4_RE.fullmatch(host):
        return False
    labels = host.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not LABEL_RE.fullmatch(label):
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
    if labels[-1].isdigit():
        return False
    return True


def normalize_domain(raw: str) -> str:
    text = raw.strip().lower()
    if not text or text.startswith("#"):
        return ""
    token = text.split()[0]
    probe = token if "://" in token else f"https://{token}"
    parsed = urlparse(probe)
    host = (parsed.hostname or "").strip(".")
    if host.startswith("www."):
        host = host[4:]
    if not is_valid_domain(host):
        return ""
    return host


def _parse_expected_status(comment: str) -> str:
    """Extract expected status from a comment like '# expected:active | ...'."""
    comment = comment.strip().lstrip("#").strip()
    if comment.lower().startswith("expected:"):
        tag = comment[len("expected:"):].split("|")[0].strip().lower()
        if tag in ("active", "banned", "backup"):
            return tag
    return ""


def load_domains(list_file) -> list[str]:
    """Load and deduplicate domains from a text file.

    *list_file* can be a ``pathlib.Path`` or any path-like object.
    """
    from pathlib import Path
    list_file = Path(list_file)
    if not list_file.exists():
        return []
    seen: set[str] = set()
    domains: list[str] = []
    for line in list_file.read_text(encoding="utf-8").splitlines():
        domain = normalize_domain(line)
        if domain and domain not in seen:
            seen.add(domain)
            domains.append(domain)
    return domains


def load_domains_with_expected(list_file) -> list[tuple[str, str]]:
    """Load domains with their expected status annotations.

    Returns list of (domain, expected_status) tuples.
    expected_status is 'active', 'banned', 'backup', or '' if not annotated.
    """
    from pathlib import Path
    list_file = Path(list_file)
    if not list_file.exists():
        return []
    seen: set[str] = set()
    results: list[tuple[str, str]] = []
    for line in list_file.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Split domain from inline comment
        parts = stripped.split("#", 1)
        domain = normalize_domain(parts[0])
        expected = _parse_expected_status(parts[1]) if len(parts) > 1 else ""
        if domain and domain not in seen:
            seen.add(domain)
            results.append((domain, expected))
    return results


# ---------------------------------------------------------------------------
# Content analysis helpers
# ---------------------------------------------------------------------------

def extract_title(html_preview: str) -> str:
    match = TITLE_RE.search(html_preview)
    if not match:
        return ""
    return " ".join(match.group(1).split())[:300]


def contains_any(text: str, keywords: list[str]) -> bool:
    low = (text or "").lower()
    return any(k in low for k in keywords)


def looks_like_real_page(title: str, body_preview: str) -> bool:
    body_title = f"{title}\n{body_preview}".lower()
    if contains_any(body_title, BLOCK_KEYWORDS) or contains_any(
        body_title, CHALLENGE_STRONG_KEYWORDS
    ):
        return False
    if len(body_preview.strip()) >= 120:
        return True
    if title.strip():
        return True
    return False


def is_block_page_host(hostname: str) -> bool:
    host = normalize_hostname(hostname)
    if not host:
        return False
    return any(host == bp or host.endswith("." + bp) for bp in BLOCK_PAGE_HOSTS)


def is_block_code(http_code: str) -> bool:
    if http_code in {"403", "451"}:
        return True
    if re.fullmatch(r"52\d", http_code) or re.fullmatch(r"53\d", http_code):
        return True
    return False


def is_cloudflare_waf(headers_text: str, body_preview: str, http_code: str) -> bool:
    """Detect Cloudflare WAF/protection pages (not ISP blocks).

    Cloudflare 403/503 with CF headers means the origin site has WAF rules,
    NOT that an ISP is blocking it. This is an important distinction —
    WAF blocks happen globally, ISP blocks are country-specific.
    """
    h = (headers_text or "").lower()
    b = (body_preview or "").lower()
    is_cf = "cf-ray" in h or "server: cloudflare" in h
    if not is_cf:
        return False
    # Cloudflare error pages (52x/53x) = origin is down, not ISP block
    if http_code in {"520", "521", "522", "523", "524", "525", "526", "530"}:
        return True
    # Cloudflare 403 with challenge or firewall page = WAF, not ISP
    if http_code == "403" and ("cloudflare" in b or "ray id" in b):
        return True
    return False


def is_domain_down(http_code: str, headers_text: str, body_preview: str) -> bool:
    """Detect if a domain is genuinely down/expired vs ISP-blocked.

    Returns True if the evidence suggests the domain itself is broken
    (expired, no hosting, DNS error) rather than being actively blocked.
    """
    b = (body_preview or "").lower()
    # Common parking/expired domain indicators
    parking_keywords = [
        "this domain is for sale",
        "domain has expired",
        "domain is parked",
        "buy this domain",
        "this webpage is parked",
        "godaddy",
        "namecheap parking",
        "domain parking",
        "is registered at",
        "hugedomains",
        "dan.com",
        "sedo.com",
        "afternic",
        "this site is under construction",
        "coming soon",
        "website coming soon",
    ]
    if any(k in b for k in parking_keywords):
        return True
    return False


# ---------------------------------------------------------------------------
# Redirect / lander helpers
# ---------------------------------------------------------------------------

def is_ready_redirect_target(effective_url: str) -> bool:
    if not effective_url:
        return False
    parsed = urlparse(effective_url)
    effective_low = effective_url.lower()
    final_path = (parsed.path or "").lower()
    return "/lander" in final_path or "/lander" in effective_low


def has_ready_lander_hint(body_preview: str) -> bool:
    body_low = (body_preview or "").lower()
    if "/lander" not in body_low:
        return False
    lander_patterns = [
        'location.href="/lander',
        "location.href='/lander",
        'location.replace("/lander',
        "location.replace('/lander",
        'window.location="/lander',
        "window.location='/lander",
        'window.location.href="/lander',
        "window.location.href='/lander",
        'content="0;url=/lander',
        "content='0;url=/lander",
        'url=/lander',
    ]
    return any(pattern in body_low for pattern in lander_patterns)


def is_sibling_domain_redirect(original_domain: str, final_domain: str) -> bool:
    """Detect redirect from one membersite domain to another sibling domain.

    If uea8th8.com redirects to uea8th9.com, the original domain is banned
    and has been replaced. Both domains belong to the same brand.
    """
    orig = normalize_hostname(original_domain)
    final = normalize_hostname(final_domain)
    if not orig or not final:
        return False
    # Strip www. for comparison
    if orig.startswith("www."):
        orig = orig[4:]
    if final.startswith("www."):
        final = final[4:]
    if orig == final:
        return False
    # Both domains belong to the same brand family
    brand_prefixes = ["uea8", "ueabet"]
    orig_is_brand = any(orig.startswith(p) or orig.split(".")[0].startswith(p) for p in brand_prefixes)
    final_is_brand = any(final.startswith(p) or final.split(".")[0].startswith(p) for p in brand_prefixes)
    return orig_is_brand and final_is_brand


def is_error_redirect_target(effective_url: str, original_domain: str) -> bool:
    if not effective_url:
        return False
    parsed = urlparse(effective_url)
    effective_low = effective_url.lower()
    final_path = (parsed.path or "").lower()
    if "/cgi-sys/defaultwebpage.cgi" in final_path or "/cgi-sys/defaultwebpage.cgi" in effective_low:
        return True
    final_host = normalize_hostname(parsed.hostname or "")
    return not is_same_domain_or_www(original_domain, final_host)
