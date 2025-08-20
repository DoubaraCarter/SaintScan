import asyncio
import socket
import ssl
from typing import List, Dict, Any, Optional, Iterable
from urllib.parse import (
    urljoin,
    urlparse,
    parse_qs,
    urlencode,
    urlunparse,
    ParseResult,
)

import httpx
from bs4 import BeautifulSoup

USER_AGENT = "SaintScan/1.0 (+https://github.com/saint) Python httpx"
TIMEOUT = 15.0

# --- Guidance used in findings ---
SecurityHeaderAdvice = {
    "content-security-policy": "Define a strict CSP (e.g., default-src 'self') with nonces/hashes.",
    "x-frame-options": "Use DENY or SAMEORIGIN to mitigate clickjacking.",
    "x-content-type-options": "Set to 'nosniff' to prevent MIME sniffing.",
    "referrer-policy": "Prefer 'strict-origin-when-cross-origin' or stricter.",
    "permissions-policy": "Explicitly limit powerful browser features.",
    "strict-transport-security": "Enable HSTS with includeSubDomains and consider preload (HTTPS sites).",
}

SENSITIVE_PATHS = [
    "/robots.txt",
    "/.env",
    "/.git/HEAD",
    "/.git/config",
    "/.DS_Store",
    "/backup.zip",
    "/database.sql",
    "/phpinfo.php",
    "/server-status",
    "/admin",
    "/.well-known/security.txt",
]

OPEN_REDIRECT_PARAMS = {"redirect", "next", "url", "continue", "return", "dest", "destination"}


def _make_finding(
    url: str,
    fid: str,
    title: str,
    severity: str,
    category: str,
    description: str,
    recommendation: str,
    cvss: float = 0.0,
    evidence: Optional[List[Dict[str, str]]] = None,
) -> Dict[str, Any]:
    return {
        "url": url,
        "id": fid,
        "title": title,
        "severity": severity,  # info|low|medium|high|critical
        "category": category,
        "description": description,
        "recommendation": recommendation,
        "cvss": cvss,
        "evidence": evidence or [],
    }


def _same_host(a: str, b: str) -> bool:
    return urlparse(a).netloc == urlparse(b).netloc


async def _fetch(client: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
    try:
        r = await client.get(url, follow_redirects=True, timeout=TIMEOUT, headers={"User-Agent": USER_AGENT})
        return r
    except Exception:
        return None


def _extract_links(base_url: str, html: str) -> List[str]:
    links: List[str] = []
    soup = BeautifulSoup(html or "", "html.parser")
    for a in soup.find_all("a", href=True):
        abs_url = urljoin(base_url, a.get("href"))
        links.append(abs_url)
    return links


def _check_security_headers(url: str, resp: httpx.Response) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    hdrs = {k.lower(): v for k, v in resp.headers.items()}
    missing = [h for h in SecurityHeaderAdvice.keys() if h not in hdrs]

    if missing:
        evidence = [{"url": url, "details": f"Missing: {h}"} for h in missing]
        sev = "medium"
        if "strict-transport-security" in missing and resp.url.scheme == "https":
            sev = "high"
        rec = " | ".join(SecurityHeaderAdvice[h] for h in SecurityHeaderAdvice)
        findings.append(
            _make_finding(
                url,
                "WEB-SEC-HEADERS",
                "Missing recommended security headers",
                sev,
                "Misconfiguration",
                f"Missing headers: {', '.join(missing)}",
                rec,
                cvss=5.3 if sev == "medium" else 7.5,
                evidence=evidence,
            )
        )
    return findings


def _check_cookie_flags(url: str, resp: httpx.Response) -> List[Dict[str, Any]]:
    # Support multi-value Set-Cookie
    raw = []
    try:
        raw = resp.headers.get_list("set-cookie")  # type: ignore[attr-defined]
    except Exception:
        v = resp.headers.get("set-cookie", "")
        raw = [v] if v else []

    weak = []
    for c in raw:
        cl = c.lower()
        if ("secure" not in cl) or ("httponly" not in cl) or ("samesite" not in cl):
            weak.append({"url": url, "details": c})

    if weak:
        return [
            _make_finding(
                url,
                "WEB-COOKIE-FLAGS",
                "Weak cookie flags",
                "medium",
                "Session Management",
                "Cookies appear to be missing Secure/HttpOnly/SameSite.",
                "Set Secure, HttpOnly and SameSite=Lax/Strict for session cookies.",
                cvss=5.3,
                evidence=weak,
            )
        ]
    return []


def _check_directory_listing(url: str, html: str) -> List[Dict[str, Any]]:
    indicators = ["Index of /", "Directory listing for", "<title>Index of", "Parent Directory"]
    if any(s in (html or "") for s in indicators):
        return [
            _make_finding(
                url,
                "WEB-DIR-LIST",
                "Directory listing enabled",
                "medium",
                "Information Disclosure",
                "Autoindex page exposes internal files.",
                "Disable autoindex on the server or restrict via proper access controls.",
                cvss=5.0,
                evidence=[{"url": url, "details": "Autoindex markers present"}],
            )
        ]
    return []


async def _check_sensitive_files(client: httpx.AsyncClient, base_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    evid: List[Dict[str, str]] = []

    async def fetch_path(p: str):
        try:
            r = await client.get(urljoin(base_url, p), timeout=TIMEOUT, headers={"User-Agent": USER_AGENT})
            # Consider 200 OK or readable text bytes as exposure
            if r.status_code == 200 and (r.text is not None):
                sample = (r.text or "")[:200]
                evid.append({"url": str(r.url), "details": f"Accessible {p}", "sample": sample})
        except Exception:
            pass

    await asyncio.gather(*[fetch_path(p) for p in SENSITIVE_PATHS])
    if evid:
        findings.append(
            _make_finding(
                base_url,
                "WEB-SENSITIVE-FILES",
                "Sensitive files publicly accessible",
                "high",
                "Information Disclosure",
                "Common sensitive files or backups are accessible from the web root.",
                "Remove secrets/backups from web root; block via server rules; use a secrets manager.",
                cvss=7.5,
                evidence=evid,
            )
        )
    return findings


def _check_open_redirect_heuristics(page_url: str, html: str) -> List[Dict[str, Any]]:
    """Static heuristic: find internal links with redirect-like params pointing off-site."""
    soup = BeautifulSoup(html or "", "html.parser")
    base_host = urlparse(page_url).netloc
    hits = []

    for a in soup.find_all("a", href=True):
        abs_url = urljoin(page_url, a["href"])
        u = urlparse(abs_url)
        if u.netloc != base_host:
            # not a local endpoint
            continue

        qs = parse_qs(u.query)
        for key, vals in qs.items():
            if key.lower() in OPEN_REDIRECT_PARAMS:
                for v in vals:
                    dest = urlparse(v)
                    if dest.scheme in ("http", "https") and dest.netloc and dest.netloc != base_host:
                        hits.append({"url": abs_url, "details": f"{key} -> {v}"})

    if hits:
        return [
            _make_finding(
                page_url,
                "WEB-OPEN-REDIRECT-HEUR",
                "Potential open redirect parameters (heuristic)",
                "low",
                "Access Control",
                "Detected parameters that may allow redirection to external domains.",
                "Validate & whitelist redirect destinations; use state/tokens; avoid reflecting arbitrary URLs.",
                cvss=3.7,
                evidence=hits,
            )
        ]
    return []


async def _test_open_redirect_active(client: httpx.AsyncClient, url: str) -> List[Dict[str, Any]]:
    """
    Active test: for endpoints that contain redirect-like params, try setting one to a controlled external value,
    and see if server responds with a redirect to that domain (no auto-follow).
    """
    u = urlparse(url)
    qs = parse_qs(u.query)
    candidates = [k for k in qs.keys() if k.lower() in OPEN_REDIRECT_PARAMS]
    if not candidates:
        return []

    test_dest = "https://example.org/"
    evid = []
    for key in candidates:
        new_qs = qs.copy()
        new_qs[key] = [test_dest]
        new_query = urlencode(new_qs, doseq=True)
        test_url = urlunparse((u.scheme, u.netloc, u.path or "/", u.params, new_query, u.fragment))
        try:
            r = await client.get(test_url, follow_redirects=False, timeout=TIMEOUT, headers={"User-Agent": USER_AGENT})
            loc = r.headers.get("location", "")
            if 300 <= r.status_code < 400 and loc.startswith(test_dest):
                evid.append({"url": test_url, "details": f"Redirects to {loc}"})
        except Exception:
            pass

    if evid:
        return [
            _make_finding(
                url,
                "WEB-OPEN-REDIRECT",
                "Open redirect confirmed",
                "high",
                "Access Control",
                "Endpoint redirects to an arbitrary external URL controlled via query parameter.",
                "Whitelist redirect targets; use fixed paths or server-side state; validate strictly.",
                cvss=7.7,
                evidence=evid,
            )
        ]
    return []


async def _check_reflected_xss(client: httpx.AsyncClient, url: str) -> List[Dict[str, Any]]:
    """
    Conservative reflected XSS probe: append a harmless payload into a 'q' param (or add one)
    and detect raw reflection in HTML.
    """
    try:
        u = urlparse(url)
        existing_qs = parse_qs(u.query)
        payload = "<script>alert(1)</script>"
        # put under 'q' or reuse a param if any exist
        if existing_qs:
            target_key = list(existing_qs.keys())[0]
        else:
            target_key = "q"
        existing_qs[target_key] = [payload]
        new_query = urlencode(existing_qs, doseq=True)
        test_url = urlunparse((u.scheme, u.netloc, u.path or "/", u.params, new_query, u.fragment))

        r = await client.get(test_url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
        # naive reflection (unescaped). This is intentionally conservative.
        if payload in (r.text or ""):
            return [
                _make_finding(
                    url,
                    "WEB-REFLECTED-XSS",
                    "Reflected XSS (naive check)",
                    "high",
                    "Injection",
                    "The test payload appears to be reflected back unescaped.",
                    "Contextually escape output, enable template auto-escape, validate/sanitize inputs.",
                    cvss=7.1,
                    evidence=[{"url": str(r.url), "details": "Payload reflected in response body"}],
                )
            ]
    except Exception:
        pass
    return []


def _cipher_is_weak(cipher: Optional[tuple]) -> bool:
    """
    cipher tuple typically looks like ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256) or impl-dependent.
    We'll do a simple name check for obviously weak ciphers.
    """
    if not cipher:
        return True
    name = str(cipher[0]).upper()
    # Basic weak indicators
    weak_markers = ("RC4", "3DES", "NULL", "MD5", "EXPORT")
    return any(m in name for m in weak_markers)


def _tls_version_is_modern(version: Optional[str]) -> bool:
    return version in ("TLSv1.2", "TLSv1.3")


def _sync_check_ssl_tls(hostname: str, port: int = 443) -> Optional[Dict[str, Any]]:
    """
    Synchronous TLS check: connects and inspects negotiated version/cipher.
    We call this via asyncio.to_thread so it doesn't block the event loop.
    """
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                proto = ssock.version()  # e.g., 'TLSv1.3'
                cipher = ssock.cipher()  # e.g., ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
                if (not _tls_version_is_modern(proto)) or _cipher_is_weak(cipher):
                    desc = f"Negotiated {proto or 'Unknown'} / {cipher[0] if cipher else 'Unknown cipher'}"
                    return _make_finding(
                        f"{hostname}:{port}",
                        "TLS-WEAK-CONFIG",
                        "Potentially weak TLS configuration",
                        "medium",
                        "Cryptography",
                        desc,
                        "Disable legacy protocols (TLS 1.0/1.1); prefer TLS 1.2+/modern AEAD ciphersuites.",
                        cvss=5.9,
                        evidence=[{"url": f"{hostname}:{port}", "details": str(cipher)}],
                    )
    except Exception:
        return None
    return None


async def _check_ssl_tls_once(hostname: str) -> List[Dict[str, Any]]:
    finding = await asyncio.to_thread(_sync_check_ssl_tls, hostname, 443)
    return [finding] if finding else []


async def crawl_and_scan(start_url: str, depth: int = 1, max_pages: int = 30, rate: int = 5) -> List[Dict[str, Any]]:
    """
    Crawl same-origin pages up to `depth`, scan each page with lightweight checks,
    and run a few host-level probes (TLS, sensitive paths).
    """
    start_url = start_url.strip()
    if not start_url.startswith(("http://", "https://")):
        start_url = "http://" + start_url

    seen = set([start_url])
    queue: List[str] = [start_url]
    findings: List[Dict[str, Any]] = []
    base = urlparse(start_url)
    base_host = base.netloc

    sem = asyncio.Semaphore(rate)
    limits = httpx.Limits(max_keepalive_connections=20, max_connections=40)
    async with httpx.AsyncClient(limits=limits, headers={"User-Agent": USER_AGENT}) as client:
        # One-time host checks
        findings.extend(await _check_ssl_tls_once(base_host))
        findings.extend(await _check_sensitive_files(client, start_url))
        findings.extend(await _check_reflected_xss(client, start_url))
        findings.extend(await _test_open_redirect_active(client, start_url))

        current_depth = 0
        while queue and len(seen) <= max_pages and current_depth <= depth:
            batch: List[str] = []
            for _ in range(min(len(queue), 10)):
                batch.append(queue.pop(0))

            async def scan_one(u: str):
                async with sem:
                    resp = await _fetch(client, u)
                    if not resp:
                        return {"url": u, "html": None, "links": []}
                    text = resp.text or ""
                    local_findings: List[Dict[str, Any]] = []
                    local_findings.extend(_check_security_headers(str(resp.url), resp))
                    local_findings.extend(_check_cookie_flags(str(resp.url), resp))
                    local_findings.extend(_check_directory_listing(str(resp.url), text))
                    local_findings.extend(_check_open_redirect_heuristics(str(resp.url), text))
                    # Opportunistic active tests on endpoints with query
                    if urlparse(str(resp.url)).query:
                        local_findings.extend(await _test_open_redirect_active(client, str(resp.url)))
                        local_findings.extend(await _check_reflected_xss(client, str(resp.url)))

                    if local_findings:
                        findings.extend(local_findings)

                    same_origin_links = [
                        l for l in _extract_links(str(resp.url), text) if _same_host(l, start_url)
                    ]
                    return {"url": str(resp.url), "links": same_origin_links}

            results = await asyncio.gather(*[scan_one(u) for u in batch])

            if current_depth < depth:
                next_links: List[str] = []
                for r in results:
                    for link in r.get("links", []):
                        if link not in seen and len(seen) <= max_pages:
                            seen.add(link)
                            next_links.append(link)
                queue.extend(next_links)

            current_depth += 1

    return findings
