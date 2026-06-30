#!/usr/bin/env python3
"""Standalone OpenRouter connectivity sanity check.

No imports from guardrail-taxonomy / p0eval / taxonomy assets.
Uses Python stdlib only; SOCKS5 requires optional PySocks (pip install PySocks).

Verifies the full network path: proxy TCP reachability, DNS, TCP peer to
OpenRouter, egress IP (direct vs via proxy), then a minimal chat/completions probe.

Examples:
  python3 scripts/openrouter_saniticheck.py
  python3 scripts/openrouter_saniticheck.py --proxy socks5h://127.0.0.1:1080
  python3 scripts/openrouter_saniticheck.py --no-proxy
  python3 scripts/openrouter_saniticheck.py --model openai/gpt-oss-safeguard-20b
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_MODEL = "openai/gpt-oss-safeguard-20b"
DEFAULT_TIMEOUT = 60
IPIFY_URL = "https://api.ipify.org?format=json"
OPENROUTER_HOST = "openrouter.ai"


def _find_env_file() -> Optional[Path]:
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / ".env"
        if candidate.is_file():
            return candidate
    return None


def _load_dotenv(path: Path) -> None:
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("'").strip('"'))


def _resolve_api_key(explicit: Optional[str]) -> str:
    if explicit:
        return explicit.strip()
    key = os.getenv("OPENROUTER_API_KEY", "").strip()
    if not key or "REPLACE_ME" in key or key.endswith("xxxx"):
        raise SystemExit(
            "OPENROUTER_API_KEY missing or placeholder. "
            "Set it in repo-root .env or pass --api-key."
        )
    return key


def _resolve_proxy(explicit: Optional[str]) -> Optional[str]:
    proxy = (
        explicit
        or os.getenv("OPENROUTER_PROXY")
        or os.getenv("ALL_PROXY")
        or os.getenv("all_proxy")
    )
    if not proxy:
        return None
    proxy = proxy.strip()
    if proxy.lower() in {"", "none", "direct"}:
        return None
    return proxy


def _proxy_kind(proxy: str) -> str:
    scheme = urllib.parse.urlparse(proxy).scheme.lower()
    if scheme == "socks5h":
        return "SOCKS5 (remote DNS via proxy)"
    if scheme == "socks5":
        return "SOCKS5 (local DNS, then CONNECT)"
    if scheme in {"http", "https"}:
        return f"HTTP proxy ({scheme})"
    return scheme or "unknown"


def _format_error(status: int, body: str) -> str:
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return f"HTTP {status}: {body[:400]}"
    err = payload.get("error", payload)
    if isinstance(err, dict):
        parts = [f"HTTP {status}"]
        if err.get("message"):
            parts.append(str(err["message"]))
        meta = err.get("metadata") or {}
        if meta.get("provider_name"):
            parts.append(f"provider={meta['provider_name']}")
        if meta.get("raw"):
            parts.append(str(meta["raw"])[:200])
        return " | ".join(parts)
    return f"HTTP {status}: {str(err)[:400]}"


def _addr_str(addr: tuple) -> str:
    host, port = addr[0], addr[1]
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{host}:{port}"


@dataclass
class TcpProbe:
    ok: bool
    local: Optional[str] = None
    peer: Optional[str] = None
    error: Optional[str] = None


def _open_socks_socket(proxy: str, timeout: float):
    try:
        import socks  # type: ignore
    except ImportError as exc:
        raise SystemExit(
            "SOCKS proxy requested but PySocks is not installed. "
            "Install with: pip install PySocks"
        ) from exc

    parsed = urllib.parse.urlparse(proxy)
    host = parsed.hostname
    port = parsed.port or 1080
    rdns = parsed.scheme.lower() == "socks5h"
    sock = socks.socksocket()
    sock.set_proxy(socks.SOCKS5, host, port, rdns=rdns)
    sock.settimeout(timeout)
    return sock, rdns


def _tcp_probe_endpoint(
    host: str,
    port: int,
    *,
    proxy: Optional[str],
    timeout: float,
) -> TcpProbe:
    try:
        if proxy and proxy.lower().startswith("socks"):
            sock, rdns = _open_socks_socket(proxy, timeout)
            sock.connect((host, port))
            local = _addr_str(sock.getsockname())
            peer_raw = sock.getpeername()
            if rdns and not _looks_like_ip(peer_raw[0]):
                peer = f"{peer_raw[0]}:{peer_raw[1]} (hostname via socks5h remote DNS)"
            else:
                peer = _addr_str(peer_raw)
            sock.close()
            return TcpProbe(ok=True, local=local, peer=peer)
        with socket.create_connection((host, port), timeout=timeout) as sock:
            return TcpProbe(
                ok=True,
                local=_addr_str(sock.getsockname()),
                peer=_addr_str(sock.getpeername()),
            )
    except OSError as exc:
        return TcpProbe(ok=False, error=str(exc))


def _socks_gateway_probe(proxy: str, timeout: float) -> TcpProbe:
    parsed = urllib.parse.urlparse(proxy)
    phost = parsed.hostname or "127.0.0.1"
    pport = parsed.port or 1080
    return _tcp_probe_endpoint(phost, pport, proxy=None, timeout=timeout)


def _socks_connect_to_ip(proxy: str, ip: str, port: int, timeout: float) -> TcpProbe:
    """Connect to a numeric IP through SOCKS5 (local DNS path) to reveal remote peer IP."""
    socks5 = proxy.replace("socks5h://", "socks5://", 1).replace("SOCKS5H://", "socks5://", 1)
    try:
        sock, _ = _open_socks_socket(socks5, timeout)
        sock.connect((ip, port))
        result = TcpProbe(
            ok=True,
            local=_addr_str(sock.getsockname()),
            peer=_addr_str(sock.getpeername()),
        )
        sock.close()
        return result
    except OSError as exc:
        return TcpProbe(ok=False, error=str(exc))


def _first_ipv4(candidates: list[str]) -> Optional[str]:
    for item in candidates:
        if _looks_like_ip(item) and ":" not in item:
            return item
    return None


def _short_error(err: Optional[str]) -> str:
    if not err:
        return "(unknown)"
    if "Connection refused" in err:
        return "unreachable (connection refused)"
    if "timed out" in err.lower():
        return "unreachable (timeout)"
    return err[:120]


def _looks_like_ip(value: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, value)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, value)
        return True
    except OSError:
        return False


def _resolve_dns_local(hostname: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        return [f"(lookup failed: {exc})"]
    seen: set[str] = set()
    out: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out or ["(no A/AAAA records)"]


def _https_via_socks(
    url: str,
    *,
    method: str,
    headers: dict[str, str],
    body: Optional[bytes],
    proxy: str,
    timeout: int,
) -> tuple[int, str]:
    parsed_url = urllib.parse.urlparse(url)
    if parsed_url.scheme != "https":
        raise ValueError(f"Only https URLs supported for SOCKS: {url}")

    sock, _ = _open_socks_socket(proxy, timeout)
    sock.connect((parsed_url.hostname, parsed_url.port or 443))

    context = ssl.create_default_context()
    with context.wrap_socket(sock, server_hostname=parsed_url.hostname) as ssock:
        conn = http.client.HTTPSConnection(parsed_url.hostname, timeout=timeout)
        conn.sock = ssock
        path = parsed_url.path or "/"
        if parsed_url.query:
            path = f"{path}?{parsed_url.query}"
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        return resp.status, resp.read().decode("utf-8", errors="replace")


def _https_request(
    url: str,
    *,
    method: str = "GET",
    headers: Optional[dict[str, str]] = None,
    body: Optional[bytes] = None,
    proxy: Optional[str] = None,
    timeout: int = 30,
) -> tuple[int, str]:
    headers = headers or {}
    if proxy and proxy.lower().startswith("socks"):
        try:
            return _https_via_socks(
                url, method=method, headers=headers, body=body, proxy=proxy, timeout=timeout
            )
        except OSError as exc:
            return 0, str(exc)

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        return 0, str(exc)


def _fetch_egress_ip(proxy: Optional[str], timeout: int) -> tuple[Optional[str], Optional[str]]:
    status, raw = _https_request(IPIFY_URL, proxy=proxy, timeout=timeout)
    if status == 0:
        return None, raw
    if status != 200:
        return None, f"HTTP {status}: {raw[:200]}"
    try:
        payload = json.loads(raw)
        ip = payload.get("ip")
        if ip:
            return str(ip), None
    except json.JSONDecodeError:
        pass
    text = raw.strip()
    return (text if text else None), None if text else "empty ipify response"


def _tls_peer_cert_summary(host: str, *, proxy: Optional[str], timeout: int) -> Optional[str]:
    try:
        if proxy and proxy.lower().startswith("socks"):
            sock, _ = _open_socks_socket(proxy, timeout)
            sock.connect((host, 443))
            context = ssl.create_default_context()
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        else:
            context = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=timeout) as raw:
                with context.wrap_socket(raw, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
    except OSError:
        return None

    if not cert:
        return None
    subject = dict(x[0] for x in cert.get("subject", ()))
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    cn = subject.get("commonName", "?")
    issuer_cn = issuer.get("commonName", issuer.get("organizationName", "?"))
    return f"CN={cn}, issuer={issuer_cn}"


def _print_network_audit(
    *,
    proxy: Optional[str],
    timeout: int,
    compare_direct: bool,
) -> tuple[bool, Optional[str], Optional[str], bool]:
    """Return (route_ok, proxy_egress, direct_egress, proxy_verified)."""
    print("\n--- Network path audit ---")

    proxy_egress: Optional[str] = None
    direct_egress: Optional[str] = None
    proxy_verified = False

    if proxy:
        parsed = urllib.parse.urlparse(proxy)
        phost = parsed.hostname or "?"
        pport = parsed.port or (1080 if "socks" in (parsed.scheme or "") else 8080)
        proxy_tcp = _socks_gateway_probe(proxy, timeout=5.0)
        print(f"  configured_proxy : {proxy}")
        print(f"  proxy.type       : {_proxy_kind(proxy)}")
        print(
            f"  proxy.tcp        : {phost}:{pport} "
            f"({'reachable' if proxy_tcp.ok else 'unreachable'})"
        )
        if proxy_tcp.ok:
            print(f"    hop local      : {proxy_tcp.local} -> {proxy_tcp.peer}")
        elif proxy_tcp.error:
            print(f"                     error: {proxy_tcp.error}")
    else:
        print("  configured_proxy : (direct, no proxy)")

    local_ips = _resolve_dns_local(OPENROUTER_HOST)
    print(f"  dns.local {OPENROUTER_HOST}:")
    for ip in local_ips:
        print(f"    {ip}")

    route_label = "via proxy" if proxy else "direct"
    or_tcp = _tcp_probe_endpoint(OPENROUTER_HOST, 443, proxy=proxy, timeout=float(timeout))
    print(f"  tcp.{OPENROUTER_HOST}:443 ({route_label}):")
    if or_tcp.ok:
        print(f"    client local   : {or_tcp.local}")
        if proxy:
            parsed = urllib.parse.urlparse(proxy)
            pgw = f"{parsed.hostname}:{parsed.port or 1080}"
            print(f"    socks gateway  : {pgw} (traffic enters local SOCKS daemon)")
        print(f"    remote target  : {or_tcp.peer}")
        ref_ip = _first_ipv4(local_ips)
        if proxy and ref_ip:
            ip_probe = _socks_connect_to_ip(proxy, ref_ip, 443, min(timeout, 15))
            if ip_probe.ok:
                print(
                    f"    target ip ref  : {ip_probe.peer} "
                    f"(socks5 CONNECT to {ref_ip}, same proxy path)"
                )
    else:
        print(f"    failed       : {or_tcp.error}")

    tls = _tls_peer_cert_summary(OPENROUTER_HOST, proxy=proxy, timeout=min(timeout, 15))
    if tls:
        print(f"  tls.{OPENROUTER_HOST} ({route_label}): {tls}")

    direct_egress: Optional[str] = None
    direct_err: Optional[str] = None
    if compare_direct or not proxy:
        direct_egress, direct_err = _fetch_egress_ip(None, timeout=min(timeout, 15))
        if direct_egress:
            print(f"  egress.direct    : {direct_egress}")
        else:
            print(f"  egress.direct    : {_short_error(direct_err)}")

    if proxy:
        proxy_egress, proxy_err = _fetch_egress_ip(proxy, timeout=min(timeout, 15))
        print(f"  egress.via_proxy : {proxy_egress or proxy_err or '(unknown)'}")

        if proxy_egress and direct_egress and proxy_egress != direct_egress:
            proxy_verified = True
            print("  proxy.active     : YES — egress IP differs from direct (SOCKS path in use)")
        elif proxy_egress and direct_egress and proxy_egress == direct_egress:
            print(
                "  proxy.active     : WARN — egress IP same as direct "
                "(proxy may be same exit, transparent, or misconfigured)"
            )
        elif proxy_egress and not direct_egress:
            proxy_verified = True
            print(
                "  proxy.active     : LIKELY — proxy egress OK, direct unreachable "
                "(cannot compare; API will use proxy)"
            )
        elif not proxy_egress:
            print(f"  proxy.active     : FAIL — proxy egress probe failed: {proxy_err}")
        else:
            print("  proxy.active     : UNKNOWN — could not determine")

        if not or_tcp.ok:
            print("  route.openrouter : FAIL — cannot TCP-connect to OpenRouter via proxy")
            return False, proxy_egress, direct_egress, proxy_verified
        if not proxy_egress:
            return False, None, direct_egress, False
        return True, proxy_egress, direct_egress, proxy_verified

    if not or_tcp.ok:
        print("  route.openrouter : FAIL — cannot TCP-connect to OpenRouter")
        return False, None, direct_egress, False
    print("  route.openrouter : direct path OK")
    return True, None, direct_egress, True


def run_check(
    *,
    api_key: str,
    model: str,
    base_url: str,
    proxy: Optional[str],
    timeout: int,
    compare_direct: bool,
    require_proxy_active: bool,
) -> int:
    print("OpenRouter sanity check")
    print(f"  base_url : {base_url}")
    print(f"  model    : {model}")
    print(f"  timeout  : {timeout}s")

    route_ok, proxy_egress, direct_egress, proxy_verified = _print_network_audit(
        proxy=proxy, timeout=timeout, compare_direct=compare_direct
    )
    if not route_ok:
        print("\n  result   : FAIL (network path)")
        return 1

    if proxy and require_proxy_active:
        if not proxy_egress:
            print("\n  result   : FAIL (proxy egress unreachable)")
            return 1
        if compare_direct and direct_egress and proxy_egress == direct_egress:
            print("\n  result   : FAIL (--require-proxy-active: egress unchanged vs direct)")
            return 1
        if compare_direct and direct_egress and proxy_egress != direct_egress:
            print("  proxy.strict   : PASS — egress differs from direct")
        elif not direct_egress:
            print("  proxy.strict   : PASS — proxy egress OK (direct unreachable)")
        else:
            print("  proxy.strict   : PASS — proxy path verified")

    print("\n--- OpenRouter API probe ---")
    url = f"{base_url.rstrip('/')}/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "X-Title": "OpenRouter Sanity Check",
    }
    body = {
        "model": model,
        "messages": [
            {
                "role": "user",
                "content": (
                    "Connectivity probe only. Reply with exactly one JSON object: "
                    '{"status":"ok"}'
                ),
            }
        ],
        "temperature": 0,
        "max_tokens": 32,
        "response_format": {"type": "json_object"},
    }

    started = time.monotonic()
    status, raw = _https_request(
        url,
        method="POST",
        headers=headers,
        body=json.dumps(body).encode("utf-8"),
        proxy=proxy,
        timeout=timeout,
    )
    elapsed = time.monotonic() - started

    print(f"  route    : {'via proxy' if proxy else 'direct'}")
    print(f"  latency  : {elapsed:.2f}s")
    print(f"  http     : {status}")

    if status != 200:
        print("  result   : FAIL")
        print(f"  detail   : {_format_error(status, raw)}")
        if status == 429:
            print(
                "  hint     : Groq upstream rate limit — retry later, bind a Groq key "
                "at https://openrouter.ai/settings/integrations."
            )
        elif status == 403:
            print("  hint     : upstream ToS/content policy block on probe payload.")
        return 1

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        print("  result   : FAIL")
        print(f"  detail   : non-JSON response: {raw[:300]}")
        return 1

    message = payload.get("choices", [{}])[0].get("message", {})
    content = (message.get("content") or "")[:200]
    upstream_model = payload.get("model", model)
    print("  result   : PASS")
    print(f"  upstream : {upstream_model}")
    if content:
        print(f"  content  : {content}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-key", help="OpenRouter API key (default: OPENROUTER_API_KEY / .env)")
    parser.add_argument("--model", default=os.getenv("OPENROUTER_MODEL", DEFAULT_MODEL))
    parser.add_argument("--base-url", default=os.getenv("OPENROUTER_BASE_URL", DEFAULT_BASE_URL))
    proxy_group = parser.add_mutually_exclusive_group()
    proxy_group.add_argument(
        "--proxy",
        default=None,
        help="Proxy URL, e.g. socks5h://127.0.0.1:1080 (default: OPENROUTER_PROXY / ALL_PROXY)",
    )
    proxy_group.add_argument(
        "--no-proxy",
        action="store_true",
        help="Force direct connection; ignore OPENROUTER_PROXY / ALL_PROXY from env",
    )
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument(
        "--no-compare-direct",
        action="store_true",
        help="Skip direct egress IP probe (faster; less proxy verification)",
    )
    parser.add_argument(
        "--require-proxy-active",
        action="store_true",
        help="Fail if proxy egress IP equals direct egress (strict SOCKS verification)",
    )
    parser.add_argument("--env-file", type=Path, help="Optional .env path (default: search upward)")
    args = parser.parse_args()

    env_path = args.env_file or _find_env_file()
    if env_path and env_path.is_file():
        _load_dotenv(env_path)
        print(f"  env_file : {env_path}")
    else:
        print("  env_file : (not found, using process environment only)")

    api_key = _resolve_api_key(args.api_key)
    if args.no_proxy:
        proxy = None
    else:
        proxy = _resolve_proxy(args.proxy)
    if args.require_proxy_active and not proxy:
        raise SystemExit("--require-proxy-active requires a proxy (omit --no-proxy)")
    return run_check(
        api_key=api_key,
        model=args.model,
        base_url=args.base_url,
        proxy=proxy,
        timeout=args.timeout,
        compare_direct=not args.no_compare_direct,
        require_proxy_active=args.require_proxy_active,
    )


if __name__ == "__main__":
    raise SystemExit(main())
