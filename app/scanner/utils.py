from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urljoin, urlparse

import requests


BLOCKED_DOMAINS = {
    domain.strip().lower().rstrip(".")
    for domain in os.environ.get("WEBSEC_BLOCKED_DOMAINS", "").split(",")
    if domain.strip()
}

DEFAULT_HEADERS = {
    "User-Agent": "WebSecInternshipScanner/1.0 (+local educational scanner)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


class TargetValidationError(ValueError):
    pass


class BlockedTargetError(TargetValidationError):
    pass


def normalize_url(raw_url: str) -> str:
    candidate = (raw_url or "").strip()
    if not candidate:
        raise TargetValidationError("Target URL is required.")
    if "://" not in candidate:
        candidate = f"http://{candidate}"

    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"}:
        raise TargetValidationError("Only http and https targets are supported.")
    if not parsed.hostname:
        raise TargetValidationError("Target URL must include a hostname.")
    return candidate.rstrip("/")


def is_blocked_target(raw_url: str) -> bool:
    parsed = urlparse(raw_url if "://" in raw_url else f"http://{raw_url}")
    hostname = (parsed.hostname or "").lower().rstrip(".")
    return any(hostname == domain or hostname.endswith(f".{domain}") for domain in BLOCKED_DOMAINS)


def validate_not_blocked(raw_url: str) -> None:
    if is_blocked_target(raw_url):
        blocked = ", ".join(sorted(BLOCKED_DOMAINS))
        raise BlockedTargetError(
            "This domain is blocked by scanner policy. "
            f"Blocked domains: {blocked}."
        )


def resolve_host(hostname: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return []
    return sorted({item[4][0] for item in infos})


def is_private_host(hostname: str) -> bool:
    addresses = resolve_host(hostname)
    if not addresses:
        return False
    for address in addresses:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return True
    return False


def same_origin(base_url: str, candidate: str) -> bool:
    base = urlparse(base_url)
    other = urlparse(candidate)
    return (base.scheme, base.hostname, base.port) == (other.scheme, other.hostname, other.port)


def safe_join(base_url: str, path: str) -> str:
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def build_session(timeout: float) -> requests.Session:
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)
    session.request_timeout = timeout
    return session
