"""
Controlled SSRF payload generation.

Design goals:
- Only target attacker-controlled OOB domains
- Always tag payloads with UUIDs for correlation
- Never hit localhost/metadata IPs
- Provide both direct and behavioral (redirect/unreachable) variants
"""
import uuid
import ipaddress
from typing import List, Dict
from urllib.parse import urlparse

FORBIDDEN_IPS = {
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "169.254.169.254",  # cloud metadata (AWS/GCP/Azure)
}

FORBIDDEN_HOST_SUBSTRINGS = {
    "metadata.google",
    "metadata.azure",
    "metadata.aws",
    "amazonaws.com",
    "gce",
    "internal",
}


def _is_forbidden_host(host: str) -> bool:
    """Guard against localhost/metadata targets."""
    host = host.lower()
    try:
        # If host is an IP literal, reject private/reserved
        ip_obj = ipaddress.ip_address(host.split(":", 1)[0])
        if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local:
            return True
        if str(ip_obj) in FORBIDDEN_IPS:
            return True
    except ValueError:
        # Not an IP literal; check known bad substrings
        if any(bad in host for bad in FORBIDDEN_HOST_SUBSTRINGS):
            return True
    return False


def _normalize_oob_host(oob_domain: str) -> str:
    parsed = urlparse(oob_domain)
    host = parsed.netloc or parsed.path
    host = host.strip().strip("/")
    if not host:
        raise ValueError("OOB domain/host is required for SSRF payloads")
    if _is_forbidden_host(host):
        raise ValueError("Forbidden OOB host provided; refusing to generate SSRF payloads")
    return host


class SSRFPayloadEngine:
    """Generate controlled SSRF URLs scoped to an attacker-controlled domain."""

    def __init__(self, oob_domain: str):
        self.base_host = _normalize_oob_host(oob_domain)

    def build_payloads(self) -> List[Dict[str, str]]:
        """
        Return a curated list of SSRF payloads. All payloads are HTTP(S) only and
        tag UUIDs on subdomains for correlation. A small set of behavioral
        variants is included (redirect/unreachable) for inference without
        exploitation.
        """
        payloads: List[Dict[str, str]] = []

        def add(kind: str, url: str, tier: str, control: bool = False, note: str = ""):
            payload_uuid = str(uuid.uuid4())
            payloads.append({
                "uuid": payload_uuid,
                "url": url.format(uuid=payload_uuid),
                "kind": kind,
                "tier": tier,
                "control": control,
                "note": note,
            })

        # Direct callbacks (primary OOB confirmation path)
        add(
            kind="direct_http",
            url=f"http://{{uuid}}.{self.base_host}/?id={{uuid}}",
            tier="OOB",
            note="Direct HTTP callback"
        )
        add(
            kind="direct_https",
            url=f"https://{{uuid}}.{self.base_host}/resource?id={{uuid}}",
            tier="OOB",
            note="Direct HTTPS callback"
        )

        # Controlled redirect chain (safe external hop)
        add(
            kind="redirect_chain",
            url=f"https://redirector.{self.base_host}/{{uuid}}?id={{uuid}}",
            tier="OOB",
            note="External redirect chain for SSRF-capable fetchers"
        )

        # Unreachable external host for timing/behavioral analysis
        add(
            kind="unreachable_probe",
            url=f"https://{{uuid}}.unreachable.{self.base_host}/?id={{uuid}}",
            tier="EXPANDED",
            control=True,
            note="Intentionally unreachable external host"
        )

        return payloads


__all__ = ["SSRFPayloadEngine", "_is_forbidden_host", "_normalize_oob_host"]
