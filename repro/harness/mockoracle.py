"""Fake www.oracle.com for the PR 4532 reproducers. Stdlib only.

One MockOracle binds one ThreadingHTTPServer per loopback host (127.0.0.1,
127.0.0.2, ...) on a free port each. The scenario dict is set after the bind
so fixtures can point at the other hosts. Every request is appended to
``requests`` (host, port, path, status, bytes_sent, t). Only the PR code
decides what to fetch, this server never pushes anything.

Scenario keys:
  slugs: advisory slugs linked from the index
  index: {status, redirect, body, drip: [chunk_bytes, interval_s]}
  pages: {slug: {sections: [(heading, [cves])], history: {heading_html, cves},
                 csaf_href, status, redirect, body}}
  csaf:  {slug: {vulns: [{cve, bug, product}], body, redirect, status,
                 pad_mb, product_tree}}
  evil:  {path: {vulns: [...], body}}  served on any host
"""

from __future__ import annotations

import json
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

INDEX_PATHS = ("/security-alerts/", "/security-alerts")
CSAF_PREFIX = "/docs/tech/security-alerts/"
CSAF_FINAL_PREFIX = "/a/tech/docs/security-alerts/"
ORACLE = "https://www.oracle.com"


def page_html(slug: str, spec: dict[str, Any]) -> str:
    """Advisory page shaped like the real one: h4 risk matrices per product family."""
    csaf_href = spec.get("csaf_href", f"{ORACLE}{CSAF_PREFIX}{slug}csaf.json")
    parts = [
        "<html><head><title>Oracle Critical Patch Update Advisory</title></head><body>",
        "<h1>Oracle Critical Patch Update Advisory</h1>",
        f'<p>This Critical Patch Update is also available as <a href="{csaf_href}">CSAF</a>.</p>',
        "<h3>Risk Matrix Content</h3><p>Risk matrices list only security vulnerabilities.</p>",
    ]
    for heading, cves in spec.get("sections", []):
        anchor = heading.replace(" ", "")
        parts.append(f'<h4 id="Appendix{anchor}">{heading}</h4><table>')
        parts.append("<tr><th>CVE#</th><th>Component</th></tr>")
        for cve in cves:
            parts.append(f"<tr><td>{cve}</td><td>{heading.replace(' Risk Matrix', '')}</td></tr>")
        parts.append("</table>")
    history = spec.get("history")
    if history:
        parts.append(history.get("heading_html", "<h3>Modification History</h3>"))
        parts.append("<table><tr><th>Date</th><th>Note</th></tr>")
        for cve in history.get("cves", []):
            parts.append(f"<tr><td>2026-01-01</td><td>Rev 2. Removed {cve} from a risk matrix.</td></tr>")
        parts.append("</table>")
    parts.append("<h3>Footer</h3><p>Oracle</p></body></html>")
    return "".join(parts)


def csaf_document(spec: dict[str, Any]) -> dict[str, Any]:
    """CSAF document shaped like Oracle's: product_tree and ids[].system_name."""
    vulns = []
    families: dict[str, list[str]] = {}
    for vuln in spec.get("vulns", []):
        product = str(vuln.get("product") or "MySQL Server")
        family = str(vuln.get("family") or ("Oracle MySQL" if "MySQL" in product else f"Oracle {product}"))
        product_id = f"{family}:{product}".replace(" ", "_")
        families.setdefault(family, [])
        if product_id not in families[family]:
            families[family].append(product_id)
        vulns.append(
            {
                "cve": vuln["cve"],
                "ids": [{"system_name": f"Oracle Bug ID of {product}", "text": str(vuln["bug"])}],
                "product_status": {"known_affected": [product_id]},
                "notes": [{"category": "description", "text": f"Vulnerability in {product}."}],
            }
        )
    document: dict[str, Any] = {
        "document": {"category": "csaf_security_advisory", "title": "Oracle Critical Patch Update"},
        "vulnerabilities": vulns,
    }
    if spec.get("product_tree", True):
        document["product_tree"] = {
            "branches": [
                {
                    "category": "vendor",
                    "name": "Oracle",
                    "branches": [
                        {
                            "category": "product_family",
                            "name": family,
                            "branches": [
                                {
                                    "category": "product_name",
                                    "name": product_id.split(":", 1)[1].replace("_", " "),
                                    "product": {"product_id": product_id, "name": product_id},
                                }
                                for product_id in product_ids
                            ],
                        }
                        for family, product_ids in families.items()
                    ],
                }
            ]
        }
    return document


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "MockOracle/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: D401, silence default stderr log
        return

    def _record(self, status: int, bytes_sent: int) -> None:
        self.server.mock.requests.append(  # type: ignore[attr-defined]
            {
                "host": self.server.server_address[0],  # type: ignore[attr-defined]
                "port": self.server.server_address[1],  # type: ignore[attr-defined]
                "path": self.path,
                "status": status,
                "bytes_sent": bytes_sent,
                "t": round(time.monotonic() - self.server.mock.t0, 3),  # type: ignore[attr-defined]
            }
        )

    def _send(self, status: int, body: bytes = b"", headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        self._record(status, len(body))

    def _send_drip(self, status: int, body: bytes, chunk: int, interval: float) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        sent = 0
        self._record(status, 0)
        try:
            while sent < len(body):
                self.wfile.write(body[sent : sent + chunk])
                self.wfile.flush()
                sent += chunk
                self.server.mock.requests[-1]["bytes_sent"] = min(sent, len(body))  # type: ignore[attr-defined]
                time.sleep(interval)
        except (BrokenPipeError, ConnectionResetError):
            self.server.mock.requests[-1]["client_gone"] = True  # type: ignore[attr-defined]

    def _send_padded_json(self, status: int, document: dict[str, Any], pad_mb: int) -> None:
        """Valid JSON whose "pad" string is pad_mb MiB, streamed in 1 MiB chunks."""
        prefix = json.dumps(document)[:-1] + ', "pad": "'
        suffix = '"}'
        pad_total = pad_mb * 1024 * 1024
        total = len(prefix) + pad_total + len(suffix)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(total))
        self.end_headers()
        self._record(status, 0)
        sent = 0
        chunk = b"x" * (1024 * 1024)
        try:
            self.wfile.write(prefix.encode())
            sent += len(prefix)
            remaining = pad_total
            while remaining > 0:
                piece = chunk[: min(len(chunk), remaining)]
                self.wfile.write(piece)
                remaining -= len(piece)
                sent += len(piece)
            self.wfile.write(suffix.encode())
            sent += len(suffix)
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            self.server.mock.requests[-1]["client_gone"] = True  # type: ignore[attr-defined]
        self.server.mock.requests[-1]["bytes_sent"] = sent  # type: ignore[attr-defined]

    def do_GET(self) -> None:  # noqa: N802
        scenario = self.server.mock.scenario  # type: ignore[attr-defined]
        path = self.path.split("?", 1)[0]
        if path in INDEX_PATHS:
            return self._index(scenario.get("index", {}), scenario.get("slugs", []))
        if path.startswith("/security-alerts/") and path.endswith(".html"):
            slug = path[len("/security-alerts/") : -len(".html")]
            spec = scenario.get("pages", {}).get(slug)
            if spec is None:
                return self._send(404, b"no such advisory")
            host = self.server.server_address[0]  # type: ignore[attr-defined]
            if spec.get("redirect") and spec.get("redirect_from_host", host) == host:
                return self._send(301, b"", {"Location": spec["redirect"]})
            body = spec["body"] if spec.get("body") is not None else page_html(slug, spec)
            return self._send(int(spec.get("status", 200)), body.encode())
        if path.startswith(CSAF_PREFIX) and path.endswith("csaf.json"):
            # Oracle answers the documented CSAF URL with a 301 to /a/tech/docs/.
            slug = path[len(CSAF_PREFIX) : -len("csaf.json")]
            return self._send(301, b"", {"Location": f"{ORACLE}{CSAF_FINAL_PREFIX}{slug}csaf.json"})
        if path.startswith(CSAF_FINAL_PREFIX) and path.endswith("csaf.json"):
            slug = path[len(CSAF_FINAL_PREFIX) : -len("csaf.json")]
            return self._csaf(scenario.get("csaf", {}).get(slug))
        evil = scenario.get("evil", {}).get(path)
        if evil is not None:
            return self._csaf(evil)
        return self._send(404, b"not found")

    def _index(self, spec: dict[str, Any], slugs: list[str]) -> None:
        if spec.get("redirect"):
            return self._send(301, b"", {"Location": spec["redirect"]})
        body = spec.get("body")
        if body is None:
            links = "".join(
                f'<li><a href="/security-alerts/{slug}.html">Oracle Critical Patch Update {slug}</a></li>'
                for slug in slugs
            )
            body = f"<html><body><h1>Critical Patch Updates, Security Alerts and Bulletins</h1><ul>{links}</ul></body></html>"
        drip = spec.get("drip")
        if drip:
            return self._send_drip(int(spec.get("status", 200)), body.encode(), int(drip[0]), float(drip[1]))
        return self._send(int(spec.get("status", 200)), body.encode())

    def _csaf(self, spec: dict[str, Any] | None) -> None:
        if spec is None:
            return self._send(404, b"no such csaf")
        if spec.get("redirect"):
            return self._send(301, b"", {"Location": spec["redirect"]})
        if spec.get("body") is not None:
            return self._send(int(spec.get("status", 200)), str(spec["body"]).encode())
        document = csaf_document(spec)
        if spec.get("pad_mb"):
            return self._send_padded_json(int(spec.get("status", 200)), document, int(spec["pad_mb"]))
        return self._send(int(spec.get("status", 200)), json.dumps(document).encode())


class _Server(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class MockOracle:
    def __init__(self, hosts: tuple[str, ...] = ("127.0.0.1",)) -> None:
        self.scenario: dict[str, Any] = {}
        self.requests: list[dict[str, Any]] = []
        self.t0 = time.monotonic()
        self.servers: dict[str, _Server] = {}
        self.threads: list[threading.Thread] = []
        for host in hosts:
            server = _Server((host, 0), _Handler)
            server.mock = self  # type: ignore[attr-defined]
            self.servers[host] = server

    def start(self) -> "MockOracle":
        for server in self.servers.values():
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)
            thread.start()
            self.threads.append(thread)
        return self

    def stop(self) -> None:
        for server in self.servers.values():
            server.shutdown()
            server.server_close()

    def base(self, host: str = "127.0.0.1") -> str:
        address = self.servers[host].server_address
        return f"http://{address[0]}:{address[1]}"

    def hits(self, host: str | None = None) -> list[dict[str, Any]]:
        if host is None:
            return list(self.requests)
        return [req for req in self.requests if req["host"] == host]
