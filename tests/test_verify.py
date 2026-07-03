"""Fidelity-harness tests.

HTTP uses a genuinely independent oracle (stdlib http.server) so a match cannot be an
artifact of diffing our facade against itself. LDAP has no stdlib server to stand up, so it
serves a known ldap facade as the target and verifies the capture->replay round-trip is
lossless (the cross-software LDAP oracle is the manual OpenLDAP/Samba demo).
"""

import functools
import http.server
import threading

from rangefinder.verify import _ServedFacade, verify_dns, verify_http, verify_ldap, verify_smb


def _serve_dir(directory):
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(directory))
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1]


def test_verify_http_faithful(tmp_path):
    root = tmp_path / "web"
    (root / ".git").mkdir(parents=True)
    (root / "index.html").write_text("<html><body>Acme home</body></html>")
    (root / "robots.txt").write_text("User-agent: *\nDisallow: /admin\n")
    (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (root / "backup.sql").write_text("INSERT INTO users VALUES('admin','S3cret!');\n")

    httpd, port = _serve_dir(root)
    try:
        report = verify_http(f"http://127.0.0.1:{port}", max_paths=60)
    finally:
        httpd.shutdown()

    # captured at least the home page, the exposed .git file and the leaked backup
    assert report.total >= 3, report.warnings
    assert report.matched == report.total, [(d.key, d.kind, d.detail) for d in report.divergences]
    assert report.score == 1.0
    # detection perspective: every probed route produced telemetry, no blind spots
    assert report.telemetry_events >= report.total
    assert report.blind_spots == []
    assert report.ok


def test_diff_http_has_teeth():
    """The diff engine must flag status, body and header divergences, not rubber-stamp."""
    from rangefinder.capture.http import _KEEP_HEADERS, _Resp
    from rangefinder.verify import _diff_http

    cmp = _KEEP_HEADERS | {"server"}
    real = _Resp(200, {"content-type": "text/html", "server": "nginx"}, b"hello")

    assert _diff_http("/", real, real, cmp) == []  # identical -> faithful
    kinds = lambda a, b: {d.kind for d in _diff_http("/x", a, b, cmp)}
    assert "status" in kinds(real, _Resp(404, real.headers, real.body))
    assert "body" in kinds(real, _Resp(200, real.headers, b"different"))
    assert "headers" in kinds(real, _Resp(200, {"content-type": "text/plain", "server": "nginx"}, real.body))
    assert "missing" in kinds(real, None)


def test_verify_ldap_round_trip():
    service = {
        "type": "ldap", "port": 389, "base_dn": "dc=acme,dc=corp",
        "allow_anonymous_bind": True,
        "entries": [
            {"dn": "", "attributes": {"namingContexts": ["dc=acme,dc=corp"],
                                      "objectClass": ["top"]}},
            {"dn": "dc=acme,dc=corp", "attributes": {"objectClass": ["domain"], "dc": ["acme"]}},
            {"dn": "cn=svc-web,dc=acme,dc=corp",
             "attributes": {"objectClass": ["user"], "cn": ["svc-web"],
                            "description": ["set password to Autumn2025!"]}},
        ],
    }
    with _ServedFacade(service) as srv:
        report = verify_ldap("127.0.0.1", srv.port)

    assert report.total >= 2, report.warnings
    assert report.matched == report.total, [(d.key, d.kind, d.detail) for d in report.divergences]
    assert report.score == 1.0
    assert any("anonymous" in b for b in report.boundary)


def test_verify_smb_round_trip():
    service = {
        "type": "smb", "port": 445, "server_os": "Windows Server 2022",
        "shares": [
            {"name": "public", "comment": "", "readonly": True,
             "files": {"readme.txt": "hello from the share\n",
                       "creds/db.conf": "db.password=Autumn2025!\n"}},
        ],
    }
    with _ServedFacade(service) as srv:
        report = verify_smb("127.0.0.1", srv.port)

    assert report.total == 1, report.warnings
    assert report.matched == report.total, [(d.key, d.kind, d.detail) for d in report.divergences]
    assert any("null-session" in b for b in report.boundary)


def test_verify_dns_round_trip():
    service = {
        "type": "dns", "port": 53, "zone": "acme.corp", "autofill_hosts": False,
        "records": [
            {"name": "acme.corp", "type": "A", "value": "10.20.0.10", "ttl": 300},
            {"name": "dc01.acme.corp", "type": "A", "value": "10.20.0.10", "ttl": 300},
            {"name": "acme.corp", "type": "MX", "value": "10 mail.acme.corp", "ttl": 300},
            {"name": "_ldap._tcp.acme.corp", "type": "SRV",
             "value": "0 100 389 dc01.acme.corp", "ttl": 300},
            {"name": "acme.corp", "type": "TXT", "value": "v=spf1 -all", "ttl": 300},
        ],
    }
    with _ServedFacade(service) as srv:
        report = verify_dns("127.0.0.1", srv.port, zone="acme.corp")

    assert report.total >= 4, report.warnings
    assert report.matched == report.total, [(d.key, d.kind, d.detail) for d in report.divergences]
    assert report.telemetry_events >= report.total  # every query logged a dns_query event


def test_diff_files_has_teeth():
    from rangefinder.verify import _diff_files

    assert _diff_files({"a": "1"}, {"a": "1"}) == ""
    assert "~a" in _diff_files({"a": "1"}, {"a": "2"})   # changed content
    assert "-a" in _diff_files({"a": "1"}, {})           # missing on replica
    assert "+b" in _diff_files({}, {"b": "1"})           # extra on replica


def test_parse_nmap_service():
    from rangefinder.verify import _parse_nmap_service

    xml = (b'<?xml version="1.0"?><nmaprun><host><ports>'
           b'<port protocol="tcp" portid="80"><state state="open"/>'
           b'<service name="http" product="nginx" version="1.31.2" method="probed"/>'
           b'</port></ports></host></nmaprun>')
    assert _parse_nmap_service(xml) == "http nginx 1.31.2"
    assert _parse_nmap_service(b"not xml at all") is None
    assert _parse_nmap_service(b"<nmaprun></nmaprun>") is None


def test_verify_http_nmap_skips_gracefully(tmp_path):
    import shutil

    if shutil.which("nmap") is not None:
        return  # only asserting the graceful-skip path, which needs nmap absent
    root = tmp_path / "web"
    root.mkdir()
    (root / "index.html").write_text("<html>home</html>")
    httpd, port = _serve_dir(root)
    try:
        report = verify_http(f"http://127.0.0.1:{port}", max_paths=40, nmap=True)
    finally:
        httpd.shutdown()
    assert any("nmap" in b for b in report.boundary)
    assert not any(d.kind == "fingerprint" for d in report.divergences)
    assert report.ok  # skipped check must not fail the run
