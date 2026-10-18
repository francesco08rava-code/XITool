"""CT deterministic fixtures → real UDP DNS → real HTTP on the integrated app."""
import json
import socket
import socketserver
import threading
from urllib.parse import urlsplit
from unittest.mock import patch
import dns.message
import dns.rcode
import dns.resolver
import dns.rrset

from xitool.execution import Engine
from xitool.http import HTTPClient, Response


def exercise(project, scope, config, lab):
    questions = []
    class DNS(socketserver.BaseRequestHandler):
        def handle(self):
            packet, stream = self.request
            query = dns.message.from_wire(packet)
            question = query.question[0]
            host = str(question.name).rstrip(".")
            questions.append(host)
            response = dns.message.make_response(query)
            if host == "missing.lab.test":
                response.set_rcode(dns.rcode.NXDOMAIN)
            elif host.endswith("lab.test") and question.rdtype == 1:
                response.answer.append(dns.rrset.from_text(str(question.name), 2, "IN", "A", "127.0.0.1"))
            elif host == "new.lab.test" and question.rdtype == 5:
                response.answer.append(dns.rrset.from_text(str(question.name), 2, "IN", "CNAME", "alias.outside.invalid."))
            stream.sendto(response.to_wire(), self.client_address)
    server = socketserver.UDPServer(("127.0.0.1", 0), DNS)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["127.0.0.1"]
    resolver.port = server.server_address[1]
    request, addresses = HTTPClient._request, socket.getaddrinfo
    def transport(client, url, headers):
        host = urlsplit(url).hostname
        if host == "crt.sh":
            data = [{"name_value": "lab.test\nnew.lab.test\nnew.lab.test\nmissing.lab.test\n*.lab.test\noutside.invalid"}]
            return Response(url, 200, {"content-type": "application/json"}, json.dumps(data))
        if host == "api.certspotter.com":
            return Response(url, 500, {}, "provider unavailable")
        return request(client, url, headers)
    def local_addresses(host, port, *args, **kwargs):
        return addresses("127.0.0.1" if host == "lab.test" or host.endswith(".lab.test") else host, port, *args, **kwargs)
    try:
        with patch("dns.resolver.Resolver", return_value=resolver), patch.object(HTTPClient, "_request", transport), patch("socket.getaddrinfo", local_addresses):
            sources = Engine(project, scope, config, "subfinding", target="lab.test", tasks=[
                {"url": "https://lab.test/", "kind": "passive", "provider": name} for name in ("crtsh", "certspotter")])
            sources.execute()
            hosts = [host for host, row in sources.state["dns_records"].items() if row["resolved"]]
            assert "new.lab.test" in hosts and "missing.lab.test" not in hosts
            urls = [{"url": f"http://{host}:{lab.server.server_port}/"} for host in hosts]
            # URLs derive from actual provider/DNS results, with an explicit lab port.
            probes = Engine(project, scope, config, "subfinding", target="lab.test", tasks=urls)
            probes.execute()
            assert "new.lab.test" in probes.state["live_hosts"]
            assert "outside.invalid" not in questions and "alias.outside.invalid" not in questions
            assert "new.lab.test" in questions
            return {"provider_fixture_results": sources.state["provider_metadata"], "dns_udp_queries": len(questions),
                    "discovered": hosts, "reached": probes.state["live_hosts"], "outside_queried": False,
                    "missing_dns_status": sources.state["dns_records"]["missing.lab.test"]["resolution_status"]}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
