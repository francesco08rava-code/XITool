"""DNS UDP reale controllato: nessun resolver pubblico richiesto."""
import socketserver
import threading
import unittest
from unittest.mock import Mock, patch
import dns.message
import dns.rcode
import dns.resolver
import dns.rrset
from xitool.dns import DNSResolver
from xitool.scope import Scope


class LocalDNSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.queries = []
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                packet, stream = self.request
                query = dns.message.from_wire(packet)
                question = query.question[0]
                host = str(question.name)
                cls.queries.append(host)
                response = dns.message.make_response(query)
                if host.startswith("missing."):
                    response.set_rcode(dns.rcode.NXDOMAIN)
                elif host.startswith("broken."):
                    response.set_rcode(dns.rcode.SERVFAIL)
                else:
                    kind = dns.rdatatype.to_text(question.rdtype)
                    value = {"A": "8.8.8.8", "AAAA": "2001:4860:4860::8888", "CNAME": "www.example.com."}.get(kind)
                    if value:
                        response.answer.append(dns.rrset.from_text(host, 30, "IN", kind, value))
                stream.sendto(response.to_wire(), self.client_address)
        cls.server = socketserver.UDPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        self.__class__.queries = []
        wire = dns.resolver.Resolver(configure=False)
        wire.nameservers = ["127.0.0.1"]
        wire.port = self.server.server_address[1]
        self.factory = patch("dns.resolver.Resolver", return_value=wire)
        self.factory.start()
        self.addCleanup(self.factory.stop)
        self.resolver = DNSResolver(Scope(["example.com", "*.example.com"], []), .5, Mock())

    def test_real_a_aaaa_cname_and_ttl_cache(self):
        result = self.resolver.resolve("example.com")
        self.assertTrue(result["resolved"])
        self.assertEqual(result["A"], ["8.8.8.8"])
        self.assertTrue(result["AAAA"])
        self.assertEqual(result["CNAME"], ["www.example.com"])
        count = len(self.queries)
        self.assertEqual(self.resolver.resolve("example.com"), result)
        self.assertEqual(len(self.queries), count)
        self.assertEqual(result["ttl_seconds"], 30)

    def test_real_nxdomain_is_not_a_transport_failure(self):
        self.assertEqual(self.resolver.resolve("missing.example.com")["resolution_status"], "NOT_FOUND")

    def test_real_servfail_is_not_nonexistent_domain(self):
        result = self.resolver.resolve("broken.example.com")
        self.assertEqual(result["resolution_status"], "RESOLVER_ERROR")
        self.assertIn("A:SERVFAIL", result["errors"])

    def test_real_dns_wildcard_is_observed(self):
        self.assertTrue(self.resolver.wildcard("example.com")["possible_wildcard"])
