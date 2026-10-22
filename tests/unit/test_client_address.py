import unittest

from sentinelapi.client_address import ClientResolver
from sentinelapi.detectors.fingerprint import network_key

PROXY = "10.0.0.5"


class TestClientResolver(unittest.TestCase):
    def setUp(self) -> None:
        self.behind_proxy = ClientResolver(["10.0.0.0/24"])

    def test_without_trusted_proxies_the_header_is_ignored(self) -> None:
        self.assertEqual(ClientResolver().address("198.51.100.7", "203.0.113.9"), "198.51.100.7")

    def test_a_trusted_proxy_passes_the_client_on(self) -> None:
        self.assertEqual(self.behind_proxy.address(PROXY, "203.0.113.9"), "203.0.113.9")

    def test_an_untrusted_peer_cannot_choose_its_address(self) -> None:
        self.assertEqual(self.behind_proxy.address("198.51.100.7", "203.0.113.9"), "198.51.100.7")

    def test_hops_the_client_wrote_are_ignored(self) -> None:
        # The client sent "1.2.3.4"; the proxy appended the address it saw.
        self.assertEqual(self.behind_proxy.address(PROXY, "1.2.3.4, 203.0.113.9"), "203.0.113.9")

    def test_a_chain_of_trusted_proxies_is_walked(self) -> None:
        self.assertEqual(self.behind_proxy.address(PROXY, "203.0.113.9, 10.0.0.7"), "203.0.113.9")

    def test_ports_and_brackets_are_understood(self) -> None:
        self.assertEqual(self.behind_proxy.address(PROXY, "203.0.113.9:4711"), "203.0.113.9")
        self.assertEqual(self.behind_proxy.address(PROXY, "[2001:db8::1]:443"), "2001:db8::1")

    def test_garbage_falls_back_to_the_peer(self) -> None:
        self.assertEqual(self.behind_proxy.address(PROXY, "not-an-address"), PROXY)
        self.assertEqual(self.behind_proxy.address(PROXY, ""), PROXY)
        self.assertEqual(self.behind_proxy.address(PROXY, None), PROXY)

    def test_a_missing_peer_is_unknown(self) -> None:
        self.assertEqual(self.behind_proxy.address(None, "203.0.113.9"), "unknown")

    def test_bad_networks_are_refused(self) -> None:
        with self.assertRaises(ValueError):
            ClientResolver(["10.0.0.0/33"])


class TestNetworkKey(unittest.TestCase):
    def test_ipv4_is_the_address(self) -> None:
        self.assertEqual(network_key("203.0.113.9"), "203.0.113.9")

    def test_ipv6_is_grouped_by_64(self) -> None:
        self.assertEqual(network_key("2001:db8:1:2:aaaa::1"), network_key("2001:db8:1:2:bbbb::2"))
        self.assertNotEqual(network_key("2001:db8:1:2::1"), network_key("2001:db8:1:3::1"))

    def test_ipv4_mapped_ipv6_is_the_ipv4_address(self) -> None:
        self.assertEqual(network_key("::ffff:203.0.113.9"), "203.0.113.9")

    def test_anything_else_is_kept_as_is(self) -> None:
        self.assertEqual(network_key("unknown"), "unknown")


if __name__ == "__main__":
    unittest.main()
