import hashlib
import unittest

from sentinelapi.privacy import Pseudonymizer


class TestPseudonymizer(unittest.TestCase):
    def test_the_same_value_always_gets_the_same_hash(self) -> None:
        pseudonymize = Pseudonymizer("key")
        self.assertEqual(pseudonymize("203.0.113.7"), pseudonymize("203.0.113.7"))
        self.assertNotEqual(pseudonymize("203.0.113.7"), pseudonymize("203.0.113.8"))

    def test_the_hash_depends_on_the_key(self) -> None:
        self.assertNotEqual(Pseudonymizer("one")("203.0.113.7"), Pseudonymizer("two")("203.0.113.7"))

    def test_it_is_not_a_plain_sha256_anyone_could_recompute(self) -> None:
        plain = hashlib.sha256(b"203.0.113.7").hexdigest()[:32]
        self.assertNotEqual(Pseudonymizer("key")("203.0.113.7"), plain)

    def test_nothing_stays_nothing(self) -> None:
        self.assertIsNone(Pseudonymizer("key")(None))

    def test_without_a_key_it_is_random_per_process(self) -> None:
        first, second = Pseudonymizer(None), Pseudonymizer(None)
        self.assertTrue(first.ephemeral)
        self.assertNotEqual(first("203.0.113.7"), second("203.0.113.7"))
        self.assertFalse(Pseudonymizer("key").ephemeral)


if __name__ == "__main__":
    unittest.main()
