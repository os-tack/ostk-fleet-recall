"""Renewal must change only the leaf and extend its usable lifetime."""
import importlib.util
import time
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("renewal", Path(__file__).parents[1] / "bin/renew-https-certificate.py")
RENEWAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RENEWAL)


class RenewalTests(unittest.TestCase):
    def test_stale_certificate_key_or_expiry_cannot_pass(self):
        before = {"sha256": "old-leaf", "public_key_sha256": "old-key", "expires_at": time.time() + 80 * 86400}
        after = {"sha256": "new-leaf", "public_key_sha256": "new-key", "expires_at": time.time() + 90 * 86400}
        RENEWAL.validate_renewal(before, after)
        for patch in ({"sha256": before["sha256"]}, {"public_key_sha256": before["public_key_sha256"]},
                      {"expires_at": before["expires_at"]}, {"expires_at": time.time() + 86400}):
            with self.subTest(patch=patch), self.assertRaises(RuntimeError):
                RENEWAL.validate_renewal(before, dict(after, **patch))


if __name__ == "__main__":
    unittest.main()
