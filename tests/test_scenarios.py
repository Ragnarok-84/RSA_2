# Tệp: tests/test_scenarios.py   [bổ sung - Báo cáo 4.7, 6.5: mọi kịch bản phải cho kết quả đúng kỳ vọng]
import glob
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scenarios.s1_authentication import run_scenario_s1
from scenarios.s2_nonrepudiation import run_scenario_s2
from scenarios.s3_revocation import run_scenario_s3
from scenarios.s4_replay import run_scenario_s4
from scenarios.s5_key_substitution import run_scenario_s5
from scenarios.s6_confidentiality import run_scenario_s6
from demo import avalanche

REAL = os.environ.get("REAL") == "1"
KEYSIZE = 2048 if REAL else 512
OAEP_KEYSIZE = max(KEYSIZE, 1024)


class TestScenarios(unittest.TestCase):
    def test_s1_authentication(self):
        self.assertTrue(run_scenario_s1(keysize=KEYSIZE, verbose=False))

    def test_s2_nonrepudiation(self):
        self.assertTrue(run_scenario_s2(keysize=KEYSIZE, verbose=False))

    def test_s3_revocation(self):
        self.assertTrue(run_scenario_s3(keysize=KEYSIZE, verbose=False))

    def test_s4_replay(self):
        self.assertTrue(run_scenario_s4(keysize=KEYSIZE, verbose=False))

    def test_s5_key_substitution(self):
        self.assertTrue(run_scenario_s5(keysize=KEYSIZE, verbose=False))

    def test_s6_confidentiality(self):
        self.assertTrue(run_scenario_s6(keysize=OAEP_KEYSIZE, verbose=False))

    def test_avalanche(self):
        r = avalanche.run_demo(verbose=False, keysize=KEYSIZE)
        self.assertGreater(r["bit_diff"], 64)
        self.assertAlmostEqual(r["avg_ratio"], 0.5, delta=0.05)
        self.assertTrue(r["swap_undetected"])
        self.assertTrue(r["hash_detects_swap"])

    def test_x509_reference(self):
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("chưa cài cryptography (bản đối chiếu X.509)")
        import contextlib
        import io
        sys.path.insert(0, os.path.join(ROOT, "tests"))
        import doi_chieu_x509
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(doi_chieu_x509.main(["--bits", str(KEYSIZE if REAL else 1024)]), 0)


class TestNoForbiddenLibraries(unittest.TestCase):
    """Đề yêu cầu tự cài phần lõi: core/, pki/, attacks/, scenarios/, demo/ không import thư viện mật mã có sẵn."""
    FORBIDDEN = re.compile(r"^\s*(import|from)\s+(hashlib|hmac|cryptography|Crypto|Cryptodome|ssl|OpenSSL)\b")

    def test_core_files_clean(self):
        files = []
        for folder in ("core", "pki", "attacks", "scenarios", "demo"):
            files += glob.glob(os.path.join(ROOT, folder, "*.py"))
        self.assertGreater(len(files), 20)
        for path in files:
            with open(path, encoding="utf-8") as f:
                for n, line in enumerate(f, 1):
                    self.assertIsNone(self.FORBIDDEN.match(line), f"{os.path.relpath(path, ROOT)}:{n} '{line.strip()}'")

    def test_checker_catches_violations(self):
        self.assertIsNotNone(self.FORBIDDEN.match("import hashlib"))
        self.assertIsNotNone(self.FORBIDDEN.match("from cryptography.hazmat import x"))
        self.assertIsNone(self.FORBIDDEN.match("from core.hmac_utils import generate_hmac"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
