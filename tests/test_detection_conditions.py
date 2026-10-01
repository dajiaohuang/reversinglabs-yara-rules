"""Synthetic rule regressions; run with Python and yara-python installed.

Fixtures are inert byte buffers, never executable files or malware samples.
"""

from pathlib import Path
import codecs
import re
import unittest

import yara


ROOT = Path(__file__).resolve().parents[1]
CASES = {
    "ransomware/Win32.Ransomware.DMALocker.yara": [
        ["dmalock_v1_encrypt_files_1", "dmalock_v1_encrypt_files_2", "dmalock_v1_encrypt_files_3", "dmalock_v1_enum_shares_and_discs_type_1"],
        ["dmalock_v1_encrypt_files_1", "dmalock_v1_encrypt_files_2", "dmalock_v1_encrypt_files_3", "dmalock_v1_enum_shares_and_discs_type_2"],
        ["dmalock_v1_encrypt_files_1", "dmalock_v1_encrypt_files_2", "dmalock_v1_encrypt_files_3", "dmalock_v1_enum_shares_and_discs_type_3"],
        ["dmalock_v1_encrypt_files_1", "dmalock_v1_encrypt_files_3", "dmalock_v1_enum_shares_and_discs_type_1", "dmalock_v2_enum_logical_disks"],
        ["dmalock_v4_encrypt_file_1", "dmalock_v4_encrypt_file_2", "dmalock_v4_remote_server_communication", "dmalock_v2_enum_logical_disks"],
    ],
    "ransomware/Win32.Ransomware.FenixLocker.yara": [
        ["encrypt_files_1", "encrypt_files_2", "encrypt_files_3"],
        ["encrypt_files_1", "encrypt_files_4", "encrypt_files_5"],
    ],
    "ransomware/Win32.Ransomware.Xorist.yara": [
        ["extract_rsrc_v1", "search_and_encrypt_v1_p1", "search_and_encrypt_v1_p2", "search_and_encrypt_v1_p3"],
        ["extract_rsrc_v2", "search_and_encrypt_v2_p1", "search_and_encrypt_v2_p2"],
    ],
    "trojan/Win32.Trojan.Emotet.yara": [
        ["decrypt_resource_v1", "generate_filename_v1"],
        ["decrypt_resource_v2", "generate_filename_v2"],
        ["decrypt_resource_v3", "generate_filename_v3"],
        ["decrypt_resource_v4", "generate_filename_snippet_v4"],
        ["decrypt_resource_snippet_v5", "liblzf_decompression_1", "liblzf_decompression_2"],
        ["decrypt_resource_snippet_v6", "liblzf_decompression_1", "liblzf_decompression_2"],
        ["decrypt_resource_snippet_v7", "state_machine_snippet_v7"],
    ],
}


def instantiate(pattern):
    """Fill wildcards with zero and bounded jumps with their minimum length."""
    data = bytearray()
    for token in pattern.split():
        if re.fullmatch(r"[0-9A-Fa-f?]{2}", token):
            data.append(int(token.replace("?", "0"), 16))
        elif re.fullmatch(r"\[\d+(?:-\d+)?\]", token):
            data.extend(bytes(int(token[1:-1].split("-")[0])))
        else:
            raise ValueError("Unsupported fixture token: " + token)
    return bytes(data)


class DetectionConditions(unittest.TestCase):
    def test_all_variant_branches_require_mz(self):
        for filename, branches in CASES.items():
            source = (ROOT / "yara" / filename).read_text()
            patterns = dict(re.findall(r"\$(\w+)\s*=\s*\{([^}]+)\}", source))
            rules = yara.compile(source=source)
            for index, identifiers in enumerate(branches):
                with self.subTest(filename=filename, branch=index + 1):
                    payload = b"\x00" * 32
                    payload += (b"\x00" * 32).join(instantiate(patterns[name]) for name in identifiers)
                    self.assertTrue(rules.match(data=b"MZ" + payload))
                    self.assertFalse(rules.match(data=b"ZZ" + payload))
            self.assertFalse(rules.match(data=b"MZ" + bytes(64)))

    def test_certificate_subject_hex_escapes_match_utf8(self):
        source = (ROOT / "yara/certificate/blocklist.yara").read_text()
        subjects = re.findall(r'pe\.signatures\[i\]\.subject contains "([^"\n]+)"', source)
        encoded = [s for s in subjects if "\\x" in s]
        self.assertEqual(len(encoded), 40)
        for subject in encoded:
            with self.subTest(subject=subject):
                self.assertNotIn("\\\\x", subject)
                decoded = codecs.escape_decode(subject.encode("ascii"))[0]
                decoded.decode("utf-8")
                rules = yara.compile(source='rule subject { strings: $subject = "' + subject + '" condition: $subject }')
                self.assertTrue(rules.match(data=decoded))
                self.assertFalse(rules.match(data=subject.encode("ascii")))


if __name__ == "__main__":
    unittest.main()
