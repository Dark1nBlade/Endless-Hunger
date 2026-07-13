import unittest
import socket
import json
import csv
import os
from unittest.mock import patch, MagicMock
import kshield

class TestKShield(unittest.TestCase):
    def test_parse_targets_simple(self):
        targets = kshield.parse_targets("127.0.0.1, localhost")
        self.assertIn("127.0.0.1", targets)
        self.assertIn("localhost", targets)

    def test_parse_targets_cidr(self):
        targets = kshield.parse_targets("192.168.1.0/30")
        # Subnet 192.168.1.0/30 has host IPs: 192.168.1.1 and 192.168.1.2
        self.assertIn("192.168.1.1", targets)
        self.assertIn("192.168.1.2", targets)
        self.assertEqual(len(targets), 2)

    def test_map_to_mitre_empty(self):
        findings = {}
        mapped = kshield.map_to_mitre(findings)
        self.assertEqual(mapped["mapped_techniques"], [])
        self.assertEqual(mapped["risk_priority_matrix"], {})

    def test_map_to_mitre_with_findings(self):
        findings = {
            "127.0.0.1": [
                {
                    "port": 22,
                    "service": "SSH",
                    "state": "open",
                    "banner": "SSH-2.0-OpenSSH",
                    "ssl_analysis": None,
                    "http_probing": None
                }
            ]
        }
        mapped = kshield.map_to_mitre(findings)
        tech_ids = [t["id"] for t in mapped["mapped_techniques"]]
        self.assertIn("T1021.004", tech_ids)
        self.assertIn("T1110", tech_ids)

        # Verify priority scoring
        self.assertIn("Credential Access", mapped["risk_priority_matrix"])
        self.assertIn("Lateral Movement", mapped["risk_priority_matrix"])

    @patch('subprocess.run')
    def test_validate_local_policies(self, mock_run):
        # Mock subprocess.run output to emulate a secure host
        mock_run.return_value = MagicMock(returncode=0, stdout="Active rules loaded", stderr="")

        results = kshield.validate_local_policies()
        # Verify results structures are present
        self.assertIn("firewall_status", results)
        self.assertIn("defense_services", results)
        self.assertIn("audit_trails", results)
        self.assertIsInstance(results["policy_score"], float)

if __name__ == "__main__":
    unittest.main()
