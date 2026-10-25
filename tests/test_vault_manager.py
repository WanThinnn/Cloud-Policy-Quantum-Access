"""Isolated Vault lifecycle regressions; no real keys, Docker or network needed.

Run: python -m unittest discover -s tests -p test_vault_manager.py -v
"""

import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


class VaultDown(Exception):
    pass


class InternalServerError(Exception):
    pass


fake_hvac = SimpleNamespace(
    exceptions=SimpleNamespace(VaultDown=VaultDown, InternalServerError=InternalServerError)
)
spec = importlib.util.spec_from_file_location(
    "vault_manager_under_test", Path(__file__).resolve().parents[1] / "scripts" / "vault_manager.py"
)
manager = importlib.util.module_from_spec(spec)
with patch.dict("sys.modules", {"hvac": fake_hvac}):
    spec.loader.exec_module(manager)


class VaultManagerTests(unittest.TestCase):
    def test_partial_shares_raise_instead_of_reporting_success(self):
        client = Mock()
        client.sys.is_sealed.return_value = True
        client.sys.submit_unseal_key.return_value = {"sealed": True}
        client.sys.read_seal_status.return_value = {"sealed": True, "progress": 1, "t": 3}
        with self.assertRaisesRegex(RuntimeError, "1/3"):
            manager.unseal_with_keys(client, ["test-share"])

    def test_duplicate_shares_are_not_resubmitted(self):
        client = Mock()
        client.sys.is_sealed.return_value = True
        client.sys.submit_unseal_key.return_value = {"sealed": True}
        client.sys.read_seal_status.return_value = {"sealed": True, "progress": 1, "t": 3}
        with self.assertRaises(RuntimeError):
            manager.unseal_with_keys(client, ["test-share", "test-share"])
        client.sys.submit_unseal_key.assert_called_once_with("test-share")

    def test_confirmed_unseal_stops_submitting_shares(self):
        client = Mock()
        client.sys.is_sealed.return_value = True
        client.sys.submit_unseal_key.return_value = {"sealed": False}
        client.sys.read_seal_status.return_value = {"sealed": False}
        manager.unseal_with_keys(client, ["test-share", "unused-share"])
        client.sys.submit_unseal_key.assert_called_once_with("test-share")

    def test_already_unsealed_does_not_submit_keys(self):
        client = Mock()
        client.sys.is_sealed.return_value = False
        client.sys.read_seal_status.return_value = {"sealed": False}
        manager.unseal_with_keys(client, ["test-share"])
        client.sys.submit_unseal_key.assert_not_called()

    def test_active_wait_rejects_sealed_vault(self):
        client = Mock()
        client.sys.is_sealed.return_value = True
        with self.assertRaisesRegex(RuntimeError, "sealed"):
            manager.wait_for_active_vault(client)
        client.sys.list_mounted_secrets_engines.assert_not_called()

    def test_active_wait_retries_leader_election(self):
        client = Mock()
        client.sys.is_sealed.return_value = False
        client.sys.list_mounted_secrets_engines.side_effect = [VaultDown(), {"secret/": {}}]
        with patch.object(manager.time, "sleep"):
            manager.wait_for_active_vault(client, attempts=2)
        self.assertEqual(client.sys.list_mounted_secrets_engines.call_count, 2)

    def test_active_wait_timeout_fails(self):
        client = Mock()
        client.sys.is_sealed.return_value = False
        client.sys.list_mounted_secrets_engines.side_effect = VaultDown()
        with patch.object(manager.time, "sleep"), self.assertRaisesRegex(RuntimeError, "ready"):
            manager.wait_for_active_vault(client, attempts=2)

    def test_kv_setup_failure_propagates(self):
        client = Mock()
        client.sys.list_mounted_secrets_engines.side_effect = RuntimeError("denied")
        with self.assertRaisesRegex(RuntimeError, "KV v2"):
            manager.ensure_kv_engine(client)

    def test_kv_retry_accepts_existing_mount(self):
        client = Mock()
        client.sys.list_mounted_secrets_engines.side_effect = [
            RuntimeError("local node not active"), {"secret/": {}}
        ]
        with patch.object(manager.time, "sleep"):
            manager.ensure_kv_engine(client)
        client.sys.enable_secrets_engine.assert_not_called()


if __name__ == "__main__":
    unittest.main()
