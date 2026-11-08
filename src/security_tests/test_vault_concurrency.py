"""Deterministic KV v2 races using independent worker clients; no network/secrets."""
import copy
import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock

import hvac
from django.test import SimpleTestCase
from crypto_access.services.vault_service import VaultService


class VersionedKV:
    def __init__(self):
        self.data = {'existing': 'fixture'}
        self.version = 1
        self.lock = threading.Lock()
        self.barrier = threading.Barrier(2)
        self.reads = 0

    def read_secret_version(self, **kwargs):
        with self.lock:
            result = {'data': {'data': copy.deepcopy(self.data), 'metadata': {'version': self.version}}}
            self.reads += 1
            synchronize = self.reads <= 2
        if synchronize:
            self.barrier.wait(timeout=5)
        return result

    def create_or_update_secret(self, path, secret, cas=None):
        with self.lock:
            if cas is not None and cas != self.version:
                raise hvac.exceptions.InvalidRequest('check-and-set parameter did not match the current version')
            self.data = copy.deepcopy(secret)
            self.version += 1


def worker(kv):
    service = object.__new__(VaultService)
    service.client = Mock()
    service.client.is_authenticated.return_value = True
    service.client.secrets.kv.v2 = kv
    service.secret_path = 'secret/data/isolated'
    service.vault_addr = 'https://vault.test'
    service._cache = {}
    return service


class VaultConcurrencyTests(SimpleTestCase):
    def test_concurrent_writes_keep_both_updates(self):
        kv = VersionedKV()
        with ThreadPoolExecutor(2) as pool:
            futures = [pool.submit(worker(kv).put_secret, name, 'fixture') for name in ('a', 'b')]
            self.assertTrue(all(f.result(timeout=10) for f in futures))
        self.assertEqual(kv.data, {'existing': 'fixture', 'a': 'fixture', 'b': 'fixture'})

    def test_only_one_worker_can_claim_initialization(self):
        kv = VersionedKV()
        with ThreadPoolExecutor(2) as pool:
            futures = [pool.submit(worker(kv).claim_secret, 'guard', 'fixture') for _ in range(2)]
            self.assertEqual(sorted(f.result(timeout=10) for f in futures), [False, True])

    def test_batch_commit_contains_all_fields_in_one_revision(self):
        kv = VersionedKV()
        kv.reads = 2
        self.assertTrue(worker(kv).put_secrets({'pk': 'fixture', 'manifest': 'fixture', 'guard': 'initialized'}))
        self.assertEqual(kv.version, 2)
        self.assertEqual(set(kv.data), {'existing', 'pk', 'manifest', 'guard'})

    def test_covercrypt_read_bypasses_worker_cache(self):
        kv = VersionedKV()
        kv.reads = 2
        key = 'CPABE_PK_COVERCRYPT'
        kv.data[key] = 'current'
        service = worker(kv)
        service._cache[key] = 'stale'
        self.assertEqual(service.get_secret(key), 'current')

    def test_covercrypt_read_outage_is_not_absent_state(self):
        service = worker(VersionedKV())
        service.client.is_authenticated.return_value = False
        with self.assertRaises(RuntimeError):
            service.get_secrets(['COVERCRYPT_KEYSET_MANIFEST_primary'])

    def test_deleted_record_is_never_recreated_as_empty(self):
        kv = VersionedKV()
        kv.read_secret_version = Mock(return_value={'data': {'data': None, 'metadata': {'version': 4}}})
        self.assertFalse(worker(kv).put_secret('new', 'fixture'))
        self.assertEqual(kv.version, 1)

    def test_conflict_retries_are_bounded(self):
        kv = VersionedKV()
        kv.reads = 2
        kv.create_or_update_secret = Mock(side_effect=hvac.exceptions.InvalidRequest(
            'check-and-set parameter did not match the current version'))
        self.assertFalse(worker(kv).put_secret('new', 'fixture'))
        self.assertLessEqual(kv.create_or_update_secret.call_count, 8)
