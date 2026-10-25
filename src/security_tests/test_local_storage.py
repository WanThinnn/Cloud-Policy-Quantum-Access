from pathlib import Path
import tempfile

from django.test import SimpleTestCase, override_settings

from crypto_access.services.storage.adapters.local import LocalStorageAdapter


class LocalStoragePathTests(SimpleTestCase):
    def setUp(self):
        self.sandbox = tempfile.TemporaryDirectory(prefix='local-storage-regression-')
        self.addCleanup(self.sandbox.cleanup)
        self.root = Path(self.sandbox.name) / 'media'
        self.override = override_settings(MEDIA_ROOT=self.root)
        self.override.enable()
        self.addCleanup(self.override.disable)
        self.storage = LocalStorageAdapter()
        self.storage.create_bucket('documents')
        self.storage.create_bucket('other')
        self.outside = Path(self.sandbox.name) / 'outside.txt'
        self.outside.write_bytes(b'outside original')

    def test_valid_nested_file_lifecycle(self):
        self.storage.upload_file('documents', 'team/report.txt', b'original')
        self.assertEqual(self.storage.download_file('documents', 'team/report.txt'), b'original')
        self.storage.copy_file('documents', 'team/report.txt', 'copies/report.txt')
        self.storage.move_file('documents', 'copies/report.txt', 'moved/report.txt')
        self.assertEqual(self.storage.download_file('documents', 'moved/report.txt'), b'original')
        self.assertEqual(self.storage.list_files('documents', 'team/')[0]['name'], 'report.txt')
        self.storage.delete_file('documents', ['team/report.txt', 'moved/report.txt'])
        self.assertFalse((self.root / 'documents/team/report.txt').exists())

    def test_bucket_root_listing_and_unicode_names(self):
        self.storage.upload_file('documents', 'báo cáo.txt', b'data')
        self.assertEqual(self.storage.list_files('documents')[0]['name'], 'báo cáo.txt')
        self.assertEqual({b['name'] for b in self.storage.list_buckets()}, {'documents', 'other'})

    def test_unsafe_bucket_names_are_rejected(self):
        for bucket in ('', '.', '..', '../outside', '/tmp', 'C:\\temp', 'C:temp', 'a/b', 'a\\b', 'NUL', 'name.'):
            with self.subTest(bucket=bucket), self.assertRaises(ValueError):
                self.storage.create_bucket(bucket)

    def test_all_operations_reject_unsafe_paths(self):
        self.storage.upload_file('documents', 'safe.txt', b'safe')
        paths = (
            '../other/secret.txt', '../../outside.txt', 'team/../../outside.txt',
            str(self.outside), '/absolute.txt', '\\rooted.txt', '\\\\server\\share\\file',
            'C:\\outside.txt', 'C:relative.txt', 'safe.txt:stream', 'team\\..\\secret',
            'team/./report', '.. /outside', 'name./report', 'CON', 'team/NUL.txt', '\x00bad',
        )
        for path in paths:
            operations = {
                'upload': lambda: self.storage.upload_file('documents', path, b'bad', upsert=True),
                'download': lambda: self.storage.download_file('documents', path),
                'delete': lambda: self.storage.delete_file('documents', [path]),
                'list': lambda: self.storage.list_files('documents', path),
                'copy_source': lambda: self.storage.copy_file('documents', path, 'copy.txt'),
                'copy_destination': lambda: self.storage.copy_file('documents', 'safe.txt', path),
                'move_source': lambda: self.storage.move_file('documents', path, 'moved.txt'),
                'move_destination': lambda: self.storage.move_file('documents', 'safe.txt', path),
                'public_url': lambda: self.storage.get_public_url('documents', path),
                'signed_url': lambda: self.storage.create_signed_url('documents', path),
            }
            for operation, call in operations.items():
                with self.subTest(path=path, operation=operation), self.assertRaises(ValueError):
                    call()
        self.assertEqual(self.outside.read_bytes(), b'outside original')
        self.assertEqual(self.storage.download_file('documents', 'safe.txt'), b'safe')

    def test_batch_delete_validates_every_path_before_any_deletion(self):
        self.storage.upload_file('documents', 'keep.txt', b'keep')
        with self.assertRaises(ValueError):
            self.storage.delete_file('documents', ['keep.txt', '../../outside.txt'])
        self.assertEqual(self.storage.download_file('documents', 'keep.txt'), b'keep')
        with self.assertRaises(ValueError):
            self.storage.delete_file('documents', 'keep.txt')

    def make_link(self, link, target, directory=False):
        try:
            link.symlink_to(target, target_is_directory=directory)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f'Symlink creation unavailable: {exc}')

    def test_symlink_file_cannot_read_write_delete_or_leak_in_listing(self):
        link = self.root / 'documents/link.txt'
        self.make_link(link, self.outside)
        for operation in (
            lambda: self.storage.download_file('documents', 'link.txt'),
            lambda: self.storage.upload_file('documents', 'link.txt', b'bad', upsert=True),
            lambda: self.storage.delete_file('documents', ['link.txt']),
            lambda: self.storage.copy_file('documents', 'link.txt', 'copy.txt'),
            lambda: self.storage.move_file('documents', 'link.txt', 'moved.txt'),
        ):
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                operation()
        self.assertEqual(self.storage.list_files('documents'), [])
        self.assertEqual(self.outside.read_bytes(), b'outside original')

    def test_symlink_directory_cannot_be_used_as_destination(self):
        self.make_link(self.root / 'documents/link', Path(self.sandbox.name), directory=True)
        with self.assertRaises(ValueError):
            self.storage.upload_file('documents', 'link/outside.txt', b'bad', upsert=True)
        self.assertEqual(self.outside.read_bytes(), b'outside original')

    def test_symlink_bucket_is_rejected_and_not_listed(self):
        self.make_link(self.root / 'linked', Path(self.sandbox.name), directory=True)
        with self.assertRaises(ValueError):
            self.storage.list_files('linked')
        self.assertNotIn('linked', {b['name'] for b in self.storage.list_buckets()})

    def test_dangling_symlink_is_rejected(self):
        self.make_link(self.root / 'documents/dangling', Path(self.sandbox.name) / 'missing')
        with self.assertRaises(ValueError):
            self.storage.upload_file('documents', 'dangling/new.txt', b'bad')
