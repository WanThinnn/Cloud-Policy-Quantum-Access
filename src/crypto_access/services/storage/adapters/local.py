import os
import shutil
import logging
import ntpath
import re
from pathlib import Path
from typing import Optional, List, Dict, Any
from django.conf import settings
from ..interface import IStorageService

logger = logging.getLogger('crypto_access.storage')

class LocalStorageAdapter(IStorageService):
    """
    Local Disk Implementation for Storage operations.
    Files are stored in MEDIA_ROOT.
    """
    
    def __init__(self):
        self.base_dir = str(Path(settings.MEDIA_ROOT).resolve())
        if not os.path.exists(self.base_dir):
            os.makedirs(self.base_dir)

    def _get_bucket_path(self, bucket_name: str) -> str:
        if not isinstance(bucket_name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', bucket_name):
            raise ValueError("Invalid storage bucket name.")
        self._validate_component(bucket_name)
        return self._resolve_path(Path(self.base_dir), [bucket_name])

    @staticmethod
    def _validate_component(part: str) -> None:
        reserved = {'CON', 'PRN', 'AUX', 'NUL'} | {
            f'{prefix}{n}' for prefix in ('COM', 'LPT') for n in range(1, 10)
        }
        if part.endswith((' ', '.')) or part.split('.')[0].upper() in reserved:
            raise ValueError("Storage path contains an unsupported filename.")

    @staticmethod
    def _resolve_path(root: Path, parts: List[str]) -> str:
        candidate = root.joinpath(*parts)
        # Reject symlinks/junctions even when they currently point inside the root.
        current = root
        for part in parts:
            current = current / part
            is_reparse_point = current.exists() and getattr(current.lstat(), 'st_file_attributes', 0) & 0x400
            if current.is_symlink() or is_reparse_point:
                raise ValueError("Storage paths cannot contain symbolic links or junctions.")
        try:
            resolved = candidate.resolve()
            resolved.relative_to(root)
        except (ValueError, OSError, RuntimeError) as exc:
            raise ValueError("Storage path must stay inside its bucket.") from exc
        return str(resolved)

    def _get_file_path(self, bucket_name: str, file_path: str, *, allow_empty: bool = False) -> str:
        bucket = Path(self._get_bucket_path(bucket_name))
        if not isinstance(file_path, str) or (not file_path and not allow_empty):
            raise ValueError("Invalid storage path.")
        # Check Windows syntax on every OS: drives, UNC, backslashes and ADS.
        if '\x00' in file_path or '\\' in file_path or ':' in file_path or ntpath.isabs(file_path):
            raise ValueError("Storage path must be relative to its bucket.")
        parts = [part for part in file_path.split('/') if part]
        if any(part in ('.', '..') for part in parts):
            raise ValueError("Storage path cannot contain dot or parent segments.")
        for part in parts:
            self._validate_component(part)
        return self._resolve_path(bucket, parts)

    def create_bucket(
        self, 
        bucket_name: str, 
        public: bool = False,
        allowed_mime_types: Optional[List[str]] = None,
        file_size_limit: Optional[int] = None
    ) -> Dict[str, Any]:
        bucket_path = self._get_bucket_path(bucket_name)
        if not os.path.exists(bucket_path):
            os.makedirs(bucket_path)
            logger.info(f"Local bucket '{bucket_name}' created successfully")
            return {"name": bucket_name, "public": public}
        return {"name": bucket_name, "error": "Bucket already exists"}

    def list_buckets(self) -> List[Dict[str, Any]]:
        buckets = []
        if os.path.exists(self.base_dir):
            for item in os.listdir(self.base_dir):
                try:
                    bucket_path = self._get_bucket_path(item)
                except ValueError:
                    continue
                if os.path.isdir(bucket_path):
                    buckets.append({"name": item})
        return buckets

    def upload_file(
        self,
        bucket_name: str,
        file_path: str,
        file_data: bytes,
        content_type: Optional[str] = None,
        upsert: bool = False,
        user: Optional[Any] = None
    ) -> Dict[str, Any]:
        full_path = self._get_file_path(bucket_name, file_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        
        if os.path.exists(full_path) and not upsert:
            raise Exception("File already exists and upsert is False")
            
        with open(full_path, 'wb') as f:
            f.write(file_data)
            
        logger.info(f"File uploaded to Local: {bucket_name}/{file_path}")
        return {"path": file_path, "size": len(file_data)}

    def download_file(self, bucket_name: str, file_path: str, user: Optional[Any] = None) -> bytes:
        full_path = self._get_file_path(bucket_name, file_path)
        if not os.path.exists(full_path):
            raise FileNotFoundError(f"File {file_path} not found in bucket {bucket_name}")
            
        with open(full_path, 'rb') as f:
            data = f.read()
        logger.info(f"File downloaded from Local: {bucket_name}/{file_path}")
        return data

    def get_public_url(self, bucket_name: str, file_path: str) -> str:
        self._get_file_path(bucket_name, file_path)
        # For local dev, return a relative media URL
        media_url = getattr(settings, 'MEDIA_URL', '/media/')
        return f"{media_url}{bucket_name}/{file_path}"

    def create_signed_url(
        self,
        bucket_name: str,
        file_path: str,
        expires_in: int = 3600
    ) -> str:
        # Local doesn't really support signed URLs, just return public URL
        return self.get_public_url(bucket_name, file_path)

    def delete_file(self, bucket_name: str, file_paths: List[str], user: Optional[Any] = None) -> Dict[str, Any]:
        if not isinstance(file_paths, (list, tuple)):
            raise ValueError("file_paths must be a list of relative paths.")
        # Validate the complete batch before deleting any entry.
        full_paths = [self._get_file_path(bucket_name, path) for path in file_paths]
        deleted = []
        for path, full_path in zip(file_paths, full_paths):
            if os.path.exists(full_path):
                os.remove(full_path)
                deleted.append(path)
        logger.info(f"Files deleted from Local {bucket_name}: {deleted}")
        return {"deleted": deleted}

    def list_files(
        self,
        bucket_name: str,
        path: str = "",
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        target_dir = self._get_file_path(bucket_name, path, allow_empty=True)
        files = []
        
        if os.path.exists(target_dir):
            # Simple non-recursive listing for local mockup
            for item in os.listdir(target_dir):
                try:
                    relative_path = '/'.join(filter(None, [path.rstrip('/'), item]))
                    item_path = self._get_file_path(bucket_name, relative_path)
                except ValueError:
                    continue
                if os.path.isfile(item_path):
                    files.append({
                        "name": item,
                        "size": os.path.getsize(item_path)
                    })
                    
        return files[offset:offset+limit]

    def move_file(
        self,
        bucket_name: str,
        from_path: str,
        to_path: str
    ) -> Dict[str, Any]:
        src = self._get_file_path(bucket_name, from_path)
        dst = self._get_file_path(bucket_name, to_path)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.move(src, dst)
        logger.info(f"File moved in Local: {bucket_name}/{from_path} -> {to_path}")
        return {"message": "success"}

    def copy_file(
        self,
        bucket_name: str,
        from_path: str,
        to_path: str
    ) -> Dict[str, Any]:
        src = self._get_file_path(bucket_name, from_path)
        dst = self._get_file_path(bucket_name, to_path)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)
        logger.info(f"File copied in Local: {bucket_name}/{from_path} -> {to_path}")
        return {"message": "success"}
