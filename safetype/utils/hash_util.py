"""
SafeType Cryptographic Hash Calculator Utility
Computes SHA-256 and MD5 hashes for process binaries on disk.
"""

import hashlib
import os
from typing import Dict, Optional


def compute_file_hashes(file_path: str) -> Dict[str, Optional[str]]:
    """
    Compute SHA-256 and MD5 hashes for a binary executable file safely.
    Returns dict with keys 'sha256' and 'md5'.
    """
    if not file_path or not os.path.isfile(file_path):
        return {"sha256": None, "md5": None}

    try:
        sha256_hash = hashlib.sha256()
        md5_hash = hashlib.md5()

        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(65536), b""):
                sha256_hash.update(byte_block)
                md5_hash.update(byte_block)

        return {
            "sha256": sha256_hash.hexdigest(),
            "md5": md5_hash.hexdigest(),
        }
    except Exception:
        return {"sha256": None, "md5": None}
