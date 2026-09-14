"""
Unit Tests for SafeType Hash Utility and YARA Engine
"""

import os
import tempfile
import pytest
from safetype.utils.hash_util import compute_file_hashes
from safetype.engine.yara_engine import YaraEngine
from safetype.db.models import ProcessRecord


def test_hash_computation():
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(b"SafeType Test File Binary Content")
        temp_path = tf.name

    try:
        hashes = compute_file_hashes(temp_path)
        assert hashes["sha256"] is not None
        assert hashes["md5"] is not None
        assert len(hashes["sha256"]) == 64
        assert len(hashes["md5"]) == 32
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_yara_signature_match():
    ye = YaraEngine()

    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(b"PE Header Mock data SetWindowsHookEx GetAsyncKeyState data")
        temp_path = tf.name

    try:
        proc = ProcessRecord(
            pid=7070,
            name="hook_sample.exe",
            exe_path=temp_path,
        )
        evt = ye.scan_binary_signatures(proc, is_suspicious_location=True)
        assert evt is not None
        assert evt.event_type == "YARA_SIGNATURE_MATCH"
        assert evt.severity == "HIGH"
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
