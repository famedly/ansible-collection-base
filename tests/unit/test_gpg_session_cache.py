from __future__ import absolute_import, division, print_function, annotations

import os
import shutil
import subprocess
import sys
import tempfile

import pytest

from ansible_collections.famedly.base.plugins.module_utils import gpg_utils
from ansible_collections.famedly.base.plugins.module_utils.gpg_utils import (
    SecretStore,
    SessionKeyCache,
)
from ansible_collections.famedly.base.plugins.plugin_utils import gpg_session_cache

DIGEST = "ab" * 32
SESSION_KEY = "9:" + "0123456789ABCDEF" * 4


@pytest.fixture
def runtime_dir(monkeypatch):
    # unix socket paths are length limited, so don't use pytest's tmp_path
    path = tempfile.mkdtemp(prefix="gsc-", dir="/tmp")
    monkeypatch.setenv("XDG_RUNTIME_DIR", path)
    yield path
    shutil.rmtree(path)


class TestSessionKeyCache:
    def test_roundtrip(self, runtime_dir):
        socket_path = gpg_session_cache.ensure_session_key_cache()
        assert socket_path is not None
        assert socket_path.startswith(runtime_dir)
        # A second call reuses the running daemon
        assert gpg_session_cache.ensure_session_key_cache() == socket_path

        cache = SessionKeyCache(socket_path)
        assert cache.get(DIGEST) is None
        cache.put(DIGEST, SESSION_KEY)
        assert SessionKeyCache(socket_path).get(DIGEST) == SESSION_KEY

    def test_rejects_malformed_requests(self, runtime_dir):
        cache = SessionKeyCache(gpg_session_cache.ensure_session_key_cache())
        cache.put("not-a-digest", SESSION_KEY)
        cache.put(DIGEST, "not a session key")
        assert cache.get(DIGEST) is None
        assert cache.get("not-a-digest") is None

    def test_unreachable_cache_is_a_miss(self):
        cache = SessionKeyCache("/nonexistent/gpg-session-cache.sock")
        assert cache.get(DIGEST) is None
        cache.put(DIGEST, SESSION_KEY)

    def test_refuses_foreign_directory(self, runtime_dir):
        os.mkdir(os.path.join(runtime_dir, f"famedly-gpg-secretstore-{os.getuid()}"), 0o755)
        assert gpg_session_cache.ensure_session_key_cache() is None

    def test_client_refuses_socket_in_shared_directory(self, runtime_dir):
        socket_path = gpg_session_cache.ensure_session_key_cache()
        SessionKeyCache(socket_path).put(DIGEST, SESSION_KEY)
        os.chmod(os.path.dirname(socket_path), 0o755)
        try:
            assert SessionKeyCache(socket_path).get(DIGEST) is None
        finally:
            os.chmod(os.path.dirname(socket_path), 0o700)
        assert SessionKeyCache(socket_path).get(DIGEST) == SESSION_KEY

    def test_daemon_exits_with_controller(self, runtime_dir):
        controller = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        socket_path = os.path.join(runtime_dir, f"{controller.pid}.sock")
        daemon = subprocess.Popen(
            [sys.executable, "-I", gpg_session_cache.__file__, socket_path, str(controller.pid)]
        )
        try:
            assert gpg_session_cache._wait_for(lambda: gpg_session_cache._is_alive(socket_path), 5)
            SessionKeyCache(socket_path).put(DIGEST, SESSION_KEY)
            assert SessionKeyCache(socket_path).get(DIGEST) == SESSION_KEY
            controller.kill()
            controller.wait()
            daemon.wait(timeout=5)
            assert not os.path.exists(socket_path)
        finally:
            controller.kill()
            daemon.kill()


class MockGPG:
    def __init__(self, keyring=None):
        self.list_keys_calls = []

    def get_recipients(self, ciphertext):
        return ["SUBKEY1", "SUBKEY2", "PRIMARY3"]

    def list_keys(self, keys=None):
        self.list_keys_calls.append(keys)
        all_keys = [
            {"keyid": "PRIMARY1", "fingerprint": "FPR1", "subkeys": [["SUBKEY1"]]},
            {"keyid": "PRIMARY2", "fingerprint": "FPR2", "subkeys": [["SUBKEY2"]]},
            {"keyid": "PRIMARY3", "fingerprint": "FPR3", "subkeys": []},
        ]
        return [k for k in all_keys if {k["keyid"], *(s[0] for s in k["subkeys"])} & set(keys)]


class TestRecipients:
    def test_resolves_recipients_with_one_gpg_call(self, monkeypatch, tmp_path):
        monkeypatch.setattr(gpg_utils.gnupg, "GPG", MockGPG)
        (tmp_path / "secret.gpg").write_bytes(b"ciphertext")
        store = SecretStore(password_store_path=str(tmp_path))

        assert store.get_recipients_from_encrypted_file("secret") == ["FPR1", "FPR2", "FPR3"]
        assert store.get_recipients_from_encrypted_file("secret") == ["FPR1", "FPR2", "FPR3"]
        assert store.gpg.list_keys_calls == [["SUBKEY1", "SUBKEY2", "PRIMARY3"]]

    def test_unknown_recipient(self, monkeypatch, tmp_path):
        monkeypatch.setattr(gpg_utils.gnupg, "GPG", MockGPG)
        monkeypatch.setattr(MockGPG, "get_recipients", lambda self, c: ["SUBKEY1", "UNKNOWN"])
        (tmp_path / "secret.gpg").write_bytes(b"ciphertext")
        store = SecretStore(password_store_path=str(tmp_path))

        with pytest.raises(gpg_utils.GPGException):
            store.get_recipients_from_encrypted_file("secret")
