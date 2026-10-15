# -*- coding: utf-8 -*-

# (c) 2026, Famedly GmbH
# GNU Affero General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/agpl-3.0.txt)

"""
Run-scoped, in-memory cache for GPG session keys.

Decrypting a pass file needs a private key operation, which takes ~150ms on a
smartcard and can't be parallelized. Within a single ansible run, the same file
is often decrypted again and again (e.g. once per host), so we remember the
session key of every file we decrypted and can then decrypt it again without
touching the private key.

The cache is a small daemon listening on a unix socket in a user-private
directory. There is one daemon per ansible controller process; it keeps the
session keys in memory only and exits as soon as that process is gone (or after
MAX_LIFETIME at the latest), so nothing outlives the ansible run. The client side lives in
module_utils/gpg_utils.py (SessionKeyCache), as modules need it as well.

This file only uses the standard library, as it is also executed as a script
to start the daemon.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import fcntl
import multiprocessing
import os
import re
import select
import socket
import socketserver
import stat
import subprocess
import sys
import tempfile
import time
from typing import Callable, Optional

DIGEST_RE = re.compile(r"[0-9a-f]{64}")
SESSION_KEY_RE = re.compile(r"\d+:[0-9A-F]+")
MAX_ENTRIES = 100000
STARTUP_TIMEOUT = 3
MAX_LIFETIME = 12 * 3600
# unix socket paths are limited to 108 bytes on Linux and 104 on macOS
MAX_SOCKET_PATH_LENGTH = 100


def _controller_pid() -> int:
    # Lookups and action plugins run in forked ansible workers, whose parent is
    # the ansible-playbook process. Inventory plugins run in that process itself.
    parent = multiprocessing.parent_process()
    return parent.pid if parent is not None else os.getpid()


def _cache_dir() -> Optional[str]:
    base = os.environ.get("XDG_RUNTIME_DIR")
    if not base or not os.path.isdir(base):
        base = tempfile.gettempdir()
    path = os.path.join(base, f"famedly-gpg-secretstore-{os.getuid()}")
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        pass
    # Never use a directory other users could have prepared or can access
    info = os.lstat(path)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
    ):
        return None
    return path


def _is_alive(socket_path: str) -> bool:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        try:
            sock.connect(socket_path)
            return True
        except OSError:
            return False


def _wait_for(condition, timeout: float, interval: float = 0.02) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(interval)
    return False


def ensure_session_key_cache() -> Optional[str]:
    """
    Return the socket path of the session key cache of the current ansible run,
    starting the daemon if necessary. Returns None if the cache is unavailable.
    """
    try:
        cache_dir = _cache_dir()
        if cache_dir is None:
            return None
        controller_pid = _controller_pid()
        socket_path = os.path.join(cache_dir, f"{controller_pid}.sock")
        if len(socket_path) > MAX_SOCKET_PATH_LENGTH:
            return None
        if _is_alive(socket_path):
            return socket_path

        subprocess.Popen(  # pylint: disable=consider-using-with
            [sys.executable, "-I", os.path.abspath(__file__), socket_path, str(controller_pid)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
        )
        if _wait_for(lambda: _is_alive(socket_path), STARTUP_TIMEOUT):
            return socket_path
    except OSError:
        pass
    return None


class _Handler(socketserver.StreamRequestHandler):
    # The server is single threaded, don't let a stuck client block it
    timeout = 2

    def handle(self):
        try:
            request = self.rfile.readline(4096).decode("ascii").split()
        except (OSError, UnicodeDecodeError):
            return
        response = ""
        cache = self.server.session_keys
        if len(request) == 2 and request[0] == "GET" and DIGEST_RE.fullmatch(request[1]):
            response = cache.get(request[1], "")
        elif (
            len(request) == 3
            and request[0] == "PUT"
            and DIGEST_RE.fullmatch(request[1])
            and SESSION_KEY_RE.fullmatch(request[2])
        ):
            if len(cache) < MAX_ENTRIES:
                cache[request[1]] = request[2]
            response = "OK"
        try:
            self.wfile.write(response.encode("ascii") + b"\n")
        except OSError:
            pass


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        # EPERM means the pid was reused by a process of another user
        return False
    return True


def _controller_alive_check(pid: int) -> Callable[[], bool]:
    try:
        # Unlike a pid, a pidfd can't be reused by another process
        pidfd = os.pidfd_open(pid)
    except ProcessLookupError:
        return lambda: False
    except (AttributeError, OSError):
        # No pidfd support (not Linux, or Linux < 5.3)
        return lambda: _process_exists(pid)
    # The pidfd becomes readable once the process has exited
    return lambda: not select.select([pidfd], [], [], 0)[0]


def serve(socket_path: str, controller_pid: int):
    # Only one daemon per socket: concurrently started daemons give up here
    lock_path = socket_path + ".lock"
    lock_fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return

    try:
        # Leftover of a crashed daemon
        os.unlink(socket_path)
    except FileNotFoundError:
        pass
    old_umask = os.umask(0o077)
    try:
        server = socketserver.UnixStreamServer(socket_path, _Handler)
    finally:
        os.umask(old_umask)
    server.session_keys = {}
    server.timeout = 1
    controller_alive = _controller_alive_check(controller_pid)
    # Backstop in case the controller's death goes unnoticed. A daemon that
    # exits during a run just means a fresh, empty cache is started.
    deadline = time.monotonic() + MAX_LIFETIME
    try:
        while controller_alive() and time.monotonic() < deadline:
            server.handle_request()
    finally:
        server.server_close()
        for path in (socket_path, lock_path):
            try:
                os.unlink(path)
            except OSError:
                pass


if __name__ == "__main__":
    serve(sys.argv[1], int(sys.argv[2]))
