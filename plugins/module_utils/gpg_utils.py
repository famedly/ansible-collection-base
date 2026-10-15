#!/usr/bin/env python
# -*- coding: utf-8 -*-

# (c) 2021-2022, Famedly GmbH
# GNU Affero General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/agpl-3.0.txt)

from __future__ import absolute_import, division, print_function
from typing import List

__metaclass__ = type

# Check if all required libs can loaded
import hashlib
import os.path
import re
import socket
import stat
from pathlib import Path
from typing import Optional, Union


try:
    import gnupg
except ImportError as imp_exc:
    GNUPG_IMPORT_ERROR = imp_exc
else:
    GNUPG_IMPORT_ERROR = None

try:
    import json
except ImportError as imp_exc:
    JSON_IMPORT_ERROR = imp_exc
else:
    JSON_IMPORT_ERROR = None

try:
    import yaml
except ImportError as imp_exc:
    YAML_IMPORT_ERROR = imp_exc
else:
    YAML_IMPORT_ERROR = None


def check_secretstore_import_errors():
    errors = {}
    if GNUPG_IMPORT_ERROR:
        errors["gnupg"] = GNUPG_IMPORT_ERROR
    if JSON_IMPORT_ERROR:
        errors["json"] = JSON_IMPORT_ERROR
    if YAML_IMPORT_ERROR:
        errors["yaml"] = YAML_IMPORT_ERROR
    return errors


class GPGException(Exception):
    def __init__(self, *args):
        super().__init__(*args)


class PasswordStoreException(Exception):
    def __init__(self, *args):
        super().__init__(*args)


class PasswordDecodeError(Exception):
    def __init__(self, *args):
        super().__init__(*args)


class RecipientsMismatchError(Exception):
    def __init__(self, *args):
        super().__init__(*args)


class TrustLevel:
    UNKNOWN = "o"
    INVALID = "i"
    DISABLED = "d"
    REVOKED = "r"
    EXPIRED = "e"
    UNKNOWN_VALIDITY = "-"
    UNDEFINED_VALIDITY = "q"
    NOT_VALID = "n"
    MARGINAL = "m"
    FULLY = "f"
    ULTIMATELY = "u"
    WELL_KNOWN_PRIVATE = "w"
    SPECIAL = "s"
    SIGNATURE_GOOD = "!"
    SIGNATURE_BAD = "-"
    NO_PUBKEY = "?"
    SIGNATURE_ERROR = "%"


SESSION_KEY_PATTERN = r"\d+:[0-9A-F]+"
SESSION_KEY_STATUS_RE = re.compile(r"^\[GNUPG:\] SESSION_KEY (" + SESSION_KEY_PATTERN + r")$", re.M)


class SessionKeyCache:
    """
    Client for the run-scoped session key cache daemon
    (see plugins/plugin_utils/gpg_session_cache.py).

    Maps the sha256 of a ciphertext to its session key, so that a file which was
    already decrypted during the current ansible run can be decrypted again
    without a private key operation (e.g. on a smartcard). Every failure is
    treated as a cache miss.
    """

    TIMEOUT = 2

    def __init__(self, socket_path: str):
        # Only talk to a socket in a directory nobody else can access, otherwise
        # another user could receive our session keys. This mirrors _cache_dir in
        # plugins/plugin_utils/gpg_session_cache.py, which module_utils can't import.
        socket_path = os.path.realpath(socket_path)
        self.socket_path = (
            socket_path if self.__is_private_dir(os.path.dirname(socket_path)) else None
        )

    @staticmethod
    def __is_private_dir(path: str) -> bool:
        try:
            info = os.lstat(path)
        except OSError:
            return False
        return (
            stat.S_ISDIR(info.st_mode)
            and info.st_uid == os.geteuid()
            and not info.st_mode & 0o077
        )

    def __request(self, line: str) -> Optional[str]:
        if self.socket_path is None:
            return None
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.TIMEOUT)
                sock.connect(self.socket_path)
                sock.sendall(line.encode("ascii") + b"\n")
                with sock.makefile("rb") as response:
                    return response.readline(4096).decode("ascii").rstrip("\n")
        except (OSError, UnicodeDecodeError):
            return None

    def get(self, digest: str) -> Optional[str]:
        session_key = self.__request(f"GET {digest}")
        if session_key and re.fullmatch(SESSION_KEY_PATTERN, session_key):
            return session_key
        return None

    def put(self, digest: str, session_key: str):
        self.__request(f"PUT {digest} {session_key}")


class SecretStore:
    SUPPORTED_TYPES = ["plain", "json", "yaml"]
    ENCODING = "UTF-8"
    RECIPIENT_METHODS = ["keyring", "pass_file", "list"]

    def __init__(
        self,
        password_store_path: str = "~/.password-store/",
        file_extension: str = ".gpg",
        keyring: str = "pubring.kbx",
        pass_gpg_id_file: str = ".gpg-id",
        recipient_method: str = "pass_file",
        recipient_list: List[str] = None,
        session_key_cache_socket: str = None,
    ):
        self.password_store_path = Path(password_store_path)
        self.file_extension = file_extension
        self.pass_gpg_id_file = pass_gpg_id_file
        self.session_key_cache = (
            SessionKeyCache(session_key_cache_socket)
            if session_key_cache_socket
            else None
        )

        # Create gpg object
        self.__gpg = gnupg.GPG(
            keyring=keyring,
        )
        self.gpg = self.__gpg

        # Memoized recipient fingerprints by sha256(ciphertext)
        self.__file_recipients = {}

        # Manage recipients
        self.recipient_method = recipient_method
        self.recipient_list = recipient_list
        if isinstance(self.recipient_list, list):
            self.recipient_method = "list"
        if recipient_method not in self.RECIPIENT_METHODS:
            raise NotImplementedError(
                "Recipient method {0} is not supported".format(recipient_method)
            )

    def __convert_slug_to_path(self, slug: str) -> Path:
        return Path(
            (self.password_store_path / (slug + self.file_extension))
            .expanduser()
            .absolute()
            .as_posix()
        )

    def __read(self, slug: str) -> bytes:
        return self.__convert_slug_to_path(slug).read_bytes()

    def __decrypt(self, ciphertext: bytes, digest: str) -> str:
        cache = self.session_key_cache
        session_key = cache.get(digest) if cache else None
        if session_key:
            # gpg reads the session key up to the newline from stdin before the
            # ciphertext, so it doesn't show up in the process list
            result = self.__gpg.decrypt(
                session_key.encode("ascii") + b"\n" + ciphertext,
                extra_args=["--override-session-key-fd", "0"],
            )
            if result.ok:
                return result.data.decode(self.ENCODING)

        # gpg also logs the session key, which must not end up in a log-file
        # configured in gpg.conf. Status lines are still written to stderr.
        result = self.__gpg.decrypt(
            ciphertext,
            extra_args=(
                ["--show-session-key", "--log-file", os.devnull] if cache else None
            ),
        )
        if not result.ok:
            raise GPGException(result.status)
        match = cache and SESSION_KEY_STATUS_RE.search(result.stderr)
        if match:
            cache.put(digest, match.group(1))
        return result.data.decode(self.ENCODING)

    def __save(self, slug: str, data: str) -> bool:
        file = self.__convert_slug_to_path(slug)
        Path.mkdir(file.parent, parents=True, exist_ok=True)
        result = self.__gpg.encrypt(
            data.encode(self.ENCODING), self.get_recipients(slug)
        )
        if result.ok:
            with open(file, "wb") as f:
                f.write(result.data)
            return True
        else:
            raise GPGException(result.status)

    def get_recipients_from_encrypted_file(self, slug) -> List[str]:
        ciphertext = self.__read(slug)
        return self.__get_recipients_from_ciphertext(
            ciphertext, hashlib.sha256(ciphertext).hexdigest()
        )

    def __get_recipients_from_ciphertext(
        self, ciphertext: bytes, digest: str
    ) -> List[str]:
        if digest not in self.__file_recipients:
            recipient_subkeys = self.__gpg.get_recipients(ciphertext)
            # Resolve all recipients with a single gpg call instead of one per recipient
            keys = self.__gpg.list_keys(keys=recipient_subkeys) if recipient_subkeys else []
            primary_fingerprints = {}
            for key in keys:
                primary_fingerprints[key["keyid"]] = key["fingerprint"]
                for subkey in key["subkeys"]:
                    primary_fingerprints[subkey[0]] = key["fingerprint"]
            recipients = list()
            for recipient_subkey in recipient_subkeys:
                if recipient_subkey not in primary_fingerprints:
                    raise GPGException(
                        f"Can not find primary key in keyring for encryption subkey {recipient_subkey}"
                    )
                recipients.append(primary_fingerprints[recipient_subkey])
            self.__file_recipients[digest] = recipients
        return list(self.__file_recipients[digest])

    def get(
        self, slug: str, data_type: str = "plain", check_recipients: bool = True
    ) -> Union[str, dict, list]:
        data_type = data_type.lower()

        if data_type not in self.SUPPORTED_TYPES:
            raise NotImplementedError("Datatype {0} is not supported".format(data_type))

        ciphertext = self.__read(slug)
        digest = hashlib.sha256(ciphertext).hexdigest()

        if check_recipients:
            file_recipients = self.__get_recipients_from_ciphertext(ciphertext, digest)
            expected_recipients = self.get_recipients(slug)

            for file_recipient in file_recipients:
                if file_recipient in expected_recipients:
                    expected_recipients.remove(file_recipient)
                else:
                    raise RecipientsMismatchError
            if len(expected_recipients) > 0:
                raise RecipientsMismatchError

        raw = self.__decrypt(ciphertext, digest)
        try:
            if data_type == "plain":
                return raw
            if data_type == "json":
                return json.loads(raw)
            if data_type == "yaml":
                return yaml.safe_load(raw)
        except (json.decoder.JSONDecodeError, yaml.YAMLError) as e:
            raise PasswordDecodeError

    def get_recipients(self, slug: str) -> List[str]:
        recipients = list()
        if self.recipient_method == "keyring":
            recipients = self.__get_recipients_from_keyring()
        if self.recipient_method == "pass_file":
            recipients = self.__get_recipients_from_pass_file(slug)
        if self.recipient_method == "list":
            recipients = self.recipient_list
        if len(recipients) == 0:
            raise PasswordStoreException("Empty recipient  list")
        return recipients

    def __get_recipients_from_keyring(self) -> List[str]:
        recipients = []
        for key in self.__gpg.list_keys():
            if key["trust"] in [
                TrustLevel.FULLY,
                TrustLevel.MARGINAL,
                TrustLevel.ULTIMATELY,
            ]:
                recipients.append(key["fingerprint"])
        return recipients

    def __get_recipients_from_pass_file(self, password_slug: str) -> List[str]:
        base_path = self.password_store_path.expanduser().absolute() / password_slug
        while base_path.as_posix() != "/":
            if os.path.isfile(base_path / self.pass_gpg_id_file):
                break
            # This is not the proper way to do it, but the proper way is extremely complicated
            # because we are in module_utils and not a module
            # print(f"debug: no {self.pass_gpg_id_file} file found on {base_path}, traversing up")
            base_path = base_path.parent
        else:
            raise FileNotFoundError(
                "Could not find {0} in tree".format(self.pass_gpg_id_file)
            )
        with open(base_path / self.pass_gpg_id_file) as f:
            return f.read().splitlines()

    def put(self, slug: str, data: Union[str, dict, list], data_type: str = None):
        if not isinstance(data, str) and data_type is None:
            data_type = "yaml"
        elif isinstance(data, str) and data_type is None:
            data_type = "plain"

        if data_type not in self.SUPPORTED_TYPES:
            raise NotImplementedError("Datatype {0} is not supported".format(data_type))

        result = None
        if data_type == "plain":
            result = data
        if data_type == "json":
            result = json.dumps(data, indent=4)
        if data_type == "yaml":
            result = yaml.safe_dump(data)

        self.__save(slug, result)

    def remove(self, slug: str):
        file = self.__convert_slug_to_path(slug)
        os.remove(file)
        path = file.parent
        while True:
            try:
                os.rmdir(path)
                path = path.parent
            except (OSError, FileNotFoundError):
                break
