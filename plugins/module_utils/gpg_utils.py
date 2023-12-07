#!/usr/bin/env python
# -*- coding: utf-8 -*-

# (c) 2021-2022, Famedly GmbH
# GNU Affero General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/agpl-3.0.txt)

from __future__ import absolute_import, division, print_function
from typing import List

__metaclass__ = type

# Check if all required libs can loaded
import os.path
from pathlib import Path
from typing import Union
import traceback


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
    ):
        self.password_store_path = Path(password_store_path)
        self.file_extension = file_extension
        self.pass_gpg_id_file = pass_gpg_id_file

        # Create gpg object
        self.__gpg = gnupg.GPG(
            keyring=keyring,
        )
        self.gpg = self.__gpg

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

    def __load(self, slug: str) -> str:
        file = self.__convert_slug_to_path(slug)
        try:
            with open(file, "rb") as f:
                result = self.__gpg.decrypt_file(f)
                if result.ok:
                    return result.data.decode(self.ENCODING)
                else:
                    raise GPGException(result.status)
        except FileNotFoundError:
            raise FileNotFoundError

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
        file = self.__convert_slug_to_path(slug)
        recipients = list()
        try:
            with open(file, "rb") as f:
                recipient_subkeys = self.__gpg.get_recipients(f.read())
            for recipient_subkey in recipient_subkeys:
                recipients.append(
                    self.__gpg.list_keys(keys=recipient_subkey).fingerprints[0]
                )
            return recipients
        except FileNotFoundError:
            raise FileNotFoundError

    def get(
        self, slug: str, data_type: str = "plain", check_recipients: bool = True
    ) -> Union[str, dict, list]:
        data_type = data_type.lower()

        if data_type not in self.SUPPORTED_TYPES:
            raise NotImplementedError("Datatype {0} is not supported".format(data_type))

        if check_recipients:
            file_recipients = self.get_recipients_from_encrypted_file(slug)
            expected_recipients = self.get_recipients(slug)

            for file_recipient in file_recipients:
                if file_recipient in expected_recipients:
                    expected_recipients.remove(file_recipient)
                else:
                    raise RecipientsMismatchError
            if len(expected_recipients) > 0:
                raise RecipientsMismatchError

        raw = self.__load(slug)
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
