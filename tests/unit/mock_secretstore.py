from typing import List, Dict, Union

from ansible_collections.famedly.base.plugins.module_utils import gpg_utils


class MockSecretStore:
    SECRETSTORE: Dict[str, Dict[str, Union[str, list]]]
    RECIPIENTS: List[str]

    def __init__(
        self,
        password_store_path: str = "~/.password-store/",
        file_extension: str = ".gpg",
        keyring: str = "pubring.kbx",
        gnupg_home: str = "~/.gnupg",
        pass_gpg_id_file: str = ".gpg-id",
        recipient_method: str = "pass_file",
        recipient_list: List[str] = None,
        session_key_cache_socket: str = None,
    ):
        self.RECIPIENTS = ["recipient1", "recipient2", "recipient3"]
        self.SECRETSTORE = {
            "secret/exists": {
                "value": "secretdata",
                "recipients": ["recipient1", "recipient2", "recipient3"],
            },
            "secret/recipient-missmatch": {
                "value": "secretdata",
                "recipients": ["recipient1", "recipient3"],
            },
            "secret/delete": {
                "value": "secretdata",
                "recipients": ["recipient1", "recipient2", "recipient3"],
            },
        }

    def get(
        self, slug: str, data_type: str = "plain", check_recipients: bool = True
    ) -> Union[str, dict, list]:
        try:
            secret = self.SECRETSTORE[slug]
        except KeyError:
            raise FileNotFoundError
        if secret["recipients"] != self.RECIPIENTS and check_recipients:
            raise gpg_utils.RecipientsMismatchError
        return secret["value"]

    def put(self, slug: str, data: Union[str, dict, list], data_type: str = None):
        self.SECRETSTORE[slug] = {
            "value": data,
            "recipients": self.get_recipients(slug),
        }

    def remove(self, slug: str):
        self.SECRETSTORE.pop(slug)

    def get_recipients_from_encrypted_file(self, slug) -> List[str]:
        try:
            secret = self.SECRETSTORE[slug]
        except KeyError:
            raise FileNotFoundError
        return secret["recipients"]

    def get_recipients(self, slug: str) -> List[str]:
        return self.RECIPIENTS
