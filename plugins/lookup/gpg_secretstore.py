#!/usr/bin/env python
# -*- coding: utf-8 -*-

# (c) 2021-2022, Famedly GmbH
# GNU Affero General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/agpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
name: gpg_secretstore
author:
    - Jadyn Emma Jäger (@jadyndev)
    - Jan Christian Grünhage (@jcgruenhage)
short_description: read passwords that are compatible with passwordstore.org's pass utility
description:
  - Enables Ansible to read passwords/secrets from the passwordstore.org pass utility.
  - It's also able to read yaml/json files if needed
options:
  _terms:
    description: Slug of the secret being read from the store.
    required: True
  check_recipients:
    description: If the ciphertexts recipients should be matched against .gpg-id.
    default: True
  data_type:
    description: If the decrypted data should be interpreted as yaml, json or plain text.
    default: 'plain'
    choices:
        - yaml
        - json
        - plain
  password_store_path:
    description: Where to look for the password store
    default: '~/.password-store'
"""
EXAMPLES = r"""
# Debug is used for examples, BAD IDEA to show passwords on screen
- name: lookup password
  debug:
    var: mypassword
  vars:
    mypassword: "{{ lookup('famedly.base.gpg_secretstore', 'example')}}"

- name: lookup password and parse yaml
  debug:
    var: mypassword
  vars:
    mypassword: "{{ lookup('famedly.base.gpg_secretstore', 'example/yaml', data_type='yaml')}}"

- name: lookup password from non-default password-store location
  debug:
    var: mypassword
  vars:
    mypassword: "{{ lookup('famedly.base.gpg_secretstore', 'example/temporary', password_store_path='/tmp/temporary-store')}}"

- name: lookup password without checking recipients
  debug:
    var: mypassword
  vars:
    mypassword: "{{ lookup('famedly.base.gpg_secretstore', 'example', check_recipients=False)}}"
"""

RETURN = r"""
_raw:
  description: a password
  type: string
"""

from ansible.plugins.lookup import LookupBase
from ansible.module_utils.six import raise_from
from ansible.module_utils.basic import missing_required_lib
from ansible.errors import AnsibleError
from ansible_collections.famedly.base.plugins.module_utils.gpg_utils import (
    SecretStore,
    check_secretstore_import_errors,
)


class LookupModule(LookupBase):
    def run(self, terms: dict, variables, **kwargs):
        errors = []
        traceback = []
        for lib, exception in check_secretstore_import_errors().items():
            errors.append(missing_required_lib(lib))
            traceback.append(exception)
        if errors:
            raise_from(
                AnsibleError("\n".join(errors)),
                "\n".join(traceback),
            )

        data_type = kwargs.get("data_type", "plain")
        password_store_path = kwargs.get("password_store_path", "~/.password-store/")
        check_recipients = kwargs.get("check_recipients", True)

        password_store = SecretStore(password_store_path=password_store_path)
        result = password_store.get(
            terms[0], data_type, check_recipients=check_recipients
        )
        return [result]
