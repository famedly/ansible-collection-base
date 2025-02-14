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
    mypassword: "{{ lookup('famedly.base.gpg_secretstore', 'example/yaml', 'data_type=yaml')}}"

- name: lookup password from non-default password-store location
  debug:
    var: mypassword
  vars:
    mypassword: "{{ lookup('famedly.base.gpg_secretstore', 'example/temporary', 'password_store_path=/tmp/temporary-store')}}"
"""

RETURN = r"""
_raw:
  description: a password
  type: string
"""

import os, mmap, json, yaml, subprocess
from ansible.plugins.lookup import LookupBase
from ansible.module_utils.six import raise_from
from ansible.module_utils.basic import missing_required_lib
from ansible.errors import AnsibleError
from ansible.parsing.splitter import parse_kv
from ansible_collections.famedly.base.plugins.module_utils.gpg_utils import (
    SecretStore,
    check_secretstore_import_errors,
)


ENTRY_SIZE = 128
CACHE_ENTRIES = 65536
NULL_ENTRY = b'\0' * ENTRY_SIZE
cache = mmap.mmap(-1, ENTRY_SIZE * CACHE_ENTRIES, flags=mmap.MAP_SHARED | mmap.MAP_ANONYMOUS)


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

        if len(terms) == 1:
            params = {}
        else:
            params = parse_kv(terms[1])

        data_type = params.get("_raw_params", params.get("data_type", "plain"))
        password_store_path = params.get("password_store_path", "~/.password-store") + "/"
        cache_entry = hash(password_store_path + terms[0]) % CACHE_ENTRIES

        cached = cache[ENTRY_SIZE * cache_entry : ENTRY_SIZE * (cache_entry + 1)]
        if cached != NULL_ENTRY:
            with open(password_store_path + terms[0] + ".gpg", "r") as f:
                read_end, write_end = os.pipe()
                os.write(write_end, cached.rstrip(b'\0'))
                os.close(write_end)
                result = subprocess.run(["gpg", "--decrypt", "--override-session-key-fd", f"{read_end}"], stdin=f, pass_fds=[read_end], capture_output=True)
                os.close(read_end)

        if cached == NULL_ENTRY or result.returncode != 0:
            with open(password_store_path + terms[0] + ".gpg", "r") as f:
                result = subprocess.run(["gpg", "--decrypt", "--show-session-key"], stdin=f, capture_output=True)

            NEEDLE = b'gpg: session key: '
            cached = next(x.removeprefix(NEEDLE) for x in result.stderr.splitlines() if x.startswith(NEEDLE))
            cached = cached[1:-1]
            cached += b'\0' * (ENTRY_SIZE - len(cached))
            cache[ENTRY_SIZE * cache_entry : ENTRY_SIZE * (cache_entry + 1)] = cached

        raw = result.stdout

        if data_type == "plain":
            return [raw]
        if data_type == "json":
            return [json.loads(raw)]
        if data_type == "yaml":
            return [yaml.safe_load(raw)]
