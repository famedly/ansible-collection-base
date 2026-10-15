# -*- coding: utf-8 -*-

# (c) 2026, Famedly GmbH
# GNU Affero General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/agpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.plugins.action import ActionBase
from ansible_collections.famedly.base.plugins.plugin_utils.gpg_session_cache import (
    ensure_session_key_cache,
)


class ActionModule(ActionBase):
    """
    Runs the gpg_secretstore module, wiring it up with the session key cache of
    the current run, so files which were already decrypted during this run
    (e.g. for another host) can be decrypted without a private key operation.
    The cache is only reachable when the module runs on the controller.
    """

    def run(self, tmp=None, task_vars=None):
        result = super().run(tmp, task_vars)
        del tmp

        module_args = self._task.args.copy()
        if (
            self._connection.transport == "local"
            and "session_key_cache_socket" not in module_args
        ):
            socket_path = ensure_session_key_cache()
            if socket_path:
                module_args["session_key_cache_socket"] = socket_path

        result.update(
            self._execute_module(module_args=module_args, task_vars=task_vars)
        )
        return result
