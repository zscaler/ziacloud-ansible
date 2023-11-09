# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# Copyright (c) 2023 Zscaler Business Development, <zscaler-partner-labs@z-bd.com>
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.module_utils.basic import env_fallback

import platform
from ansible.module_utils import ansible_release
import importlib
from zscaler.zia import ZIAClientHelper as ZIA

VALID_ZIA_CLOUD = {
    "zscaler",
    "zscloud",
    "zscalerbeta",
    "zspreview",
    "zscalerone",
    "zscalertwo",
    "zscalerthree",
    "zscalergov",
    "zscalerten",
}


def to_zscaler_sdk_cls(pkg_name, cls_name):
    sdk_names = (
        "zscaler",
    )  # tuple with one item for now. You can add more SDK names if needed

    for sdk_name in sdk_names:
        try:
            mod = importlib.import_module("{0}.{1}".format(sdk_name, pkg_name))
        except ModuleNotFoundError:
            continue
        else:
            try:
                return getattr(mod, cls_name)
            except AttributeError:
                raise Exception(
                    "{0}.{1}.{2} does not exist".format(sdk_name, pkg_name, cls_name)
                )

    raise Exception("Couldn't find any sdk package named {0}".format(pkg_name))


class ConnectionHelper:
    def __init__(self, min_sdk_version):
        self.min_sdk_version = min_sdk_version
        self.sdk_installed = self._check_sdk_installed()

    def _check_sdk_installed(self):
        try:
            import zscaler

            installed_version = tuple(map(int, zscaler.__version__.split(".")))
            if installed_version < self.min_sdk_version:
                raise Exception(
                    f"zscaler version should be >= {'.'.join(map(str, self.min_sdk_version))}"
                )
            return True
        except ModuleNotFoundError:
            return False
        except AttributeError:
            raise Exception(
                "zscaler does not have a __version__ attribute. Please ensure you have the correct SDK installed."
            )

    def ensure_sdk_installed(self):
        if not self.sdk_installed:
            raise Exception('Missing required SDK "zscaler".')


class ZIAClientHelper(ZIA):
    def __init__(self, module):
        self.connection_helper = ConnectionHelper(min_sdk_version=(1, 0, 0))
        self.connection_helper.ensure_sdk_installed()

        provider = module.params.get("provider") or {}

        username = (
            provider.get("username") if provider else module.params.get("username")
        )
        if not username:
            raise ValueError("username must be provided via provider or directly")

        password = (
            provider.get("password") if provider else module.params.get("password")
        )
        if not password:
            raise ValueError("password must be provided via provider or directly")

        api_key = provider.get("api_key") if provider else module.params.get("api_key")
        if not api_key:
            raise ValueError("api_key must be provided via provider or directly")

        cloud_env = provider.get("cloud") if provider else module.params.get("cloud")
        if not cloud_env:
            raise ValueError("cloud must be provided via provider or directly")

        cloud_env = cloud_env.lower()

        if cloud_env not in VALID_ZIA_CLOUD:
            raise ValueError(
                f"Invalid ZIA Cloud environment '{cloud_env}'. Supported environments are: {', '.join(VALID_ZIA_CLOUD)}."
            )

        super().__init__(
            username=username,
            password=password,
            api_key=api_key,
            cloud=cloud_env,  # using the validated cloud environment
        )

        ansible_version = ansible_release.__version__  # Get the Ansible version
        self.user_agent = f"zia-ansible/{ansible_version}/({platform.system().lower()} {platform.machine()}"

    @staticmethod
    def zia_argument_spec():
        return dict(
            provider=dict(
                type="dict",
                options=dict(
                    username=dict(
                        no_log=True,
                        fallback=(env_fallback, ["ZIA_USERNAME"]),
                    ),
                    password=dict(
                        no_log=True,
                        fallback=(env_fallback, ["ZIA_PASSWORD"]),
                    ),
                    api_key=dict(
                        no_log=True,
                        fallback=(env_fallback, ["ZIA_API_KEY"]),
                    ),
                    cloud=dict(
                        no_log=False,
                        fallback=(env_fallback, ["ZIA_CLOUD"]),
                    ),
                    sandbox_token=dict(
                        no_log=True,
                        fallback=(env_fallback, ["ZIA_SANDBOX_TOKEN"]),
                    ),
                ),
            ),
            username=dict(
                no_log=True,
                fallback=(env_fallback, ["ZIA_USERNAME"]),
            ),
            password=dict(
                no_log=True,
                fallback=(env_fallback, ["ZIA_PASSWORD"]),
            ),
            api_key=dict(
                no_log=True,
                fallback=(env_fallback, ["ZIA_API_KEY"]),
            ),
            cloud=dict(
                no_log=False,
                fallback=(env_fallback, ["ZIA_CLOUD"]),
            ),
            sandbox_token=dict(
                no_log=True,
                fallback=(env_fallback, ["ZIA_SANDBOX_TOKEN"]),
            ),
        )
