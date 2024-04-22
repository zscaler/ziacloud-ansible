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

from ansible.module_utils.basic import missing_required_lib, env_fallback
from ansible.module_utils import ansible_release
import platform

try:
    from zscaler.zia import ZIAClientHelper as ZIA
    HAS_ZSCALER = True
    ZSCALER_IMPORT_ERROR = None
except ImportError:
    ZIA = object  # Default to object if import fails
    HAS_ZSCALER = False
    ZSCALER_IMPORT_ERROR = missing_required_lib("zscaler")

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


class ConnectionHelper:
    def __init__(self, min_sdk_version):
        if not HAS_ZSCALER:
            raise ImportError(ZSCALER_IMPORT_ERROR)

        self.min_sdk_version = min_sdk_version
        self.check_sdk_installed()

    def check_sdk_installed(self):
        import zscaler

        installed_version = tuple(map(int, zscaler.__version__.split(".")))
        if installed_version < self.min_sdk_version:
            raise Exception(
                f"zscaler version should be >= {'.'.join(map(str, self.min_sdk_version))}"
            )


class ZIAClientHelper(ZIA):
    def __init__(self, module):
        if not HAS_ZSCALER:
            module.fail_json(msg="The 'zscaler' library is required for this module.", exception=ZSCALER_IMPORT_ERROR)

        self.connection_helper = ConnectionHelper(min_sdk_version=(0, 1, 0))
        provider = module.params.get("provider") or {}
        username = provider.get("username") or module.params.get("username")
        password = provider.get("password") or module.params.get("password")
        api_key = provider.get("api_key") or module.params.get("api_key")
        cloud_env = provider.get("cloud") or module.params.get("cloud")
        cloud_env = cloud_env.lower()

        if cloud_env not in VALID_ZIA_CLOUD:
            raise ValueError(f"Invalid ZIA Cloud environment '{cloud_env}'.")

        super().__init__(
            username=username, password=password, api_key=api_key, cloud=cloud_env
        )
        ansible_version = ansible_release.__version__
        self.user_agent = f"zia-ansible/{ansible_version}/({platform.system().lower()} {platform.machine()})"

    @staticmethod
    def zia_argument_spec():
        return dict(
            provider=dict(
                type="dict",
                options=dict(
                    username=dict(
                        no_log=False,
                        required=True,  # Not required at the provider level if they are provided at the top level
                        fallback=(env_fallback, ["ZIA_USERNAME"]),
                        type="str",
                    ),
                    password=dict(
                        no_log=True,
                        required=True,
                        fallback=(env_fallback, ["ZIA_PASSWORD"]),
                        type="str",
                    ),
                    api_key=dict(
                        no_log=True,
                        required=True,
                        fallback=(env_fallback, ["ZIA_API_KEY"]),
                        type="str",
                    ),
                    cloud=dict(
                        no_log=False,
                        required=True,
                        choices=[
                            "zscloud",
                            "zscaler",
                            "zscalerone",
                            "zscalertwo",
                            "zscalerthree",
                            "zscalerbeta",
                            "zscalergov",
                            "zscalerten",
                        ],
                        fallback=(env_fallback, ["ZIA_CLOUD"]),
                        type="str",
                    ),
                    sandbox_token=dict(
                        no_log=True,
                        required=False,
                        fallback=(env_fallback, ["ZIA_SANDBOX_TOKEN"]),
                        type="str",
                    ),
                ),
            ),
            username=dict(
                no_log=True,
                required=True,
                fallback=(env_fallback, ["ZIA_USERNAME"]),
                type="str",
            ),
            password=dict(
                no_log=True,
                required=True,
                fallback=(env_fallback, ["ZIA_PASSWORD"]),
                type="str",
            ),
            api_key=dict(
                no_log=True,
                required=True,
                fallback=(env_fallback, ["ZIA_API_KEY"]),
                type="str",
            ),
            cloud=dict(
                no_log=False,
                required=True,
                choices=[
                    "zscloud",
                    "zscaler",
                    "zscalerone",
                    "zscalertwo",
                    "zscalerthree",
                    "zscalerbeta",
                    "zscalergov",
                    "zscalerten",
                ],
                fallback=(env_fallback, ["ZIA_CLOUD"]),
                type="str",
            ),
            sandbox_token=dict(
                no_log=True,
                required=False,
                fallback=(env_fallback, ["ZIA_SANDBOX_TOKEN"]),
                type="str",
            ),
        )
