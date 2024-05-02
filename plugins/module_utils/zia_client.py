# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 Zscaler Inc, <devrel@zscaler.com>

#                              MIT License
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import platform
from ansible.module_utils.basic import missing_required_lib, env_fallback
from ansible.module_utils import ansible_release

# Initialize import error variables
ZSCALER_IMPORT_ERROR = None
VERSION_IMPORT_ERROR = None

try:
    from zscaler.zia import ZIAClientHelper as ZIA

    HAS_ZSCALER = True
    ZSCALER_IMPORT_ERROR = None
except ImportError:
    ZIA = object  # Default to object if import fails
    HAS_ZSCALER = False
    ZSCALER_IMPORT_ERROR = missing_required_lib("zscaler")

# Attempt to import the version information
try:
    from ansible_collections.zscaler.ziacloud.plugins.module_utils.version import (
        __version__ as ansible_collection_version,
    )

    HAS_VERSION = True
except ImportError as e:
    HAS_VERSION = False
    VERSION_IMPORT_ERROR = missing_required_lib(
        "plugins.module_utils.version (version information)"
    )


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
            module.fail_json(
                msg="The 'zscaler' library is required for this module.",
                exception=ZSCALER_IMPORT_ERROR,
            )
        if not HAS_VERSION:
            module.fail_json(
                msg="Failed to import the version from the collection's module_utils.",
                exception=VERSION_IMPORT_ERROR,
            )

        self.connection_helper = ConnectionHelper(min_sdk_version=(0, 1, 0))
        provider = module.params.get("provider", {})
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
        self.user_agent = f"ziacloud-ansible/{ansible_version} (collection/{ansible_collection_version}) ({platform.system().lower()} {platform.machine()})"

    @staticmethod
    def zia_argument_spec():
        return dict(
            provider=dict(
                type="dict",
                options=dict(
                    username=dict(
                        no_log=False,
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
