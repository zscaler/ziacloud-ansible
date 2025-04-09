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

import os
import platform
from ansible.module_utils.basic import missing_required_lib, env_fallback
from ansible.module_utils import ansible_release

# Initialize import error variables
ZSCALER_IMPORT_ERROR = None
VERSION_IMPORT_ERROR = None

try:
    from zscaler.oneapi_client import LegacyZIAClient
    from zscaler import ZscalerClient as OneAPIClient
    HAS_ZSCALER = True
except ImportError as e:
    LegacyZIAClient = object  # Default to object if import fails
    OneAPIClient = object
    HAS_ZSCALER = False
    ZSCALER_IMPORT_ERROR = missing_required_lib("zscaler")

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

class ZIAClientHelper:
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

        # Initialize provider to an empty dict if None
        provider = module.params.get("provider") or {}

        # Get use_legacy_client flag from provider, module params, or environment
        use_legacy_client = (
            provider.get("use_legacy_client")
            or module.params.get("use_legacy_client")
            or os.getenv("ZSCALER_USE_LEGACY_CLIENT", "").lower() == "true"
        )

        if use_legacy_client:
            self._client = self._init_legacy_client(module, provider)
        else:
            self._client = self._init_oneapi_client(module, provider)

        # Set user agent for both client types
        ansible_version = ansible_release.__version__
        self.user_agent = f"ziacloud-ansible/{ansible_version} (collection/{ansible_collection_version}) ({platform.system().lower()} {platform.machine()})"

    def __getattr__(self, name):
        """Delegate attribute access to the underlying client's zia service"""
        try:
            # First try to get the attribute from the client's zia service
            return getattr(self._client.zia, name)
        except AttributeError:
            # If not found in zia service, try the client directly
            return getattr(self._client, name)

    def _init_legacy_client(self, module, provider):
        """Initialize the legacy ZIA client with username/password/api_key authentication"""
        # Use provider or environment variables
        username = (
            provider.get("username")
            or module.params.get("username")
            or os.getenv("ZIA_USERNAME")
        )
        password = (
            provider.get("password")
            or module.params.get("password")
            or os.getenv("ZIA_PASSWORD")
        )
        api_key = (
            provider.get("api_key")
            or module.params.get("api_key")
            or os.getenv("ZIA_API_KEY")
        )
        cloud_env = (
            provider.get("cloud")
            or module.params.get("cloud")
            or os.getenv("ZIA_CLOUD")
        )

        if not all([username, password, api_key, cloud_env]):
            module.fail_json(msg="All legacy authentication parameters must be provided (username, password, api_key, cloud).")

        # Only validate cloud environment if using ZIA_CLOUD
        if os.getenv("ZIA_CLOUD"):
            cloud_env = cloud_env.lower()
            if cloud_env not in VALID_ZIA_CLOUD:
                module.fail_json(msg=f"Invalid ZIA Cloud environment '{cloud_env}'.")

        config = {
            "username": username,
            "password": password,
            "api_key": api_key,
            "cloud": cloud_env
        }

        return LegacyZIAClient(config)

    def _init_oneapi_client(self, module, provider):
        """Initialize the OneAPI client with OAuth2 authentication"""
        # Get OneAPI parameters from provider, module params, or environment
        client_id = (
            provider.get("client_id")
            or module.params.get("client_id")
            or os.getenv("ZSCALER_CLIENT_ID")
        )
        client_secret = (
            provider.get("client_secret")
            or module.params.get("client_secret")
            or os.getenv("ZSCALER_CLIENT_SECRET")
        )
        private_key = (
            provider.get("private_key")
            or module.params.get("private_key")
            or os.getenv("ZSCALER_PRIVATE_KEY")
        )
        vanity_domain = (
            provider.get("vanity_domain")
            or module.params.get("vanity_domain")
            or os.getenv("ZSCALER_VANITY_DOMAIN")
        )
        cloud_env = (
            provider.get("cloud")
            or module.params.get("cloud")
            or os.getenv("ZSCALER_CLOUD")
        )
        sandbox_token = (
            provider.get("sandbox_token")
            or module.params.get("sandbox_token")
            or os.getenv("ZSCALER_SANDBOX_TOKEN")
        )
        sandbox_cloud = (
            provider.get("sandbox_cloud")
            or module.params.get("sandbox_cloud")
            or os.getenv("ZSCALER_SANDBOX_CLOUD")
        )

        # Sandbox-only authentication
        if sandbox_token and sandbox_cloud and not client_id and not client_secret and not private_key:
            config = {
                "sandbox_token": sandbox_token,
                "sandbox_cloud": sandbox_cloud,
                "logging": {"enabled": True, "verbose": False},
            }
            return OneAPIClient(config)

        # Validate required parameters for OAuth2
        if not vanity_domain:
            module.fail_json(msg="vanity_domain is required for OneAPI authentication")

        if not (client_id and (client_secret or private_key)):
            module.fail_json(msg="client_id with either client_secret or private_key is required for OneAPI authentication")

        # Build config dictionary
        config = {
            "clientId": client_id,
            "vanityDomain": vanity_domain,
            "logging": {"enabled": True, "verbose": False},
        }

        if client_secret:
            config["clientSecret"] = client_secret
        elif private_key:
            config["privateKey"] = private_key

        if cloud_env:
            config["cloud"] = cloud_env.lower()

        if sandbox_token:
            config["sandbox_token"] = sandbox_token
        if sandbox_cloud:
            config["sandbox_cloud"] = sandbox_cloud

        return OneAPIClient(config)

    @staticmethod
    def zia_argument_spec():
        """Return the argument specification for both legacy and OneAPI authentication"""
        return dict(
            provider=dict(
                type="dict",
                options=dict(
                    # Legacy authentication parameters
                    username=dict(
                        no_log=False,
                        required=False,
                        fallback=(env_fallback, ["ZIA_USERNAME"]),
                        type="str",
                    ),
                    password=dict(
                        no_log=True,
                        required=False,
                        fallback=(env_fallback, ["ZIA_PASSWORD"]),
                        type="str",
                    ),
                    api_key=dict(
                        no_log=True,
                        required=False,
                        fallback=(env_fallback, ["ZIA_API_KEY"]),
                        type="str",
                    ),
                    cloud=dict(
                        no_log=False,
                        required=False,
                        fallback=(env_fallback, ["ZIA_CLOUD", "ZSCALER_CLOUD"]),
                        type="str",
                    ),
                    sandbox_token=dict(
                        no_log=True,
                        required=False,
                        fallback=(env_fallback, ["ZIA_SANDBOX_TOKEN", "ZSCALER_SANDBOX_TOKEN"]),
                        type="str",
                    ),
                    sandbox_cloud=dict(
                        no_log=False,
                        required=False,
                        fallback=(env_fallback, ["ZSCALER_SANDBOX_CLOUD"]),
                        type="str",
                    ),
                    # OneAPI authentication parameters
                    client_id=dict(
                        no_log=True,
                        required=False,
                        fallback=(env_fallback, ["ZSCALER_CLIENT_ID"]),
                        type="str",
                    ),
                    client_secret=dict(
                        no_log=True,
                        required=False,
                        fallback=(env_fallback, ["ZSCALER_CLIENT_SECRET"]),
                        type="str",
                    ),
                    private_key=dict(
                        no_log=True,
                        required=False,
                        fallback=(env_fallback, ["ZSCALER_PRIVATE_KEY"]),
                        type="str",
                    ),
                    vanity_domain=dict(
                        no_log=False,
                        required=False,
                        fallback=(env_fallback, ["ZSCALER_VANITY_DOMAIN"]),
                        type="str",
                    ),
                    # Client selection flag
                    use_legacy_client=dict(
                        type="bool",
                        required=False,
                        default=False,
                        fallback=(env_fallback, ["ZSCALER_USE_LEGACY_CLIENT"]),
                    ),
                ),
            ),
            # Top-level parameters (same as provider options)
            username=dict(
                no_log=True,
                required=False,
                fallback=(env_fallback, ["ZIA_USERNAME"]),
                type="str",
            ),
            password=dict(
                no_log=True,
                required=False,
                fallback=(env_fallback, ["ZIA_PASSWORD"]),
                type="str",
            ),
            api_key=dict(
                no_log=True,
                required=False,
                fallback=(env_fallback, ["ZIA_API_KEY"]),
                type="str",
            ),
            cloud=dict(
                no_log=False,
                required=False,
                fallback=(env_fallback, ["ZIA_CLOUD", "ZSCALER_CLOUD"]),
                type="str",
            ),
            sandbox_token=dict(
                no_log=True,
                required=False,
                fallback=(env_fallback, ["ZIA_SANDBOX_TOKEN", "ZSCALER_SANDBOX_TOKEN"]),
                type="str",
            ),
            sandbox_cloud=dict(
                no_log=False,
                required=False,
                fallback=(env_fallback, ["ZSCALER_SANDBOX_CLOUD"]),
                type="str",
            ),
            client_id=dict(
                no_log=True,
                required=False,
                fallback=(env_fallback, ["ZSCALER_CLIENT_ID"]),
                type="str",
            ),
            client_secret=dict(
                no_log=True,
                required=False,
                fallback=(env_fallback, ["ZSCALER_CLIENT_SECRET"]),
                type="str",
            ),
            private_key=dict(
                no_log=True,
                required=False,
                fallback=(env_fallback, ["ZSCALER_PRIVATE_KEY"]),
                type="str",
            ),
            vanity_domain=dict(
                no_log=False,
                required=False,
                fallback=(env_fallback, ["ZSCALER_VANITY_DOMAIN"]),
                type="str",
            ),
            use_legacy_client=dict(
                type="bool",
                required=False,
                default=False,
                fallback=(env_fallback, ["ZSCALER_USE_LEGACY_CLIENT"]),
            ),
        )

# import os
# import platform
# from ansible.module_utils.basic import missing_required_lib, env_fallback
# from ansible.module_utils import ansible_release

# # Initialize import error variables
# ZSCALER_IMPORT_ERROR = None
# VERSION_IMPORT_ERROR = None

# try:
#     from zscaler.zia import ZIAClientHelper as ZIA

#     HAS_ZSCALER = True
# except ImportError as e:
#     ZIA = object  # Default to object if import fails
#     HAS_ZSCALER = False
#     ZSCALER_IMPORT_ERROR = missing_required_lib("zscaler")

# try:
#     from ansible_collections.zscaler.ziacloud.plugins.module_utils.version import (
#         __version__ as ansible_collection_version,
#     )

#     HAS_VERSION = True
# except ImportError as e:
#     HAS_VERSION = False
#     VERSION_IMPORT_ERROR = missing_required_lib(
#         "plugins.module_utils.version (version information)"
#     )

# VALID_ZIA_CLOUD = {
#     "zscaler",
#     "zscloud",
#     "zscalerbeta",
#     "zspreview",
#     "zscalerone",
#     "zscalertwo",
#     "zscalerthree",
#     "zscalergov",
#     "zscalerten",
# }


# class ConnectionHelper:
#     def __init__(self, min_sdk_version):
#         if not HAS_ZSCALER:
#             raise ImportError(ZSCALER_IMPORT_ERROR)

#         self.min_sdk_version = min_sdk_version
#         self.check_sdk_installed()

#     def check_sdk_installed(self):
#         import zscaler

#         installed_version = tuple(map(int, zscaler.__version__.split(".")))
#         if installed_version < self.min_sdk_version:
#             raise Exception(
#                 f"zscaler version should be >= {'.'.join(map(str, self.min_sdk_version))}"
#             )


# class ZIAClientHelper(ZIA):
#     def __init__(self, module):
#         if not HAS_ZSCALER:
#             module.fail_json(
#                 msg="The 'zscaler' library is required for this module.",
#                 exception=ZSCALER_IMPORT_ERROR,
#             )
#         if not HAS_VERSION:
#             module.fail_json(
#                 msg="Failed to import the version from the collection's module_utils.",
#                 exception=VERSION_IMPORT_ERROR,
#             )

#         # Initialize provider to an empty dict if None
#         provider = module.params.get("provider") or {}

#         # Use provider or environment variables
#         username = (
#             provider.get("username")
#             or module.params.get("username")
#             or os.getenv("ZIA_USERNAME")
#         )
#         password = (
#             provider.get("password")
#             or module.params.get("password")
#             or os.getenv("ZIA_PASSWORD")
#         )
#         api_key = (
#             provider.get("api_key")
#             or module.params.get("api_key")
#             or os.getenv("ZIA_API_KEY")
#         )
#         cloud_env = (
#             provider.get("cloud")
#             or module.params.get("cloud")
#             or os.getenv("ZIA_CLOUD")
#         )

#         if not all([username, password, api_key, cloud_env]):
#             module.fail_json(msg="All authentication parameters must be provided.")

#         cloud_env = cloud_env.lower()
#         if cloud_env not in VALID_ZIA_CLOUD:
#             module.fail_json(msg=f"Invalid ZIA Cloud environment '{cloud_env}'.")

#         super().__init__(
#             username=username, password=password, api_key=api_key, cloud=cloud_env
#         )

#         ansible_version = ansible_release.__version__
#         self.user_agent = f"ziacloud-ansible/{ansible_version} (collection/{ansible_collection_version}) ({platform.system().lower()} {platform.machine()})"

#     @staticmethod
#     def zia_argument_spec():
#         return dict(
#             provider=dict(
#                 type="dict",
#                 options=dict(
#                     username=dict(
#                         no_log=False,
#                         required=False,
#                         fallback=(env_fallback, ["ZIA_USERNAME"]),
#                         type="str",
#                     ),
#                     password=dict(
#                         no_log=True,
#                         required=False,
#                         fallback=(env_fallback, ["ZIA_PASSWORD"]),
#                         type="str",
#                     ),
#                     api_key=dict(
#                         no_log=True,
#                         required=False,
#                         fallback=(env_fallback, ["ZIA_API_KEY"]),
#                         type="str",
#                     ),
#                     cloud=dict(
#                         no_log=False,
#                         required=False,
#                         choices=[
#                             "zscloud",
#                             "zscaler",
#                             "zscalerone",
#                             "zscalertwo",
#                             "zscalerthree",
#                             "zscalerbeta",
#                             "zscalergov",
#                             "zscalerten",
#                         ],
#                         fallback=(env_fallback, ["ZIA_CLOUD"]),
#                         type="str",
#                     ),
#                     sandbox_token=dict(
#                         no_log=True,
#                         required=False,
#                         fallback=(env_fallback, ["ZIA_SANDBOX_TOKEN"]),
#                         type="str",
#                     ),
#                 ),
#             ),
#             username=dict(
#                 no_log=True,
#                 required=False,
#                 fallback=(env_fallback, ["ZIA_USERNAME"]),
#                 type="str",
#             ),
#             password=dict(
#                 no_log=True,
#                 required=False,
#                 fallback=(env_fallback, ["ZIA_PASSWORD"]),
#                 type="str",
#             ),
#             api_key=dict(
#                 no_log=True,
#                 required=False,
#                 fallback=(env_fallback, ["ZIA_API_KEY"]),
#                 type="str",
#             ),
#             cloud=dict(
#                 no_log=False,
#                 required=False,
#                 choices=[
#                     "zscloud",
#                     "zscaler",
#                     "zscalerone",
#                     "zscalertwo",
#                     "zscalerthree",
#                     "zscalerbeta",
#                     "zscalergov",
#                     "zscalerten",
#                 ],
#                 fallback=(env_fallback, ["ZIA_CLOUD"]),
#                 type="str",
#             ),
#             sandbox_token=dict(
#                 no_log=True,
#                 required=False,
#                 fallback=(env_fallback, ["ZIA_SANDBOX_TOKEN"]),
#                 type="str",
#             ),
#         )
