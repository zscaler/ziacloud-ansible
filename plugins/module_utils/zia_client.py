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
    VERSION_IMPORT_ERROR = missing_required_lib("plugins.module_utils.version (version information)")

# =============================================================================
# Authentication Modes (mutually exclusive)
# =============================================================================
#
# 1. LEGACY API MODE
#    - use_legacy_client=true (required)
#    - Parameters: username, password, api_key, cloud (ALL required)
#    - ZIA_CLOUD env var; cloud is ALWAYS required
#    - Valid cloud values: zscloud, zscaler, zscalerbeta, zspreview, zscalerone,
#      zscalertwo, zscalerthree, zscalergov, zscalerten
#    - use_legacy_client MUST NOT be set when using OneAPI parameters
#
# 2. OneAPI MODE (default)
#    - use_legacy_client=false or omitted
#    - Parameters: client_id + (client_secret OR private_key) + vanity_domain
#    - Cloud: optional (ZSCALER_CLOUD); only beta or production
#    - For production, omit cloud or set to "production"
#
# 3. SANDBOX MODE (separate from Legacy and OneAPI)
#    - sandbox_token + sandbox_cloud
#    - No client_id, no legacy params
#
# =============================================================================

# Legacy API: ZIA_CLOUD values (identify endpoint e.g. zsapi.zscalerone.net)
VALID_ZIA_CLOUD = frozenset(
    {
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
)

# OneAPI: ZSCALER_CLOUD values only
VALID_ZSCALER_CLOUD = frozenset({"beta", "production"})

# Combined for argument_spec choices (cloud param shared by both modes)
CLOUD_CHOICES = sorted(VALID_ZIA_CLOUD | VALID_ZSCALER_CLOUD)


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

        provider = module.params.get("provider") or {}
        use_legacy_client = self._resolve_use_legacy_client(provider, module)

        # Sandbox mode: sandbox_token + sandbox_cloud, no Legacy/OneAPI params
        if self._is_sandbox_mode(provider, module):
            self._client = self._init_sandbox_client(module, provider)
        elif use_legacy_client:
            self._validate_no_oneapi_params_with_legacy(provider, module)
            self._client = self._init_legacy_client(module, provider)
        else:
            self._validate_legacy_params_require_use_legacy_client(provider, module)
            self._client = self._init_oneapi_client(module, provider)

        ansible_version = ansible_release.__version__
        self.user_agent = f"ziacloud-ansible/{ansible_version} (collection/{ansible_collection_version}) ({platform.system().lower()} {platform.machine()})"

    @staticmethod
    def _resolve_use_legacy_client(provider, module):
        """Resolve use_legacy_client from provider, module params, or env."""
        val = provider.get("use_legacy_client") or module.params.get("use_legacy_client")
        if val is not None:
            return bool(val)
        return os.getenv("ZSCALER_USE_LEGACY_CLIENT", "").lower() == "true"

    @staticmethod
    def _is_sandbox_mode(provider, module):
        """Sandbox mode: sandbox_token + sandbox_cloud, no Legacy/OneAPI creds."""
        sandbox_token = provider.get("sandbox_token") or module.params.get("sandbox_token") or os.getenv("ZSCALER_SANDBOX_TOKEN")
        sandbox_cloud = provider.get("sandbox_cloud") or module.params.get("sandbox_cloud") or os.getenv("ZSCALER_SANDBOX_CLOUD")
        has_legacy = any(
            provider.get(k) or module.params.get(k) or os.getenv(env)
            for k, env in [
                ("username", "ZIA_USERNAME"),
                ("password", "ZIA_PASSWORD"),
                ("api_key", "ZIA_API_KEY"),
            ]
        )
        has_oneapi = any(
            provider.get(k) or module.params.get(k) or os.getenv(env)
            for k, env in [
                ("client_id", "ZSCALER_CLIENT_ID"),
                ("client_secret", "ZSCALER_CLIENT_SECRET"),
                ("private_key", "ZSCALER_PRIVATE_KEY"),
                ("vanity_domain", "ZSCALER_VANITY_DOMAIN"),
            ]
        )
        return sandbox_token and sandbox_cloud and not has_legacy and not has_oneapi

    def _validate_legacy_params_require_use_legacy_client(self, provider, module):
        """When Legacy params are provided without use_legacy_client, fail with clear guidance."""
        params = self._resolve_legacy_params(provider, module)
        has_all_legacy = all([params["username"], params["password"], params["api_key"], params["cloud"]])
        if has_all_legacy:
            module.fail_json(
                msg="You appear to be using Legacy API parameters (username, password, api_key, cloud). "
                "For Legacy authentication, set use_legacy_client=true in the provider or ZSCALER_USE_LEGACY_CLIENT=true as an environment variable."
            )

    def _validate_no_oneapi_params_with_legacy(self, provider, module):
        """use_legacy_client MUST NOT be set when using OneAPI parameters."""
        has_oneapi = (
            (provider.get("vanity_domain") or module.params.get("vanity_domain") or os.getenv("ZSCALER_VANITY_DOMAIN"))
            and (provider.get("client_id") or module.params.get("client_id") or os.getenv("ZSCALER_CLIENT_ID"))
            and (
                (provider.get("client_secret") or module.params.get("client_secret") or os.getenv("ZSCALER_CLIENT_SECRET"))
                or (provider.get("private_key") or module.params.get("private_key") or os.getenv("ZSCALER_PRIVATE_KEY"))
            )
        )
        if has_oneapi:
            module.fail_json(
                msg="Cannot use use_legacy_client=true with OneAPI parameters (client_id, vanity_domain, client_secret or private_key). "
                "Use use_legacy_client=false for OneAPI mode, or provide only Legacy parameters (username, password, api_key, cloud) for Legacy mode."
            )

    def __getattr__(self, name):
        """Delegate attribute access to the underlying client's zia service"""
        try:
            # First try to get the attribute from the client's zia service
            return getattr(self._client.zia, name)
        except AttributeError:
            # If not found in zia service, try the client directly
            return getattr(self._client, name)

    def _init_sandbox_client(self, module, provider):
        """Sandbox mode: sandbox_token + sandbox_cloud (separate from Legacy/OneAPI)."""
        sandbox_token = provider.get("sandbox_token") or module.params.get("sandbox_token") or os.getenv("ZSCALER_SANDBOX_TOKEN")
        sandbox_cloud = provider.get("sandbox_cloud") or module.params.get("sandbox_cloud") or os.getenv("ZSCALER_SANDBOX_CLOUD")
        config = {
            "sandbox_token": sandbox_token,
            "sandbox_cloud": sandbox_cloud,
            "logging": {"enabled": True, "verbose": False},
        }
        return OneAPIClient(config)

    @staticmethod
    def _resolve_legacy_params(provider, module):
        """Resolve Legacy API params: username, password, api_key, cloud (ZIA_CLOUD)."""
        return {
            "username": provider.get("username") or module.params.get("username") or os.getenv("ZIA_USERNAME"),
            "password": provider.get("password") or module.params.get("password") or os.getenv("ZIA_PASSWORD"),
            "api_key": provider.get("api_key") or module.params.get("api_key") or os.getenv("ZIA_API_KEY"),
            "cloud": provider.get("cloud") or os.getenv("ZIA_CLOUD") or module.params.get("cloud"),
        }

    def _init_legacy_client(self, module, provider):
        """Legacy API mode: username, password, api_key, cloud (all required). use_legacy_client=true."""
        params = self._resolve_legacy_params(provider, module)
        username, password, api_key, cloud_env = params["username"], params["password"], params["api_key"], params["cloud"]

        if not all([username, password, api_key, cloud_env]):
            module.fail_json(
                msg="All legacy authentication parameters must be provided (username, password, api_key, cloud). "
                "Use ZIA_CLOUD env var or provider cloud (e.g. zscalerone, zscalertwo, zscalergov)."
            )

        cloud_env = cloud_env.lower()
        if cloud_env not in VALID_ZIA_CLOUD:
            module.fail_json(
                msg=f"Invalid cloud '{cloud_env}' for Legacy client. "
                f"Valid values: {', '.join(sorted(VALID_ZIA_CLOUD))}. "
                "Use use_legacy_client=true with ZIA_CLOUD."
            )

        config = {
            "username": username,
            "password": password,
            "api_key": api_key,
            "cloud": cloud_env,
        }

        return LegacyZIAClient(config)

    @staticmethod
    def _resolve_oneapi_params(provider, module):
        """Resolve OneAPI params and optional sandbox. Cloud uses ZSCALER_CLOUD."""
        return {
            "client_id": provider.get("client_id") or module.params.get("client_id") or os.getenv("ZSCALER_CLIENT_ID"),
            "client_secret": provider.get("client_secret") or module.params.get("client_secret") or os.getenv("ZSCALER_CLIENT_SECRET"),
            "private_key": provider.get("private_key") or module.params.get("private_key") or os.getenv("ZSCALER_PRIVATE_KEY"),
            "vanity_domain": provider.get("vanity_domain") or module.params.get("vanity_domain") or os.getenv("ZSCALER_VANITY_DOMAIN"),
            "cloud": provider.get("cloud") or os.getenv("ZSCALER_CLOUD") or module.params.get("cloud"),
            "sandbox_token": provider.get("sandbox_token") or module.params.get("sandbox_token") or os.getenv("ZSCALER_SANDBOX_TOKEN"),
            "sandbox_cloud": provider.get("sandbox_cloud") or module.params.get("sandbox_cloud") or os.getenv("ZSCALER_SANDBOX_CLOUD"),
        }

    def _init_oneapi_client(self, module, provider):
        """OneAPI mode: client_id + (client_secret OR private_key) + vanity_domain. Cloud optional."""
        p = self._resolve_oneapi_params(provider, module)
        client_id, client_secret, private_key = p["client_id"], p["client_secret"], p["private_key"]
        vanity_domain, cloud_env = p["vanity_domain"], p["cloud"]
        sandbox_token, sandbox_cloud = p["sandbox_token"], p["sandbox_cloud"]

        # Validate required OneAPI parameters
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

        # OneAPI cloud: optional. Only "beta" is passed; production is default.
        # Ignore Legacy names (zscalerone, zscalertwo, etc.) - they would break the URL.
        if cloud_env:
            cloud_lower = cloud_env.lower()
            if cloud_lower == "beta":
                config["cloud"] = "beta"
            elif cloud_lower == "production" or cloud_lower in VALID_ZIA_CLOUD:
                # Production (explicit or Legacy name): omit - SDK defaults to production
                pass
            else:
                module.fail_json(
                    msg=f"Invalid cloud '{cloud_env}' for OneAPI. "
                    "Only 'beta' (for beta environment) or 'production' (default, optional) are supported. "
                    "Legacy cloud names (zscalerone, zscalertwo, zscalergov, etc.) require use_legacy_client=true. "
                    "For production, omit the cloud parameter or set to 'production'."
                )

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
                        choices=CLOUD_CHOICES,
                    ),
                    sandbox_token=dict(
                        no_log=True,
                        required=False,
                        fallback=(
                            env_fallback,
                            ["ZIA_SANDBOX_TOKEN", "ZSCALER_SANDBOX_TOKEN"],
                        ),
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
                choices=CLOUD_CHOICES,
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
