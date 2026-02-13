# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 Zscaler Inc, <devrel@zscaler.com>
# MIT License

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import sys
import os

COLLECTION_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")
)
if COLLECTION_ROOT not in sys.path:
    sys.path.insert(0, COLLECTION_ROOT)

import pytest
from unittest.mock import MagicMock, patch


class TestZIAClientHelper:
    """Unit tests for ZIAClientHelper in zia_client.py"""

    def test_zia_argument_spec_returns_dict(self):
        """Test that zia_argument_spec returns a valid argument spec dict."""
        from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
            ZIAClientHelper,
        )

        spec = ZIAClientHelper.zia_argument_spec()
        assert isinstance(spec, dict)
        assert "provider" in spec
        assert "username" in spec
        assert "password" in spec
        assert "api_key" in spec
        assert "cloud" in spec
        assert "client_id" in spec
        assert "client_secret" in spec
        assert "vanity_domain" in spec

    def test_legacy_client_missing_required_params_fails(self):
        """Test that legacy client fails when required params (username, password, api_key, cloud) are missing."""
        with patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.HAS_ZSCALER",
            True,
        ), patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.HAS_VERSION",
            True,
        ):
            from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
                ZIAClientHelper,
            )

            module = MagicMock()
            module.params = {"provider": {"use_legacy_client": True}}
            module.fail_json.side_effect = Exception("fail_json called")

            with pytest.raises(Exception, match="fail_json called"):
                ZIAClientHelper(module)

            module.fail_json.assert_called_once()
            call_msg = module.fail_json.call_args[1]["msg"]
            assert "legacy authentication" in call_msg.lower()

    def test_legacy_client_with_all_params_instantiates(self):
        """Test that legacy client is instantiated when all required params provided."""
        mock_legacy_client = MagicMock()
        with patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.HAS_ZSCALER",
            True,
        ), patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.HAS_VERSION",
            True,
        ), patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.LegacyZIAClient",
            return_value=mock_legacy_client,
        ):
            from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
                ZIAClientHelper,
            )

            module = MagicMock()
            module.params = {
                "provider": {
                    "use_legacy_client": True,
                    "username": "user",
                    "password": "pass",
                    "api_key": "key",
                    "cloud": "zscaler",
                },
            }

            helper = ZIAClientHelper(module)

            assert helper._client == mock_legacy_client

    def test_oneapi_client_missing_vanity_domain_fails(self):
        """Test that OneAPI client fails when vanity_domain is missing."""
        with patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.HAS_ZSCALER",
            True,
        ), patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.HAS_VERSION",
            True,
        ):
            from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
                ZIAClientHelper,
            )

            module = MagicMock()
            module.params = {
                "provider": {
                    "use_legacy_client": False,
                    "client_id": "cid",
                    "client_secret": "csecret",
                },
            }
            module.fail_json.side_effect = Exception("fail_json called")

            with pytest.raises(Exception, match="fail_json called"):
                ZIAClientHelper(module)

            module.fail_json.assert_called_once()
            call_msg = module.fail_json.call_args[1]["msg"]
            assert "vanity_domain" in call_msg.lower()

    def test_oneapi_client_missing_client_creds_fails(self):
        """Test that OneAPI client fails when client_id and client_secret/private_key are missing."""
        with patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.HAS_ZSCALER",
            True,
        ), patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.HAS_VERSION",
            True,
        ):
            from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
                ZIAClientHelper,
            )

            module = MagicMock()
            module.params = {
                "provider": {
                    "use_legacy_client": False,
                    "vanity_domain": "test.zscaler.net",
                },
            }
            module.fail_json.side_effect = Exception("fail_json called")

            with pytest.raises(Exception, match="fail_json called"):
                ZIAClientHelper(module)

            module.fail_json.assert_called_once()
            call_msg = module.fail_json.call_args[1]["msg"]
            assert "client_id" in call_msg.lower()

    def test_oneapi_client_with_valid_params_instantiates(self):
        """Test that OneAPI client is instantiated with valid params."""
        mock_oneapi_client = MagicMock()
        mock_oneapi_client.zia = MagicMock()

        with patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.HAS_ZSCALER",
            True,
        ), patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.HAS_VERSION",
            True,
        ), patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.OneAPIClient",
            return_value=mock_oneapi_client,
        ):
            from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
                ZIAClientHelper,
            )

            module = MagicMock()
            module.params = {
                "provider": {
                    "use_legacy_client": False,
                    "vanity_domain": "test.zscaler.net",
                    "client_id": "cid",
                    "client_secret": "csecret",
                },
            }

            helper = ZIAClientHelper(module)

            assert helper._client == mock_oneapi_client

    def test_env_var_use_legacy_client(self):
        """Test that ZSCALER_USE_LEGACY_CLIENT env var is respected."""
        mock_legacy_client = MagicMock()
        with patch.dict(
            os.environ, {"ZSCALER_USE_LEGACY_CLIENT": "true"}, clear=False
        ), patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.HAS_ZSCALER",
            True,
        ), patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.HAS_VERSION",
            True,
        ), patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.LegacyZIAClient",
            return_value=mock_legacy_client,
        ):
            from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
                ZIAClientHelper,
            )

            module = MagicMock()
            module.params = {
                "provider": {
                    "username": "u",
                    "password": "p",
                    "api_key": "k",
                    "cloud": "zscaler",
                },
            }

            helper = ZIAClientHelper(module)

            assert helper._client == mock_legacy_client

    def test_provider_none_uses_empty_dict(self):
        """Test that None provider is treated as empty dict."""
        mock_legacy_client = MagicMock()
        with patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.HAS_ZSCALER",
            True,
        ), patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.HAS_VERSION",
            True,
        ), patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.LegacyZIAClient",
            return_value=mock_legacy_client,
        ):
            from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
                ZIAClientHelper,
            )

            module = MagicMock()
            module.params = {
                "provider": None,
                "use_legacy_client": True,
                "username": "u",
                "password": "p",
                "api_key": "k",
                "cloud": "zscaler",
            }

            helper = ZIAClientHelper(module)

            assert helper._client == mock_legacy_client

    def test_oneapi_client_with_private_key_instantiates(self):
        """Test OneAPI client with private_key instead of client_secret."""
        mock_oneapi_client = MagicMock()
        mock_oneapi_client.zia = MagicMock()
        with patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.HAS_ZSCALER",
            True,
        ), patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.HAS_VERSION",
            True,
        ), patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.OneAPIClient",
            return_value=mock_oneapi_client,
        ):
            from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
                ZIAClientHelper,
            )

            module = MagicMock()
            module.params = {
                "provider": {
                    "use_legacy_client": False,
                    "vanity_domain": "test.zscaler.net",
                    "client_id": "cid",
                    "private_key": "-----BEGIN RSA PRIVATE KEY-----",
                },
            }
            helper = ZIAClientHelper(module)
            assert helper._client == mock_oneapi_client

    def test_sandbox_only_auth_instantiates(self):
        """Test sandbox-only authentication (no client_id)."""
        mock_oneapi_client = MagicMock()
        mock_oneapi_client.zia = MagicMock()
        with patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.HAS_ZSCALER",
            True,
        ), patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.HAS_VERSION",
            True,
        ), patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.OneAPIClient",
            return_value=mock_oneapi_client,
        ):
            from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
                ZIAClientHelper,
            )

            module = MagicMock()
            module.params = {
                "provider": {"sandbox_token": "token", "sandbox_cloud": "cloud"},
            }
            helper = ZIAClientHelper(module)
            assert helper._client == mock_oneapi_client

    def test_legacy_invalid_cloud_from_env_fails(self):
        """Test legacy client fails with invalid cloud when ZIA_CLOUD is set."""
        with patch.dict(os.environ, {"ZIA_CLOUD": "invalid"}, clear=False), patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.HAS_ZSCALER",
            True,
        ), patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.HAS_VERSION",
            True,
        ):
            from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
                ZIAClientHelper,
            )

            module = MagicMock()
            module.params = {
                "provider": {
                    "use_legacy_client": True,
                    "username": "u",
                    "password": "p",
                    "api_key": "k",
                    "cloud": "invalid",
                },
            }
            module.fail_json.side_effect = Exception("fail_json called")
            with pytest.raises(Exception, match="fail_json called"):
                ZIAClientHelper(module)
            assert "Invalid" in module.fail_json.call_args[1]["msg"]

    def test_oneapi_cloud_beta_passed_to_config(self):
        """Test OneAPI passes cloud=beta to SDK when explicitly set."""
        mock_oneapi_client = MagicMock()
        mock_oneapi_client.zia = MagicMock()
        with patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.HAS_ZSCALER",
            True,
        ), patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.HAS_VERSION",
            True,
        ), patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.OneAPIClient",
            return_value=mock_oneapi_client,
        ) as mock_oneapi_class:
            from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
                ZIAClientHelper,
            )

            module = MagicMock()
            module.params = {
                "provider": {
                    "use_legacy_client": False,
                    "vanity_domain": "test.zscaler.net",
                    "client_id": "cid",
                    "client_secret": "csecret",
                    "cloud": "beta",
                },
            }

            ZIAClientHelper(module)
            call_config = mock_oneapi_class.call_args[0][0]
            assert call_config.get("cloud") == "beta"

    def test_oneapi_cloud_zscalertwo_ignored(self):
        """Test OneAPI ignores Legacy cloud names (zscalertwo) to avoid URL breakage."""
        mock_oneapi_client = MagicMock()
        mock_oneapi_client.zia = MagicMock()
        with patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.HAS_ZSCALER",
            True,
        ), patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.HAS_VERSION",
            True,
        ), patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.OneAPIClient",
            return_value=mock_oneapi_client,
        ) as mock_oneapi_class:
            from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
                ZIAClientHelper,
            )

            module = MagicMock()
            module.params = {
                "provider": {
                    "use_legacy_client": False,
                    "vanity_domain": "test.zscaler.net",
                    "client_id": "cid",
                    "client_secret": "csecret",
                    "cloud": "zscalertwo",
                },
            }

            ZIAClientHelper(module)
            call_config = mock_oneapi_class.call_args[0][0]
            assert "cloud" not in call_config

    def test_oneapi_cloud_invalid_fails(self):
        """Test OneAPI fails with clear message when cloud has invalid value."""
        with patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.HAS_ZSCALER",
            True,
        ), patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.HAS_VERSION",
            True,
        ):
            from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
                ZIAClientHelper,
            )

            module = MagicMock()
            module.params = {
                "provider": {
                    "use_legacy_client": False,
                    "vanity_domain": "test.zscaler.net",
                    "client_id": "cid",
                    "client_secret": "csecret",
                    "cloud": "invalid",
                },
            }
            module.fail_json.side_effect = Exception("fail_json called")

            with pytest.raises(Exception, match="fail_json called"):
                ZIAClientHelper(module)
            call_msg = module.fail_json.call_args[1]["msg"]
            assert "beta" in call_msg.lower()
            assert "production" in call_msg.lower()

    def test_legacy_client_with_oneapi_params_fails(self):
        """Test that use_legacy_client=true with OneAPI params fails (mutually exclusive)."""
        with patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.HAS_ZSCALER",
            True,
        ), patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.HAS_VERSION",
            True,
        ):
            from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
                ZIAClientHelper,
            )

            module = MagicMock()
            module.params = {
                "provider": {
                    "use_legacy_client": True,
                    "username": "u",
                    "password": "p",
                    "api_key": "k",
                    "cloud": "zscaler",
                    "vanity_domain": "test.zscaler.net",
                    "client_id": "cid",
                    "client_secret": "csecret",
                },
            }
            module.fail_json.side_effect = Exception("fail_json called")

            with pytest.raises(Exception, match="fail_json called"):
                ZIAClientHelper(module)
            call_msg = module.fail_json.call_args[1]["msg"]
            assert "use_legacy_client" in call_msg.lower()
            assert "OneAPI" in call_msg

    def test_legacy_params_without_use_legacy_client_fails(self):
        """Test that Legacy params without use_legacy_client fail with helpful message."""
        with patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.HAS_ZSCALER",
            True,
        ), patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.HAS_VERSION",
            True,
        ):
            from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
                ZIAClientHelper,
            )

            module = MagicMock()
            module.params = {
                "provider": {
                    "use_legacy_client": False,
                    "username": "u",
                    "password": "p",
                    "api_key": "k",
                    "cloud": "zscaler",
                },
            }
            module.fail_json.side_effect = Exception("fail_json called")

            with pytest.raises(Exception, match="fail_json called"):
                ZIAClientHelper(module)
            call_msg = module.fail_json.call_args[1]["msg"]
            assert "Legacy API" in call_msg
            assert "use_legacy_client" in call_msg.lower()

    def test_getattr_delegates_to_zia(self):
        """Test __getattr__ delegates to client.zia first."""
        mock_legacy_client = MagicMock()
        mock_legacy_client.zia.sandbox = MagicMock()
        with patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.HAS_ZSCALER",
            True,
        ), patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.HAS_VERSION",
            True,
        ), patch(
            "ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.LegacyZIAClient",
            return_value=mock_legacy_client,
        ):
            from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
                ZIAClientHelper,
            )

            module = MagicMock()
            module.params = {
                "provider": {
                    "use_legacy_client": True,
                    "username": "u",
                    "password": "p",
                    "api_key": "k",
                    "cloud": "zscaler",
                },
            }
            helper = ZIAClientHelper(module)
            assert helper.sandbox == mock_legacy_client.zia.sandbox
