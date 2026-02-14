# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 Zscaler Inc, <devrel@zscaler.com>
# MIT License

from __future__ import absolute_import, division, print_function
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)
from tests.unit.plugins.modules.common.utils import (
    set_module_args,
    AnsibleExitJson,
    AnsibleFailJson,
    ModuleTestCase,
    DEFAULT_PROVIDER,
)
from unittest.mock import MagicMock, patch
import pytest

__metaclass__ = type

import sys
import os

COLLECTION_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
if COLLECTION_ROOT not in sys.path:
    sys.path.insert(0, COLLECTION_ROOT)


REAL_ARGUMENT_SPEC = ZIAClientHelper.zia_argument_spec()


class MockBox:
    """Mock Box object to simulate SDK responses"""

    def __init__(self, data):
        self._data = data

    def as_dict(self):
        return self._data

    def __getattr__(self, name):
        return self._data.get(name)


class TestZIAActivationStatusInfoModule(ModuleTestCase):
    """Unit tests for zia_activation_status_info module."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock ZIA client that preserves argument_spec"""
        with patch("ansible_collections.zscaler.ziacloud.plugins.modules.zia_activation_status_info.ZIAClientHelper") as mock_class:
            base_spec = REAL_ARGUMENT_SPEC.copy()
            base_spec.update(status=dict(type="str", required=False))
            mock_class.zia_argument_spec.return_value = base_spec
            client_instance = MagicMock()
            mock_class.return_value = client_instance
            yield client_instance

    def test_get_activation_status(self, mock_client):
        """Test fetching activation status."""
        mock_status = MockBox({"status": "ACTIVE"})
        mock_client.activate.status.return_value = (mock_status, None, None)

        set_module_args(provider=DEFAULT_PROVIDER)

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_activation_status_info,
        )

        with pytest.raises(AnsibleExitJson) as result:
            zia_activation_status_info.main()

        mock_client.activate.status.assert_called_once()
        assert result.value.result["changed"] is False
        assert result.value.result["current_activation_status"]["status"] == "ACTIVE"

    def test_get_status_with_filter_match(self, mock_client):
        """Test fetching status when provided status matches."""
        mock_status = MockBox({"status": "ACTIVE"})
        mock_client.activate.status.return_value = (mock_status, None, None)

        set_module_args(provider=DEFAULT_PROVIDER, status="ACTIVE")

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_activation_status_info,
        )

        with pytest.raises(AnsibleExitJson) as result:
            zia_activation_status_info.main()

        assert result.value.result["status_matches"] is True

    def test_get_status_with_filter_no_match(self, mock_client):
        """Test fetching status when provided status does not match."""
        mock_status = MockBox({"status": "PENDING"})
        mock_client.activate.status.return_value = (mock_status, None, None)

        set_module_args(provider=DEFAULT_PROVIDER, status="ACTIVE")

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_activation_status_info,
        )

        with pytest.raises(AnsibleExitJson) as result:
            zia_activation_status_info.main()

        assert result.value.result["status_matches"] is False
        assert "does not match" in result.value.result["msg"]

    def test_api_error_on_status(self, mock_client):
        """Test handling API error when getting status."""
        mock_client.activate.status.return_value = (None, None, "API Error")

        set_module_args(provider=DEFAULT_PROVIDER)

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_activation_status_info,
        )

        with pytest.raises(AnsibleFailJson) as result:
            zia_activation_status_info.main()

        assert "Failed to get activation status" in result.value.result["msg"]
