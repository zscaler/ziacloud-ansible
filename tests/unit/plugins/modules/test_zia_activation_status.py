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

from tests.unit.plugins.modules.common.utils import (
    set_module_args,
    AnsibleExitJson,
    AnsibleFailJson,
    ModuleTestCase,
    DEFAULT_PROVIDER,
)

from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)

REAL_ARGUMENT_SPEC = ZIAClientHelper.zia_argument_spec()


class MockBox:
    """Mock Box object to simulate SDK responses"""

    def __init__(self, data):
        self._data = data

    def as_dict(self):
        return self._data

    def __getattr__(self, name):
        return self._data.get(name)


class TestZIAActivationStatusModule(ModuleTestCase):
    """Unit tests for zia_activation_status module."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock ZIA client that preserves argument_spec"""
        with patch(
            "ansible_collections.zscaler.ziacloud.plugins.modules.zia_activation_status.ZIAClientHelper"
        ) as mock_class:
            base_spec = REAL_ARGUMENT_SPEC.copy()
            base_spec.update(
                status=dict(type="str", choices=["ACTIVE"], required=True),
                state=dict(type="str", choices=["present"], default="present"),
            )
            mock_class.zia_argument_spec.return_value = base_spec
            client_instance = MagicMock()
            mock_class.return_value = client_instance
            yield client_instance

    def test_activate_when_pending(self, mock_client):
        """Test activating when current status is PENDING."""
        mock_status_pending = MockBox({"status": "PENDING"})
        mock_status_active = MockBox({"status": "ACTIVE"})

        mock_client.activate.status.side_effect = [
            (mock_status_pending, None, None),
            (mock_status_active, None, None),
        ]
        mock_client.activate.activate.return_value = (None, None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            status="ACTIVE",
            state="present",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_activation_status,
        )

        with pytest.raises(AnsibleExitJson) as result:
            zia_activation_status.main()

        mock_client.activate.activate.assert_called_once()
        assert result.value.result["changed"] is True
        assert result.value.result["data"]["status"] == "ACTIVE"

    def test_no_change_when_already_active(self, mock_client):
        """Test no change when status is already ACTIVE."""
        mock_status_active = MockBox({"status": "ACTIVE"})
        mock_client.activate.status.return_value = (mock_status_active, None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            status="ACTIVE",
            state="present",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_activation_status,
        )

        with pytest.raises(AnsibleExitJson) as result:
            zia_activation_status.main()

        mock_client.activate.activate.assert_not_called()
        assert result.value.result["changed"] is False
        assert result.value.result["data"]["status"] == "ACTIVE"

    def test_activate_remains_pending(self, mock_client):
        """Test when activation leaves status as PENDING (another admin's changes)."""
        mock_status_pending = MockBox({"status": "PENDING"})
        mock_client.activate.status.side_effect = [
            (mock_status_pending, None, None),
            (mock_status_pending, None, None),
        ]
        mock_client.activate.activate.return_value = (None, None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            status="ACTIVE",
            state="present",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_activation_status,
        )

        with pytest.raises(AnsibleExitJson) as result:
            zia_activation_status.main()

        mock_client.activate.activate.assert_called_once()
        assert result.value.result["changed"] is False
        assert result.value.result["data"]["status"] == "PENDING"

    def test_status_api_error(self, mock_client):
        """Test handling API error when getting status."""
        mock_client.activate.status.return_value = (None, None, "API Error")

        set_module_args(
            provider=DEFAULT_PROVIDER,
            status="ACTIVE",
            state="present",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_activation_status,
        )

        with pytest.raises(AnsibleFailJson) as result:
            zia_activation_status.main()

        assert "Failed to get activation status" in result.value.result["msg"]

    def test_activate_api_error(self, mock_client):
        """Test handling API error when activating."""
        mock_status_pending = MockBox({"status": "PENDING"})
        mock_client.activate.status.return_value = (mock_status_pending, None, None)
        mock_client.activate.activate.return_value = (None, None, "Activation failed")

        set_module_args(
            provider=DEFAULT_PROVIDER,
            status="ACTIVE",
            state="present",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_activation_status,
        )

        with pytest.raises(AnsibleFailJson) as result:
            zia_activation_status.main()

        assert "Failed to activate" in result.value.result["msg"]
