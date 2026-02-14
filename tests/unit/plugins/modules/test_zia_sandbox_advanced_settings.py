# -*- coding: utf-8 -*-
# Copyright (c) 2023 Zscaler Inc, <devrel@zscaler.com>
# MIT License - Auto-generated

from __future__ import absolute_import, division, print_function
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import ZIAClientHelper
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
    def __init__(self, data):
        self._data = data or {}

    def as_dict(self):
        return self._data

    def get(self, key, default=None):
        return self._data.get(key, default)

    def __getattr__(self, name):
        return self._data.get(name)


class TestSandboxAdvancedSettingsModule(ModuleTestCase):
    @pytest.fixture
    def mock_client(self):
        with patch("ansible_collections.zscaler.ziacloud.plugins.modules.zia_sandbox_advanced_settings.ZIAClientHelper") as mock_class:
            mock_class.zia_argument_spec.return_value = REAL_ARGUMENT_SPEC.copy()
            client_instance = MagicMock()
            mock_class.return_value = client_instance

            client_instance.sandbox.add_hash_to_custom_list.return_value = (MockBox({"fileHashesToBeBlocked": [], "id": 1}), None, None)
            client_instance.sandbox.get_file_hash_count.return_value = (MockBox({"fileHashesToBeBlocked": [], "id": 1}), None, None)
            client_instance.sandbox.get_behavioral_analysis.return_value = (MockBox({"fileHashesToBeBlocked": [], "id": 1}), None, None)
            yield client_instance

    def test_list_or_get(self, mock_client):
        mock_client.sandbox.get_behavioral_analysis.return_value = (MockBox({"fileHashesToBeBlocked": [], "id": 1}), None, None)
        set_module_args(provider=DEFAULT_PROVIDER, file_hashes_to_be_blocked=[])
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_sandbox_advanced_settings

        with pytest.raises(AnsibleExitJson) as result:
            zia_sandbox_advanced_settings.main()
        assert result.value.result["changed"] is False

    def test_api_error(self, mock_client):
        mock_client.sandbox.get_behavioral_analysis.return_value = (None, None, "API Error")
        set_module_args(provider=DEFAULT_PROVIDER, file_hashes_to_be_blocked=[])
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_sandbox_advanced_settings

        with pytest.raises(AnsibleFailJson):
            zia_sandbox_advanced_settings.main()

    def test_invalid_hash_sha1(self, mock_client):
        """Invalid hash - SHA1 not supported - validation error path."""
        set_module_args(
            provider=DEFAULT_PROVIDER,
            file_hashes_to_be_blocked=["a" * 40],  # SHA1 length
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_sandbox_advanced_settings

        with pytest.raises(AnsibleFailJson) as result:
            zia_sandbox_advanced_settings.main()
        assert "SHA1" in result.value.result["msg"] or "Invalid" in result.value.result["msg"]

    def test_state_absent_clears_list(self, mock_client):
        """state=absent with current hashes - clears list."""
        mock_client.sandbox.get_behavioral_analysis.return_value = (MockBox({"fileHashesToBeBlocked": ["abc123def456789012345678901234ab"]}), None, None)
        mock_client.sandbox.add_hash_to_custom_list.return_value = (None, None, None)
        mock_client.sandbox.get_file_hash_count.return_value = (MockBox({"count": 0}), None, None)
        set_module_args(provider=DEFAULT_PROVIDER, file_hashes_to_be_blocked=[], state="absent")
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_sandbox_advanced_settings

        with pytest.raises(AnsibleExitJson) as result:
            zia_sandbox_advanced_settings.main()
        assert result.value.result["changed"] is True
        assert "cleared" in result.value.result["msg"]

    def test_check_mode_change_needed(self, mock_client):
        """check_mode when change needed."""
        mock_client.sandbox.get_behavioral_analysis.return_value = (MockBox({"fileHashesToBeBlocked": []}), None, None)
        set_module_args(
            provider=DEFAULT_PROVIDER,
            file_hashes_to_be_blocked=["42914d6d213a20a2684064be5c80ffa9"],
            _ansible_check_mode=True,
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_sandbox_advanced_settings

        with pytest.raises(AnsibleExitJson) as result:
            zia_sandbox_advanced_settings.main()
        assert result.value.result["changed"] is True

    def test_add_hash_api_error(self, mock_client):
        """API error when adding hashes."""
        mock_client.sandbox.get_behavioral_analysis.return_value = (MockBox({"fileHashesToBeBlocked": []}), None, None)
        mock_client.sandbox.add_hash_to_custom_list.return_value = (None, None, "Add failed")
        set_module_args(
            provider=DEFAULT_PROVIDER,
            file_hashes_to_be_blocked=["42914d6d213a20a2684064be5c80ffa9"],
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_sandbox_advanced_settings

        with pytest.raises(AnsibleFailJson):
            zia_sandbox_advanced_settings.main()

    def test_get_file_hash_count_error(self, mock_client):
        """API error when getting file hash count after update."""
        mock_client.sandbox.get_behavioral_analysis.return_value = (MockBox({"fileHashesToBeBlocked": []}), None, None)
        mock_client.sandbox.add_hash_to_custom_list.return_value = (None, None, None)
        mock_client.sandbox.get_file_hash_count.return_value = (None, None, "Count error")
        set_module_args(
            provider=DEFAULT_PROVIDER,
            file_hashes_to_be_blocked=["42914d6d213a20a2684064be5c80ffa9"],
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_sandbox_advanced_settings

        with pytest.raises(AnsibleFailJson):
            zia_sandbox_advanced_settings.main()
