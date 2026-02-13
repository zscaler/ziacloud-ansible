# -*- coding: utf-8 -*-
# Copyright (c) 2023 Zscaler Inc, <devrel@zscaler.com>
# MIT License - Auto-generated

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import sys, os
COLLECTION_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
if COLLECTION_ROOT not in sys.path:
    sys.path.insert(0, COLLECTION_ROOT)

import pytest
from unittest.mock import MagicMock, patch
from tests.unit.plugins.modules.common.utils import (
    set_module_args, AnsibleExitJson, AnsibleFailJson, ModuleTestCase, DEFAULT_PROVIDER,
)
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import ZIAClientHelper

REAL_ARGUMENT_SPEC = ZIAClientHelper.zia_argument_spec()

class MockBox:
    def __init__(self, data): self._data = data or {}
    def as_dict(self): return self._data
    def get(self, key, default=None): return self._data.get(key, default)
    def __getattr__(self, name): return self._data.get(name)

class TestBrowserControlPolicyModule(ModuleTestCase):
    @pytest.fixture
    def mock_client(self):
        with patch("ansible_collections.zscaler.ziacloud.plugins.modules.zia_browser_control_policy.ZIAClientHelper") as mock_class:
            mock_class.zia_argument_spec.return_value = REAL_ARGUMENT_SPEC.copy()
            client_instance = MagicMock()
            mock_class.return_value = client_instance

            client_instance.browser_control_settings.update_browser_control_settings.return_value = (MockBox({'id': 1, 'name': 'test', 'whitelist_urls': [], 'blacklist_urls': []}), None, None)
            client_instance.browser_control_settings.get_browser_control_settings.return_value = (MockBox({'id': 1, 'name': 'test', 'whitelist_urls': [], 'blacklist_urls': []}), None, None)
            yield client_instance

    def test_list_or_get(self, mock_client):
        mock_client.browser_control_settings.get_browser_control_settings.return_value = (MockBox({'id': 1, 'name': 'test', 'whitelist_urls': [], 'blacklist_urls': []}), None, None)
        set_module_args(provider=DEFAULT_PROVIDER)
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_browser_control_policy
        with pytest.raises(AnsibleExitJson) as result:
            zia_browser_control_policy.main()
        assert result.value.result["changed"] is False

    def test_api_error(self, mock_client):
        mock_client.browser_control_settings.get_browser_control_settings.return_value = (None, None, 'API Error')
        set_module_args(provider=DEFAULT_PROVIDER)
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_browser_control_policy
        with pytest.raises(AnsibleFailJson):
            zia_browser_control_policy.main()

    def test_state_absent_no_op(self, mock_client):
        """state=absent is a no-op for singleton - cannot delete."""
        mock_client.browser_control_settings.get_browser_control_settings.return_value = (
            MockBox({"plugin_check_frequency": "DAILY", "enable_warnings": True}), None, None
        )
        set_module_args(provider=DEFAULT_PROVIDER, state="absent")
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_browser_control_policy
        with pytest.raises(AnsibleExitJson) as result:
            zia_browser_control_policy.main()
        assert result.value.result["changed"] is False
        assert "cannot be deleted" in result.value.result["msg"]

    def test_check_mode_with_diff(self, mock_client):
        """check_mode when policy differs - reports changed."""
        current = {"plugin_check_frequency": "DAILY", "enable_warnings": False}
        mock_client.browser_control_settings.get_browser_control_settings.return_value = (
            MockBox(current), None, None
        )
        set_module_args(provider=DEFAULT_PROVIDER, plugin_check_frequency="WEEKLY", _ansible_check_mode=True)
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_browser_control_policy
        with pytest.raises(AnsibleExitJson) as result:
            zia_browser_control_policy.main()
        assert result.value.result["changed"] is True

    def test_check_mode_no_diff(self, mock_client):
        """check_mode when policy matches - no change."""
        current = {"plugin_check_frequency": "DAILY", "enable_warnings": True}
        mock_client.browser_control_settings.get_browser_control_settings.return_value = (
            MockBox(current), None, None
        )
        set_module_args(provider=DEFAULT_PROVIDER, plugin_check_frequency="DAILY", enable_warnings=True, _ansible_check_mode=True)
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_browser_control_policy
        with pytest.raises(AnsibleExitJson) as result:
            zia_browser_control_policy.main()
        assert result.value.result["changed"] is False

    def test_update_error_path(self, mock_client):
        """API error on update."""
        mock_client.browser_control_settings.get_browser_control_settings.return_value = (
            MockBox({"plugin_check_frequency": "WEEKLY"}), None, None
        )
        mock_client.browser_control_settings.update_browser_control_settings.return_value = (
            None, None, "Update failed"
        )
        set_module_args(provider=DEFAULT_PROVIDER, plugin_check_frequency="DAILY")
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_browser_control_policy
        with pytest.raises(AnsibleFailJson):
            zia_browser_control_policy.main()

    def test_smart_isolation_profile_dict_path(self, mock_client):
        """smart_isolation_profile as dict - branch coverage for profile path."""
        current = {"smart_isolation_profile": {"id": "abc-123"}}
        mock_client.browser_control_settings.get_browser_control_settings.return_value = (
            MockBox(current), None, None
        )
        mock_client.browser_control_settings.update_browser_control_settings.return_value = (
            MockBox({"smart_isolation_profile": {"id": "xyz-456"}}), None, None
        )
        set_module_args(
            provider=DEFAULT_PROVIDER,
            smart_isolation_profile={"id": "xyz-456"},
            enable_smart_browser_isolation=True,
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_browser_control_policy
        with pytest.raises(AnsibleExitJson) as result:
            zia_browser_control_policy.main()
        assert result.value.result["changed"] is True

    def test_smart_isolation_users_groups_int_ids(self, mock_client):
        """smart_isolation_users/groups with int IDs - branch coverage."""
        current = {"smart_isolation_users": [], "smart_isolation_groups": []}
        mock_client.browser_control_settings.get_browser_control_settings.return_value = (
            MockBox(current), None, None
        )
        mock_client.browser_control_settings.update_browser_control_settings.return_value = (
            MockBox({}), None, None
        )
        set_module_args(
            provider=DEFAULT_PROVIDER,
            smart_isolation_users=[100, 200],
            smart_isolation_groups=[10, 20],
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_browser_control_policy
        with pytest.raises(AnsibleExitJson) as result:
            zia_browser_control_policy.main()
        assert result.value.result["changed"] is True
