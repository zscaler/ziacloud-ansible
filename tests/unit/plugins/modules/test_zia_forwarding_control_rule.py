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


class TestForwardingControlRuleModule(ModuleTestCase):
    @pytest.fixture
    def mock_client(self):
        with patch("ansible_collections.zscaler.ziacloud.plugins.modules.zia_forwarding_control_rule.ZIAClientHelper") as mock_class:
            mock_class.zia_argument_spec.return_value = REAL_ARGUMENT_SPEC.copy()
            client_instance = MagicMock()
            mock_class.return_value = client_instance

            client_instance.forwarding_control.add_rule.return_value = (
                MockBox({"id": 1, "name": "test", "whitelist_urls": [], "blacklist_urls": []}),
                None,
                None,
            )
            client_instance.forwarding_control.delete_rule.return_value = (
                MockBox({"id": 1, "name": "test", "whitelist_urls": [], "blacklist_urls": []}),
                None,
                None,
            )
            client_instance.forwarding_control.get_rule.return_value = (
                MockBox({"id": 1, "name": "test", "whitelist_urls": [], "blacklist_urls": []}),
                None,
                None,
            )
            client_instance.forwarding_control.update_rule.return_value = (
                MockBox({"id": 1, "name": "test", "whitelist_urls": [], "blacklist_urls": []}),
                None,
                None,
            )
            client_instance.forwarding_control.list_rules.return_value = ([], None, None)
            yield client_instance

    def test_list_or_get(self, mock_client):
        mock_client.forwarding_control.list_rules.return_value = ([], None, None)
        set_module_args(provider=DEFAULT_PROVIDER, name="test", state="present")
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_forwarding_control_rule

        with pytest.raises(AnsibleExitJson) as result:
            zia_forwarding_control_rule.main()
        assert result.value.result.get("changed", False) is True

    def test_get_by_id(self, mock_client):
        mock_item = MockBox({"id": 1, "name": "test"})
        mock_client.forwarding_control.get_rule.return_value = (mock_item, None, None)
        set_module_args(provider=DEFAULT_PROVIDER, id=1, name="test")
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_forwarding_control_rule

        with pytest.raises(AnsibleExitJson) as result:
            zia_forwarding_control_rule.main()
        assert result.value.result.get("changed") in (True, False)

    def test_api_error(self, mock_client):
        mock_client.forwarding_control.list_rules.return_value = (None, None, "API Error")
        set_module_args(provider=DEFAULT_PROVIDER, name="test", state="present")
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_forwarding_control_rule

        with pytest.raises(AnsibleFailJson):
            zia_forwarding_control_rule.main()

    def test_validation_zpa_missing_attrs(self, mock_client):
        """forward_method=ZPA without zpa_app_segments and zpa_gateway - validation error."""
        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="test",
            type="FORWARDING",
            forward_method="ZPA",
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_forwarding_control_rule

        with pytest.raises(AnsibleFailJson) as result:
            zia_forwarding_control_rule.main()
        assert "ZPA" in result.value.result["msg"] or "required" in result.value.result["msg"]

    def test_validation_direct_prohibited(self, mock_client):
        """forward_method=DIRECT with zpa_gateway set - validation error."""
        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="test",
            type="FORWARDING",
            forward_method="DIRECT",
            zpa_gateway={"id": 1, "name": "gw"},
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_forwarding_control_rule

        with pytest.raises(AnsibleFailJson) as result:
            zia_forwarding_control_rule.main()
        assert "zpa_gateway" in result.value.result["msg"] or "DIRECT" in result.value.result["msg"]

    def test_validation_proxychain_missing_proxy(self, mock_client):
        """forward_method=PROXYCHAIN without proxy_gateway - validation error."""
        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="test",
            type="FORWARDING",
            forward_method="PROXYCHAIN",
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_forwarding_control_rule

        with pytest.raises(AnsibleFailJson) as result:
            zia_forwarding_control_rule.main()
        assert "proxy" in result.value.result["msg"].lower() or "Proxy" in result.value.result["msg"]

    def test_validation_proxychain_prohibited(self, mock_client):
        """forward_method=PROXYCHAIN with zpa_gateway set - validation error."""
        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="test",
            type="FORWARDING",
            forward_method="PROXYCHAIN",
            proxy_gateway={"id": 1, "name": "proxy"},
            zpa_gateway={"id": 1, "name": "gw"},
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_forwarding_control_rule

        with pytest.raises(AnsibleFailJson) as result:
            zia_forwarding_control_rule.main()
        assert "zpa_gateway" in result.value.result["msg"] or "PROXYCHAIN" in result.value.result["msg"]

    def _make_rule_mock(self, data):
        m = MagicMock()
        m.as_dict.return_value = data
        m.name = data.get("name")
        return m

    def test_idempotent_no_diff(self, mock_client):
        """Existing rule matches desired - no change."""
        existing = {
            "id": 1,
            "name": "test",
            "description": "desc",
            "order": 1,
            "rank": 7,
            "type": "FORWARDING",
            "forward_method": "ZIA",
            "enabled": True,
            "state": "ENABLED",
            "locations": [],
            "location_groups": [],
            "departments": [],
            "groups": [],
            "users": [],
        }
        mock_client.forwarding_control.list_rules.return_value = ([self._make_rule_mock(existing)], None, None)
        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="test",
            type="FORWARDING",
            forward_method="ZIA",
            description="desc",
            order=1,
            enabled=True,
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_forwarding_control_rule

        with pytest.raises(AnsibleExitJson) as result:
            zia_forwarding_control_rule.main()
        assert result.value.result["changed"] is False

    def test_check_mode_with_diff(self, mock_client):
        """check_mode when rule would be created (no existing)."""
        mock_client.forwarding_control.list_rules.return_value = ([], None, None)
        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="newrule",
            type="FORWARDING",
            forward_method="ZIA",
            _ansible_check_mode=True,
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_forwarding_control_rule

        with pytest.raises(AnsibleExitJson) as result:
            zia_forwarding_control_rule.main()
        assert result.value.result["changed"] is True

    def test_check_mode_no_diff(self, mock_client):
        """check_mode when existing rule matches - no change."""
        existing = {
            "id": 1,
            "name": "match",
            "description": "d",
            "order": 1,
            "rank": 7,
            "type": "FORWARDING",
            "forward_method": "ZIA",
            "enabled": True,
            "state": "ENABLED",
            "locations": [],
            "location_groups": [],
            "departments": [],
            "groups": [],
            "users": [],
        }
        mock_client.forwarding_control.list_rules.return_value = ([self._make_rule_mock(existing)], None, None)
        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="match",
            type="FORWARDING",
            forward_method="ZIA",
            description="d",
            order=1,
            enabled=True,
            _ansible_check_mode=True,
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_forwarding_control_rule

        with pytest.raises(AnsibleExitJson) as result:
            zia_forwarding_control_rule.main()
        assert result.value.result["changed"] is False

    def test_get_rule_by_id_error(self, mock_client):
        """API error when fetching rule by id."""
        mock_client.forwarding_control.get_rule.return_value = (None, None, "Get error")
        set_module_args(provider=DEFAULT_PROVIDER, id=1, name="test")
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_forwarding_control_rule

        with pytest.raises(AnsibleFailJson):
            zia_forwarding_control_rule.main()

    def test_update_error(self, mock_client):
        """API error when updating rule."""
        existing = {
            "id": 1,
            "name": "test",
            "description": "old",
            "order": 1,
            "rank": 7,
            "type": "FORWARDING",
            "forward_method": "ZIA",
            "enabled": True,
            "state": "ENABLED",
        }
        mock_client.forwarding_control.get_rule.return_value = (self._make_rule_mock(existing), None, None)
        mock_client.forwarding_control.update_rule.return_value = (None, None, "Update failed")
        set_module_args(
            provider=DEFAULT_PROVIDER,
            id=1,
            name="test",
            type="FORWARDING",
            forward_method="ZIA",
            description="new",
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_forwarding_control_rule

        with pytest.raises(AnsibleFailJson):
            zia_forwarding_control_rule.main()

    def test_add_rule_error(self, mock_client):
        """API error when adding rule."""
        mock_client.forwarding_control.list_rules.return_value = ([], None, None)
        mock_client.forwarding_control.add_rule.return_value = (None, None, "Add failed")
        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="newrule",
            type="FORWARDING",
            forward_method="ZIA",
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_forwarding_control_rule

        with pytest.raises(AnsibleFailJson):
            zia_forwarding_control_rule.main()

    def test_delete_error(self, mock_client):
        """API error when deleting rule."""
        existing = {"id": 1, "name": "test", "default_rule": False, "predefined": False}
        mock_client.forwarding_control.get_rule.return_value = (self._make_rule_mock(existing), None, None)
        mock_client.forwarding_control.delete_rule.return_value = (None, None, "Delete failed")
        set_module_args(provider=DEFAULT_PROVIDER, id=1, name="test", state="absent")
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_forwarding_control_rule

        with pytest.raises(AnsibleFailJson):
            zia_forwarding_control_rule.main()

    def test_default_rule_absent_no_delete(self, mock_client):
        """state=absent with default_rule=True - no delete allowed."""
        existing = {"id": 1, "name": "test", "default_rule": True, "predefined": False}
        mock_client.forwarding_control.get_rule.return_value = (self._make_rule_mock(existing), None, None)
        set_module_args(provider=DEFAULT_PROVIDER, id=1, name="test", state="absent")
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_forwarding_control_rule

        with pytest.raises(AnsibleExitJson) as result:
            zia_forwarding_control_rule.main()
        assert result.value.result["changed"] is False
