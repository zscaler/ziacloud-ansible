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


class TestZIAIPSSignatureRulesModule(ModuleTestCase):
    """Unit tests for zia_ips_signature_rules module."""

    SAMPLE_RULE = {
        "id": 1254654,
        "name": "Custom_IPS_Rule_Example",
        "description": "Blocks requests to /admin",
        "rule_text": 'alert http any any -> any any (msg:"HTTP /admin"; content:"/admin"; http_uri; nocase; sid:1000010; rev:1;)',
    }

    @pytest.fixture
    def mock_client(self):
        with patch("ansible_collections.zscaler.ziacloud.plugins.modules.zia_ips_signature_rules.ZIAClientHelper") as mock_class:
            base_spec = REAL_ARGUMENT_SPEC.copy()
            base_spec.update(
                id=dict(type="int", required=False),
                name=dict(type="str", required=True),
                description=dict(type="str", required=False),
                rule_text=dict(type="str", required=False),
                state=dict(type="str", choices=["present", "absent"], default="present"),
            )
            mock_class.zia_argument_spec.return_value = base_spec
            client_instance = MagicMock()
            mock_class.return_value = client_instance
            yield client_instance

    def test_create_rule(self, mock_client):
        mock_client.ips_signature_rules.list_ips_signature_rules.return_value = ([], None, None)
        mock_client.ips_signature_rules.add_ips_signature_rule.return_value = (MockBox(self.SAMPLE_RULE), None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="Custom_IPS_Rule_Example",
            description="Blocks requests to /admin",
            rule_text=self.SAMPLE_RULE["rule_text"],
            state="present",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_ips_signature_rules

        with pytest.raises(AnsibleExitJson) as result:
            zia_ips_signature_rules.main()

        mock_client.ips_signature_rules.add_ips_signature_rule.assert_called_once()
        assert result.value.result["changed"] is True
        assert result.value.result["data"]["name"] == "Custom_IPS_Rule_Example"

    def test_update_rule(self, mock_client):
        existing = dict(self.SAMPLE_RULE)
        existing["description"] = "Old description"
        mock_client.ips_signature_rules.list_ips_signature_rules.return_value = ([MockBox(existing)], None, None)
        updated = dict(self.SAMPLE_RULE)
        updated["description"] = "Blocks requests to /admin"
        mock_client.ips_signature_rules.update_ips_signature_rule.return_value = (MockBox(updated), None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="Custom_IPS_Rule_Example",
            description="Blocks requests to /admin",
            rule_text=self.SAMPLE_RULE["rule_text"],
            state="present",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_ips_signature_rules

        with pytest.raises(AnsibleExitJson) as result:
            zia_ips_signature_rules.main()

        mock_client.ips_signature_rules.update_ips_signature_rule.assert_called_once()
        assert result.value.result["changed"] is True

    def test_delete_rule(self, mock_client):
        mock_client.ips_signature_rules.list_ips_signature_rules.return_value = ([MockBox(self.SAMPLE_RULE)], None, None)
        mock_client.ips_signature_rules.delete_ips_signature_rule.return_value = (None, None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="Custom_IPS_Rule_Example",
            state="absent",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_ips_signature_rules

        with pytest.raises(AnsibleExitJson) as result:
            zia_ips_signature_rules.main()

        mock_client.ips_signature_rules.delete_ips_signature_rule.assert_called_once()
        assert result.value.result["changed"] is True

    def test_no_change_when_identical(self, mock_client):
        mock_client.ips_signature_rules.get_ips_signature_rule.return_value = (MockBox(self.SAMPLE_RULE), None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            id=1254654,
            name="Custom_IPS_Rule_Example",
            description="Blocks requests to /admin",
            rule_text=self.SAMPLE_RULE["rule_text"],
            state="present",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_ips_signature_rules

        with pytest.raises(AnsibleExitJson) as result:
            zia_ips_signature_rules.main()

        mock_client.ips_signature_rules.add_ips_signature_rule.assert_not_called()
        mock_client.ips_signature_rules.update_ips_signature_rule.assert_not_called()
        assert result.value.result["changed"] is False

    def test_delete_nonexistent_rule(self, mock_client):
        mock_client.ips_signature_rules.list_ips_signature_rules.return_value = ([], None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="NonExistent",
            state="absent",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_ips_signature_rules

        with pytest.raises(AnsibleExitJson) as result:
            zia_ips_signature_rules.main()

        mock_client.ips_signature_rules.delete_ips_signature_rule.assert_not_called()
        assert result.value.result["changed"] is False

    def test_check_mode_create(self, mock_client):
        mock_client.ips_signature_rules.list_ips_signature_rules.return_value = ([], None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="New_Rule",
            rule_text=self.SAMPLE_RULE["rule_text"],
            state="present",
            _ansible_check_mode=True,
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_ips_signature_rules

        with pytest.raises(AnsibleExitJson) as result:
            zia_ips_signature_rules.main()

        mock_client.ips_signature_rules.add_ips_signature_rule.assert_not_called()
        assert result.value.result["changed"] is True

    def test_get_rule_by_id(self, mock_client):
        mock_client.ips_signature_rules.get_ips_signature_rule.return_value = (MockBox(self.SAMPLE_RULE), None, None)
        mock_client.ips_signature_rules.delete_ips_signature_rule.return_value = (None, None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            id=1254654,
            name="Custom_IPS_Rule_Example",
            state="absent",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_ips_signature_rules

        with pytest.raises(AnsibleExitJson) as result:
            zia_ips_signature_rules.main()

        mock_client.ips_signature_rules.get_ips_signature_rule.assert_called_once()
        assert result.value.result["changed"] is True

    def test_list_error(self, mock_client):
        mock_client.ips_signature_rules.list_ips_signature_rules.return_value = (None, None, "List error")

        set_module_args(provider=DEFAULT_PROVIDER, name="Test", state="present")

        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_ips_signature_rules

        with pytest.raises(AnsibleFailJson) as result:
            zia_ips_signature_rules.main()

        assert "error" in result.value.result["msg"].lower()

    def test_add_rule_error(self, mock_client):
        mock_client.ips_signature_rules.list_ips_signature_rules.return_value = ([], None, None)
        mock_client.ips_signature_rules.add_ips_signature_rule.return_value = (None, None, "Add failed")

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="Test",
            rule_text=self.SAMPLE_RULE["rule_text"],
            state="present",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_ips_signature_rules

        with pytest.raises(AnsibleFailJson) as result:
            zia_ips_signature_rules.main()

        assert "error" in result.value.result["msg"].lower()

    def test_update_rule_error(self, mock_client):
        existing = dict(self.SAMPLE_RULE)
        existing["description"] = "Old"
        mock_client.ips_signature_rules.list_ips_signature_rules.return_value = ([MockBox(existing)], None, None)
        mock_client.ips_signature_rules.update_ips_signature_rule.return_value = (None, None, "Update failed")

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="Custom_IPS_Rule_Example",
            description="New description",
            state="present",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_ips_signature_rules

        with pytest.raises(AnsibleFailJson) as result:
            zia_ips_signature_rules.main()

        assert "error" in result.value.result["msg"].lower()

    def test_delete_rule_error(self, mock_client):
        mock_client.ips_signature_rules.list_ips_signature_rules.return_value = ([MockBox(self.SAMPLE_RULE)], None, None)
        mock_client.ips_signature_rules.delete_ips_signature_rule.return_value = (None, None, "Delete failed")

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="Custom_IPS_Rule_Example",
            state="absent",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_ips_signature_rules

        with pytest.raises(AnsibleFailJson) as result:
            zia_ips_signature_rules.main()

        assert "error" in result.value.result["msg"].lower()
