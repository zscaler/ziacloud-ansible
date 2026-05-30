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


class TestZIAIPSSignatureRulesInfoModule(ModuleTestCase):
    """Unit tests for zia_ips_signature_rules_info module."""

    SAMPLE_RULE = {
        "id": 1254654,
        "name": "Custom_IPS_Rule_Example",
        "description": "Blocks requests to /admin",
        "rule_text": "alert http any any -> any any (sid:1000010; rev:1;)",
    }

    SAMPLE_RULE_2 = {
        "id": 1254655,
        "name": "Custom_IPS_Rule_Example_2",
        "description": "Second rule",
        "rule_text": "alert http any any -> any any (sid:1000011; rev:1;)",
    }

    @pytest.fixture
    def mock_client(self):
        with patch("ansible_collections.zscaler.ziacloud.plugins.modules.zia_ips_signature_rules_info.ZIAClientHelper") as mock_class:
            base_spec = REAL_ARGUMENT_SPEC.copy()
            base_spec.update(
                name=dict(type="str", required=False),
                id=dict(type="int", required=False),
            )
            mock_class.zia_argument_spec.return_value = base_spec
            client_instance = MagicMock()
            mock_class.return_value = client_instance
            yield client_instance

    def test_get_rule_by_id(self, mock_client):
        mock_client.ips_signature_rules.get_ips_signature_rule.return_value = (MockBox(self.SAMPLE_RULE), None, None)

        set_module_args(provider=DEFAULT_PROVIDER, id=1254654)

        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_ips_signature_rules_info

        with pytest.raises(AnsibleExitJson) as result:
            zia_ips_signature_rules_info.main()

        mock_client.ips_signature_rules.get_ips_signature_rule.assert_called_once()
        assert result.value.result["changed"] is False
        assert len(result.value.result["rules"]) == 1
        assert result.value.result["rules"][0]["name"] == "Custom_IPS_Rule_Example"

    def test_get_rule_by_name(self, mock_client):
        mock_rules = [MockBox(self.SAMPLE_RULE), MockBox(self.SAMPLE_RULE_2)]
        mock_client.ips_signature_rules.list_ips_signature_rules.return_value = (mock_rules, None, None)

        set_module_args(provider=DEFAULT_PROVIDER, name="Custom_IPS_Rule_Example")

        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_ips_signature_rules_info

        with pytest.raises(AnsibleExitJson) as result:
            zia_ips_signature_rules_info.main()

        assert result.value.result["changed"] is False
        assert len(result.value.result["rules"]) == 1
        assert result.value.result["rules"][0]["name"] == "Custom_IPS_Rule_Example"

    def test_get_all_rules(self, mock_client):
        mock_rules = [MockBox(self.SAMPLE_RULE), MockBox(self.SAMPLE_RULE_2)]
        mock_client.ips_signature_rules.list_ips_signature_rules.return_value = (mock_rules, None, None)

        set_module_args(provider=DEFAULT_PROVIDER)

        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_ips_signature_rules_info

        with pytest.raises(AnsibleExitJson) as result:
            zia_ips_signature_rules_info.main()

        assert result.value.result["changed"] is False
        assert len(result.value.result["rules"]) == 2

    def test_get_rule_by_id_not_found(self, mock_client):
        mock_client.ips_signature_rules.get_ips_signature_rule.return_value = (None, None, "Not Found")

        set_module_args(provider=DEFAULT_PROVIDER, id=999999999)

        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_ips_signature_rules_info

        with pytest.raises(AnsibleFailJson) as result:
            zia_ips_signature_rules_info.main()

        assert "Failed to retrieve IPS Signature Rule" in result.value.result["msg"]

    def test_get_rule_by_name_not_found(self, mock_client):
        mock_client.ips_signature_rules.list_ips_signature_rules.return_value = ([MockBox(self.SAMPLE_RULE)], None, None)

        set_module_args(provider=DEFAULT_PROVIDER, name="NonExistent")

        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_ips_signature_rules_info

        with pytest.raises(AnsibleFailJson) as result:
            zia_ips_signature_rules_info.main()

        assert "not found" in result.value.result["msg"]

    def test_api_error_on_list(self, mock_client):
        mock_client.ips_signature_rules.list_ips_signature_rules.return_value = (None, None, "API Error")

        set_module_args(provider=DEFAULT_PROVIDER)

        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_ips_signature_rules_info

        with pytest.raises(AnsibleFailJson) as result:
            zia_ips_signature_rules_info.main()

        assert "Error retrieving IPS Signature Rules" in result.value.result["msg"]
