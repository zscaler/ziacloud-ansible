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

class TestRiskProfilesModule(ModuleTestCase):
    @pytest.fixture
    def mock_client(self):
        with patch("ansible_collections.zscaler.ziacloud.plugins.modules.zia_risk_profiles.ZIAClientHelper") as mock_class:
            mock_class.zia_argument_spec.return_value = REAL_ARGUMENT_SPEC.copy()
            client_instance = MagicMock()
            mock_class.return_value = client_instance

            client_instance.risk_profiles.add_risk_profile.return_value = (MockBox({'id': 1, 'name': 'test', 'whitelist_urls': [], 'blacklist_urls': []}), None, None)
            client_instance.risk_profiles.delete_risk_profile.return_value = (MockBox({'id': 1, 'name': 'test', 'whitelist_urls': [], 'blacklist_urls': []}), None, None)
            client_instance.risk_profiles.get_risk_profile.return_value = (MockBox({'id': 1, 'name': 'test', 'whitelist_urls': [], 'blacklist_urls': []}), None, None)
            client_instance.risk_profiles.update_risk_profile.return_value = (MockBox({'id': 1, 'name': 'test', 'whitelist_urls': [], 'blacklist_urls': []}), None, None)
            client_instance.risk_profiles.list_risk_profiles.return_value = ([], None, None)
            yield client_instance

    def test_list_or_get(self, mock_client):
        mock_client.risk_profiles.list_risk_profiles.return_value = ([], None, None)
        set_module_args(provider=DEFAULT_PROVIDER, profile_name="test")
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_risk_profiles
        with pytest.raises(AnsibleExitJson) as result:
            zia_risk_profiles.main()
        assert result.value.result.get("changed", False) is True

    def test_get_by_id(self, mock_client):
        mock_item = MockBox({"id": 1, "name": "test"})
        mock_client.risk_profiles.get_risk_profile.return_value = (mock_item, None, None)
        set_module_args(provider=DEFAULT_PROVIDER, id=1, profile_name="test")
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_risk_profiles
        with pytest.raises(AnsibleExitJson) as result:
            zia_risk_profiles.main()
        assert result.value.result.get("changed") in (True, False)

    def test_api_error(self, mock_client):
        mock_client.risk_profiles.list_risk_profiles.return_value = (None, None, 'API Error')
        set_module_args(provider=DEFAULT_PROVIDER, profile_name="test")
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_risk_profiles
        with pytest.raises(AnsibleFailJson):
            zia_risk_profiles.main()
