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


class TestUserManagementinfoModule(ModuleTestCase):
    @pytest.fixture
    def mock_client(self):
        with patch("ansible_collections.zscaler.ziacloud.plugins.modules.zia_user_management_info.ZIAClientHelper") as mock_class:
            mock_class.zia_argument_spec.return_value = REAL_ARGUMENT_SPEC.copy()
            client_instance = MagicMock()
            mock_class.return_value = client_instance

            client_instance.user_management.get_user.return_value = (MockBox({"id": 1, "name": "test", "whitelist_urls": [], "blacklist_urls": []}), None, None)
            client_instance.user_management.list_users.return_value = (
                [MockBox({"id": 1, "name": "test", "whitelist_urls": [], "blacklist_urls": []})],
                None,
                None,
            )
            yield client_instance

    def test_list_or_get(self, mock_client):
        mock_client.user_management.list_users.return_value = ([MockBox({"id": 1, "name": "test", "whitelist_urls": [], "blacklist_urls": []})], None, None)
        set_module_args(provider=DEFAULT_PROVIDER)
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_user_management_info

        with pytest.raises(AnsibleExitJson) as result:
            zia_user_management_info.main()
        assert result.value.result["changed"] is False

    def test_get_by_id(self, mock_client):
        mock_item = MockBox({"id": 1, "name": "test"})
        mock_client.user_management.get_user.return_value = (mock_item, None, None)
        set_module_args(provider=DEFAULT_PROVIDER, id=1)
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_user_management_info

        with pytest.raises(AnsibleExitJson) as result:
            zia_user_management_info.main()
        assert result.value.result.get("changed") in (True, False)

    def test_api_error(self, mock_client):
        mock_client.user_management.list_users.return_value = (None, None, "API Error")
        set_module_args(provider=DEFAULT_PROVIDER)
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_user_management_info

        with pytest.raises(AnsibleFailJson):
            zia_user_management_info.main()

    def test_jmespath_query_filter(self, mock_client):
        mock_client.user_management.list_users.return_value = (
            [
                MockBox({"id": 1, "name": "Adam", "department": {"name": "Engineering"}}),
                MockBox({"id": 2, "name": "Beth", "department": {"name": "Marketing"}}),
                MockBox({"id": 3, "name": "Carl", "department": {"name": "Engineering"}}),
            ],
            None,
            None,
        )
        set_module_args(provider=DEFAULT_PROVIDER, query="[?department.name == 'Engineering']")
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_user_management_info

        with pytest.raises(AnsibleExitJson) as result:
            zia_user_management_info.main()
        users = result.value.result["users"]
        assert [u["name"] for u in users] == ["Adam", "Carl"]

    def test_jmespath_query_projection(self, mock_client):
        mock_client.user_management.list_users.return_value = (
            [
                MockBox({"id": 1, "name": "Adam", "email": "adam@example.com"}),
                MockBox({"id": 2, "name": "Beth", "email": "beth@example.com"}),
            ],
            None,
            None,
        )
        set_module_args(provider=DEFAULT_PROVIDER, query="[*].email")
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_user_management_info

        with pytest.raises(AnsibleExitJson) as result:
            zia_user_management_info.main()
        assert result.value.result["users"] == ["adam@example.com", "beth@example.com"]

    def test_jmespath_query_no_match_returns_empty(self, mock_client):
        mock_client.user_management.list_users.return_value = (
            [MockBox({"id": 1, "name": "Adam"})],
            None,
            None,
        )
        set_module_args(provider=DEFAULT_PROVIDER, query="[?name == 'does-not-exist']")
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_user_management_info

        with pytest.raises(AnsibleExitJson) as result:
            zia_user_management_info.main()
        assert result.value.result["users"] == []

    def test_invalid_jmespath_query_fails(self, mock_client):
        mock_client.user_management.list_users.return_value = (
            [MockBox({"id": 1, "name": "Adam"})],
            None,
            None,
        )
        set_module_args(provider=DEFAULT_PROVIDER, query="[?broken(")
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_user_management_info

        with pytest.raises(AnsibleFailJson) as result:
            zia_user_management_info.main()
        assert "JMESPath" in result.value.result["msg"]
