# -*- coding: utf-8 -*-
# Copyright (c) 2023 Zscaler Inc, <devrel@zscaler.com>
# MIT License

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
        self._data = data

    def as_dict(self):
        return self._data

    def __getattr__(self, name):
        return self._data.get(name)


class TestZIAAdminRolesInfoModule(ModuleTestCase):
    @pytest.fixture
    def mock_client(self):
        with patch("ansible_collections.zscaler.ziacloud.plugins.modules.zia_admin_roles_info.ZIAClientHelper") as mock_class:
            base_spec = REAL_ARGUMENT_SPEC.copy()
            base_spec.update(name=dict(type="str", required=False), id=dict(type="int", required=False))
            mock_class.zia_argument_spec.return_value = base_spec
            client_instance = MagicMock()
            mock_class.return_value = client_instance
            yield client_instance

    def test_list_all(self, mock_client):
        mock_items = [MockBox({"id": 26270, "name": "Engineering_Role"})]
        mock_client.admin_roles.list_roles.return_value = (mock_items, None, None)
        set_module_args(provider=DEFAULT_PROVIDER)
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_admin_roles_info

        with pytest.raises(AnsibleExitJson) as result:
            zia_admin_roles_info.main()
        assert result.value.result["changed"] is False
        assert len(result.value.result["roles"]) == 1

    def test_get_by_id(self, mock_client):
        mock_role = MockBox({"id": 26270, "name": "Engineering_Role"})
        mock_client.admin_roles.get_role.return_value = (mock_role, None, None)
        set_module_args(provider=DEFAULT_PROVIDER, id=26270)
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_admin_roles_info

        with pytest.raises(AnsibleExitJson) as result:
            zia_admin_roles_info.main()
        mock_client.admin_roles.get_role.assert_called_once()
        assert result.value.result["changed"] is False

    def test_api_error(self, mock_client):
        mock_client.admin_roles.list_roles.return_value = (None, None, "API Error")
        set_module_args(provider=DEFAULT_PROVIDER)
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_admin_roles_info

        with pytest.raises(AnsibleFailJson):
            zia_admin_roles_info.main()
