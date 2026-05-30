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


class TestEmailProfilesInfoModule(ModuleTestCase):
    @pytest.fixture
    def mock_client(self):
        with patch("ansible_collections.zscaler.ziacloud.plugins.modules.zia_email_profiles_info.ZIAClientHelper") as mock_class:
            mock_class.zia_argument_spec.return_value = REAL_ARGUMENT_SPEC.copy()
            client_instance = MagicMock()
            mock_class.return_value = client_instance

            client_instance.email_profiles.get_email_profile.return_value = (
                MockBox({"id": 1, "name": "Example", "emails": []}),
                None,
                None,
            )
            client_instance.email_profiles.list_email_profiles.return_value = (
                [MockBox({"id": 1, "name": "Example", "emails": []})],
                None,
                None,
            )
            yield client_instance

    def test_list_all(self, mock_client):
        set_module_args(provider=DEFAULT_PROVIDER)
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_email_profiles_info

        with pytest.raises(AnsibleExitJson) as result:
            zia_email_profiles_info.main()
        assert result.value.result["changed"] is False
        assert result.value.result["profiles"][0]["name"] == "Example"

    def test_get_by_id(self, mock_client):
        mock_client.email_profiles.get_email_profile.return_value = (
            MockBox({"id": 5, "name": "ById"}),
            None,
            None,
        )
        set_module_args(provider=DEFAULT_PROVIDER, id=5)
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_email_profiles_info

        with pytest.raises(AnsibleExitJson) as result:
            zia_email_profiles_info.main()
        assert result.value.result["profiles"][0]["id"] == 5

    def test_get_by_name(self, mock_client):
        mock_client.email_profiles.list_email_profiles.return_value = (
            [
                MockBox({"id": 1, "name": "Example"}),
                MockBox({"id": 2, "name": "Other"}),
            ],
            None,
            None,
        )
        set_module_args(provider=DEFAULT_PROVIDER, name="Other")
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_email_profiles_info

        with pytest.raises(AnsibleExitJson) as result:
            zia_email_profiles_info.main()
        assert result.value.result["profiles"] == [{"id": 2, "name": "Other"}]

    def test_get_by_name_not_found(self, mock_client):
        mock_client.email_profiles.list_email_profiles.return_value = (
            [MockBox({"id": 1, "name": "Example"})],
            None,
            None,
        )
        set_module_args(provider=DEFAULT_PROVIDER, name="DoesNotExist")
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_email_profiles_info

        with pytest.raises(AnsibleFailJson):
            zia_email_profiles_info.main()

    def test_api_error(self, mock_client):
        mock_client.email_profiles.list_email_profiles.return_value = (None, None, "API Error")
        set_module_args(provider=DEFAULT_PROVIDER)
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_email_profiles_info

        with pytest.raises(AnsibleFailJson):
            zia_email_profiles_info.main()
