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


class TestZIAEmailProfilesModule(ModuleTestCase):
    """Unit tests for zia_email_profiles module."""

    SAMPLE_PROFILE = {
        "id": 3687131,
        "name": "Example",
        "description": "Example email profile",
        "emails": ["john.doe@example.com", "mary.jane@example.com"],
    }

    @pytest.fixture
    def mock_client(self):
        with patch("ansible_collections.zscaler.ziacloud.plugins.modules.zia_email_profiles.ZIAClientHelper") as mock_class:
            base_spec = REAL_ARGUMENT_SPEC.copy()
            base_spec.update(
                id=dict(type="int", required=False),
                name=dict(type="str", required=True),
                description=dict(type="str", required=False),
                emails=dict(type="list", elements="str", required=False),
                state=dict(type="str", choices=["present", "absent"], default="present"),
            )
            mock_class.zia_argument_spec.return_value = base_spec
            client_instance = MagicMock()
            mock_class.return_value = client_instance
            yield client_instance

    def test_create_email_profile(self, mock_client):
        mock_client.email_profiles.list_email_profiles.return_value = ([], None, None)
        mock_client.email_profiles.add_email_profile.return_value = (MockBox(self.SAMPLE_PROFILE), None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="Example",
            description="Example email profile",
            emails=["john.doe@example.com", "mary.jane@example.com"],
            state="present",
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_email_profiles

        with pytest.raises(AnsibleExitJson) as result:
            zia_email_profiles.main()

        mock_client.email_profiles.add_email_profile.assert_called_once()
        assert result.value.result["changed"] is True
        assert result.value.result["data"]["name"] == "Example"

    def test_update_email_profile(self, mock_client):
        existing = dict(self.SAMPLE_PROFILE)
        existing["description"] = "Old description"
        mock_client.email_profiles.list_email_profiles.return_value = ([MockBox(existing)], None, None)
        updated = dict(self.SAMPLE_PROFILE)
        updated["description"] = "Updated description"
        mock_client.email_profiles.update_email_profile.return_value = (MockBox(updated), None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="Example",
            description="Updated description",
            emails=["john.doe@example.com", "mary.jane@example.com"],
            state="present",
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_email_profiles

        with pytest.raises(AnsibleExitJson) as result:
            zia_email_profiles.main()

        mock_client.email_profiles.update_email_profile.assert_called_once()
        assert result.value.result["changed"] is True

    def test_delete_email_profile(self, mock_client):
        mock_client.email_profiles.list_email_profiles.return_value = ([MockBox(self.SAMPLE_PROFILE)], None, None)
        mock_client.email_profiles.delete_email_profile.return_value = (None, None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="Example",
            state="absent",
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_email_profiles

        with pytest.raises(AnsibleExitJson) as result:
            zia_email_profiles.main()

        mock_client.email_profiles.delete_email_profile.assert_called_once()
        assert result.value.result["changed"] is True

    def test_no_change_when_identical(self, mock_client):
        mock_client.email_profiles.get_email_profile.return_value = (MockBox(self.SAMPLE_PROFILE), None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            id=3687131,
            name="Example",
            description="Example email profile",
            emails=["mary.jane@example.com", "john.doe@example.com"],  # different order, still equal
            state="present",
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_email_profiles

        with pytest.raises(AnsibleExitJson) as result:
            zia_email_profiles.main()

        mock_client.email_profiles.add_email_profile.assert_not_called()
        mock_client.email_profiles.update_email_profile.assert_not_called()
        assert result.value.result["changed"] is False

    def test_delete_nonexistent_profile(self, mock_client):
        mock_client.email_profiles.list_email_profiles.return_value = ([], None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="NonExistent",
            state="absent",
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_email_profiles

        with pytest.raises(AnsibleExitJson) as result:
            zia_email_profiles.main()

        mock_client.email_profiles.delete_email_profile.assert_not_called()
        assert result.value.result["changed"] is False

    def test_check_mode_create(self, mock_client):
        mock_client.email_profiles.list_email_profiles.return_value = ([], None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="New_Profile",
            description="New description",
            state="present",
            _ansible_check_mode=True,
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_email_profiles

        with pytest.raises(AnsibleExitJson) as result:
            zia_email_profiles.main()

        mock_client.email_profiles.add_email_profile.assert_not_called()
        assert result.value.result["changed"] is True

    def test_check_mode_delete(self, mock_client):
        mock_client.email_profiles.list_email_profiles.return_value = ([MockBox(self.SAMPLE_PROFILE)], None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="Example",
            state="absent",
            _ansible_check_mode=True,
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_email_profiles

        with pytest.raises(AnsibleExitJson) as result:
            zia_email_profiles.main()

        mock_client.email_profiles.delete_email_profile.assert_not_called()
        assert result.value.result["changed"] is True

    def test_get_profile_by_id(self, mock_client):
        mock_client.email_profiles.get_email_profile.return_value = (MockBox(self.SAMPLE_PROFILE), None, None)
        mock_client.email_profiles.delete_email_profile.return_value = (None, None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            id=3687131,
            name="Example",
            state="absent",
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_email_profiles

        with pytest.raises(AnsibleExitJson) as result:
            zia_email_profiles.main()

        mock_client.email_profiles.get_email_profile.assert_called_once()
        assert result.value.result["changed"] is True

    def test_list_profiles_error(self, mock_client):
        mock_client.email_profiles.list_email_profiles.return_value = (None, None, "List error")

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="Test",
            state="present",
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_email_profiles

        with pytest.raises(AnsibleFailJson) as result:
            zia_email_profiles.main()

        assert "error" in result.value.result["msg"].lower()

    def test_add_profile_error(self, mock_client):
        mock_client.email_profiles.list_email_profiles.return_value = ([], None, None)
        mock_client.email_profiles.add_email_profile.return_value = (None, None, "Add failed")

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="Test",
            state="present",
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_email_profiles

        with pytest.raises(AnsibleFailJson) as result:
            zia_email_profiles.main()

        assert "error" in result.value.result["msg"].lower()

    def test_update_profile_error(self, mock_client):
        existing = dict(self.SAMPLE_PROFILE)
        existing["description"] = "Old"
        mock_client.email_profiles.list_email_profiles.return_value = ([MockBox(existing)], None, None)
        mock_client.email_profiles.update_email_profile.return_value = (None, None, "Update failed")

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="Example",
            description="New description",
            state="present",
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_email_profiles

        with pytest.raises(AnsibleFailJson) as result:
            zia_email_profiles.main()

        assert "error" in result.value.result["msg"].lower()

    def test_delete_profile_error(self, mock_client):
        mock_client.email_profiles.list_email_profiles.return_value = ([MockBox(self.SAMPLE_PROFILE)], None, None)
        mock_client.email_profiles.delete_email_profile.return_value = (None, None, "Delete failed")

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="Example",
            state="absent",
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_email_profiles

        with pytest.raises(AnsibleFailJson) as result:
            zia_email_profiles.main()

        assert "error" in result.value.result["msg"].lower()
