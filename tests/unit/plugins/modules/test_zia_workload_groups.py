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
    """Mock Box object to simulate SDK responses."""

    def __init__(self, data):
        self._data = data

    def as_dict(self):
        return self._data

    def __getattr__(self, name):
        return self._data.get(name)


class TestZIAWorkloadGroupsModule(ModuleTestCase):
    """Unit tests for zia_workload_groups module."""

    SAMPLE_GROUP = {
        "id": 17811899,
        "name": "BD_WORKLOAD_GROUP01",
        "description": "Test workload group",
        "expression_json": {
            "expression_containers": [
                {
                    "tag_type": "ATTR",
                    "operator": "AND",
                    "tag_container": [{"tags": [{"key": "GroupName", "value": "example"}], "operator": "AND"}],
                }
            ]
        },
    }

    @pytest.fixture
    def mock_client(self):
        """Create a mock ZIA client that preserves argument_spec."""
        with patch("ansible_collections.zscaler.ziacloud.plugins.modules.zia_workload_groups.ZIAClientHelper") as mock_class:
            base_spec = REAL_ARGUMENT_SPEC.copy()
            base_spec.update(
                id=dict(type="int", required=False),
                name=dict(type="str", required=False),
                description=dict(type="str", required=False),
                expression_json=dict(type="list", elements="dict", required=False),
                state=dict(type="str", choices=["present", "absent"], default="present"),
            )
            mock_class.zia_argument_spec.return_value = base_spec
            client_instance = MagicMock()
            mock_class.return_value = client_instance
            yield client_instance

    def test_create_workload_group(self, mock_client):
        """Test creating a new workload group."""
        mock_client.workload_groups.list_groups.return_value = ([], None, None)
        mock_created = MockBox(self.SAMPLE_GROUP)
        mock_client.workload_groups.add_group.return_value = (mock_created, None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="BD_WORKLOAD_GROUP01",
            description="Test workload group",
            state="present",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_workload_groups,
        )

        with pytest.raises(AnsibleExitJson) as result:
            zia_workload_groups.main()

        mock_client.workload_groups.add_group.assert_called_once()
        assert result.value.result["changed"] is True
        assert result.value.result["data"]["name"] == "BD_WORKLOAD_GROUP01"

    def test_create_workload_group_with_expression(self, mock_client):
        """Test creating a workload group with expression_json."""
        mock_client.workload_groups.list_groups.return_value = ([], None, None)
        mock_created = MockBox(self.SAMPLE_GROUP)
        mock_client.workload_groups.add_group.return_value = (mock_created, None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="ATTR Workload Group",
            description="Match by attribute",
            expression_json=[
                {
                    "expression_containers": [
                        {
                            "tag_type": "ATTR",
                            "operator": "AND",
                            "tag_container": [
                                {
                                    "tags": [{"key": "GroupName", "value": "example"}],
                                    "operator": "AND",
                                }
                            ],
                        }
                    ]
                }
            ],
            state="present",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_workload_groups,
        )

        with pytest.raises(AnsibleExitJson) as result:
            zia_workload_groups.main()

        mock_client.workload_groups.add_group.assert_called_once()
        call_kwargs = mock_client.workload_groups.add_group.call_args[1]
        assert "expression_json" in call_kwargs
        assert "expression_containers" in call_kwargs["expression_json"]

    def test_update_workload_group(self, mock_client):
        """Test updating an existing workload group."""
        existing_group = dict(self.SAMPLE_GROUP)
        existing_group["description"] = "Old description"
        mock_existing = MockBox(existing_group)

        mock_client.workload_groups.list_groups.return_value = ([mock_existing], None, None)
        updated_group = dict(self.SAMPLE_GROUP)
        updated_group["description"] = "Updated description"
        mock_updated = MockBox(updated_group)
        mock_client.workload_groups.update_group.return_value = (mock_updated, None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="BD_WORKLOAD_GROUP01",
            description="Updated description",
            state="present",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_workload_groups,
        )

        with pytest.raises(AnsibleExitJson) as result:
            zia_workload_groups.main()

        mock_client.workload_groups.update_group.assert_called_once()
        assert result.value.result["changed"] is True

    def test_delete_workload_group(self, mock_client):
        """Test deleting a workload group."""
        mock_existing = MockBox(self.SAMPLE_GROUP)
        mock_client.workload_groups.list_groups.return_value = ([mock_existing], None, None)
        mock_client.workload_groups.delete_group.return_value = (None, None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="BD_WORKLOAD_GROUP01",
            state="absent",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_workload_groups,
        )

        with pytest.raises(AnsibleExitJson) as result:
            zia_workload_groups.main()

        mock_client.workload_groups.delete_group.assert_called_once_with(17811899)
        assert result.value.result["changed"] is True

    def test_delete_workload_group_by_id(self, mock_client):
        """Test deleting a workload group by ID."""
        mock_existing = MockBox(self.SAMPLE_GROUP)
        mock_client.workload_groups.get_group.return_value = (mock_existing, None, None)
        mock_client.workload_groups.delete_group.return_value = (None, None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            id=17811899,
            name="BD_WORKLOAD_GROUP01",
            state="absent",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_workload_groups,
        )

        with pytest.raises(AnsibleExitJson) as result:
            zia_workload_groups.main()

        mock_client.workload_groups.get_group.assert_called_once_with(17811899)
        mock_client.workload_groups.delete_group.assert_called_once_with(17811899)

    def test_no_change_when_identical(self, mock_client):
        """Test no change when group already matches desired state."""
        mock_existing = MockBox(self.SAMPLE_GROUP)
        mock_client.workload_groups.get_group.return_value = (mock_existing, None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            id=17811899,
            name="BD_WORKLOAD_GROUP01",
            description="Test workload group",
            state="present",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_workload_groups,
        )

        with pytest.raises(AnsibleExitJson) as result:
            zia_workload_groups.main()

        mock_client.workload_groups.add_group.assert_not_called()
        mock_client.workload_groups.update_group.assert_not_called()
        assert result.value.result["changed"] is False

    def test_delete_nonexistent_group(self, mock_client):
        """Test deleting a non-existent group (no change)."""
        mock_client.workload_groups.list_groups.return_value = ([], None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="NonExistent",
            state="absent",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_workload_groups,
        )

        with pytest.raises(AnsibleExitJson) as result:
            zia_workload_groups.main()

        mock_client.workload_groups.delete_group.assert_not_called()
        assert result.value.result["changed"] is False

    def test_check_mode_create(self, mock_client):
        """Test check mode for create operation."""
        mock_client.workload_groups.list_groups.return_value = ([], None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="New_Workload_Group",
            description="New description",
            state="present",
            _ansible_check_mode=True,
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_workload_groups,
        )

        with pytest.raises(AnsibleExitJson) as result:
            zia_workload_groups.main()

        mock_client.workload_groups.add_group.assert_not_called()
        assert result.value.result["changed"] is True

    def test_check_mode_delete(self, mock_client):
        """Test check mode for delete operation."""
        mock_existing = MockBox(self.SAMPLE_GROUP)
        mock_client.workload_groups.list_groups.return_value = ([mock_existing], None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="BD_WORKLOAD_GROUP01",
            state="absent",
            _ansible_check_mode=True,
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_workload_groups,
        )

        with pytest.raises(AnsibleExitJson) as result:
            zia_workload_groups.main()

        mock_client.workload_groups.delete_group.assert_not_called()
        assert result.value.result["changed"] is True

    def test_list_groups_error(self, mock_client):
        """Test handling error when listing workload groups."""
        mock_client.workload_groups.list_groups.return_value = (None, None, "List error")

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="Test",
            state="present",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_workload_groups,
        )

        with pytest.raises(AnsibleFailJson) as result:
            zia_workload_groups.main()

        assert "error" in result.value.result["msg"].lower()

    def test_add_group_error(self, mock_client):
        """Test handling error when adding workload group."""
        mock_client.workload_groups.list_groups.return_value = ([], None, None)
        mock_client.workload_groups.add_group.return_value = (None, None, "Add failed")

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="Test",
            state="present",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_workload_groups,
        )

        with pytest.raises(AnsibleFailJson) as result:
            zia_workload_groups.main()

        assert "error" in result.value.result["msg"].lower()

    def test_update_group_error(self, mock_client):
        """Test handling error when updating workload group."""
        existing_group = dict(self.SAMPLE_GROUP)
        existing_group["description"] = "Old"
        mock_existing = MockBox(existing_group)
        mock_client.workload_groups.list_groups.return_value = ([mock_existing], None, None)
        mock_client.workload_groups.update_group.return_value = (
            None,
            None,
            "Update failed",
        )

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="BD_WORKLOAD_GROUP01",
            description="New description",
            state="present",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_workload_groups,
        )

        with pytest.raises(AnsibleFailJson) as result:
            zia_workload_groups.main()

        assert "error" in result.value.result["msg"].lower()

    def test_delete_group_error(self, mock_client):
        """Test handling error when deleting workload group."""
        mock_existing = MockBox(self.SAMPLE_GROUP)
        mock_client.workload_groups.list_groups.return_value = ([mock_existing], None, None)
        mock_client.workload_groups.delete_group.return_value = (None, None, "Delete failed")

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="BD_WORKLOAD_GROUP01",
            state="absent",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_workload_groups,
        )

        with pytest.raises(AnsibleFailJson) as result:
            zia_workload_groups.main()

        assert "error" in result.value.result["msg"].lower()
