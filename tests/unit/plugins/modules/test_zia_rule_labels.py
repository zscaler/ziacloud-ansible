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


class TestZIARuleLabelsModule(ModuleTestCase):
    """Unit tests for zia_rule_labels module."""

    SAMPLE_LABEL = {
        "id": 3687131,
        "name": "Example",
        "description": "Example description",
    }

    @pytest.fixture
    def mock_client(self):
        """Create a mock ZIA client that preserves argument_spec"""
        with patch("ansible_collections.zscaler.ziacloud.plugins.modules.zia_rule_labels.ZIAClientHelper") as mock_class:
            base_spec = REAL_ARGUMENT_SPEC.copy()
            base_spec.update(
                id=dict(type="int", required=False),
                name=dict(type="str", required=True),
                description=dict(type="str", required=False),
                state=dict(type="str", choices=["present", "absent"], default="present"),
            )
            mock_class.zia_argument_spec.return_value = base_spec
            client_instance = MagicMock()
            mock_class.return_value = client_instance
            yield client_instance

    def test_create_rule_label(self, mock_client):
        """Test creating a new rule label."""
        mock_client.rule_labels.list_labels.return_value = ([], None, None)
        mock_created = MockBox(self.SAMPLE_LABEL)
        mock_client.rule_labels.add_label.return_value = (mock_created, None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="Example",
            description="Example description",
            state="present",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_rule_labels,
        )

        with pytest.raises(AnsibleExitJson) as result:
            zia_rule_labels.main()

        mock_client.rule_labels.add_label.assert_called_once()
        assert result.value.result["changed"] is True
        assert result.value.result["data"]["name"] == "Example"

    def test_update_rule_label(self, mock_client):
        """Test updating an existing rule label."""
        existing_label = dict(self.SAMPLE_LABEL)
        existing_label["description"] = "Old description"
        mock_existing = MockBox(existing_label)

        mock_client.rule_labels.list_labels.return_value = ([mock_existing], None, None)
        updated_label = dict(self.SAMPLE_LABEL)
        updated_label["description"] = "Updated description"
        mock_updated = MockBox(updated_label)
        mock_client.rule_labels.update_label.return_value = (mock_updated, None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="Example",
            description="Updated description",
            state="present",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_rule_labels,
        )

        with pytest.raises(AnsibleExitJson) as result:
            zia_rule_labels.main()

        mock_client.rule_labels.update_label.assert_called_once()
        assert result.value.result["changed"] is True

    def test_delete_rule_label(self, mock_client):
        """Test deleting a rule label."""
        mock_existing = MockBox(self.SAMPLE_LABEL)
        mock_client.rule_labels.list_labels.return_value = ([mock_existing], None, None)
        mock_client.rule_labels.delete_label.return_value = (None, None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="Example",
            state="absent",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_rule_labels,
        )

        with pytest.raises(AnsibleExitJson) as result:
            zia_rule_labels.main()

        mock_client.rule_labels.delete_label.assert_called_once()
        assert result.value.result["changed"] is True

    def test_no_change_when_identical(self, mock_client):
        """Test no change when label already matches desired state."""
        mock_existing = MockBox(self.SAMPLE_LABEL)
        # When id is passed, module uses get_label; when only name, uses list_labels
        mock_client.rule_labels.get_label.return_value = (mock_existing, None, None)

        # Pass id so normalized_desired matches normalized_existing (module compares id, name, description)
        set_module_args(
            provider=DEFAULT_PROVIDER,
            id=3687131,
            name="Example",
            description="Example description",
            state="present",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_rule_labels,
        )

        with pytest.raises(AnsibleExitJson) as result:
            zia_rule_labels.main()

        mock_client.rule_labels.add_label.assert_not_called()
        mock_client.rule_labels.update_label.assert_not_called()
        assert result.value.result["changed"] is False

    def test_delete_nonexistent_label(self, mock_client):
        """Test deleting a non-existent label (no change)."""
        mock_client.rule_labels.list_labels.return_value = ([], None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="NonExistent",
            state="absent",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_rule_labels,
        )

        with pytest.raises(AnsibleExitJson) as result:
            zia_rule_labels.main()

        mock_client.rule_labels.delete_label.assert_not_called()
        assert result.value.result["changed"] is False

    def test_check_mode_create(self, mock_client):
        """Test check mode for create operation."""
        mock_client.rule_labels.list_labels.return_value = ([], None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="New_Label",
            description="New description",
            state="present",
            _ansible_check_mode=True,
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_rule_labels,
        )

        with pytest.raises(AnsibleExitJson) as result:
            zia_rule_labels.main()

        mock_client.rule_labels.add_label.assert_not_called()
        assert result.value.result["changed"] is True

    def test_check_mode_delete(self, mock_client):
        """Test check mode for delete operation."""
        mock_existing = MockBox(self.SAMPLE_LABEL)
        mock_client.rule_labels.list_labels.return_value = ([mock_existing], None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="Example",
            state="absent",
            _ansible_check_mode=True,
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_rule_labels,
        )

        with pytest.raises(AnsibleExitJson) as result:
            zia_rule_labels.main()

        mock_client.rule_labels.delete_label.assert_not_called()
        assert result.value.result["changed"] is True

    def test_get_label_by_id(self, mock_client):
        """Test retrieving rule label by ID."""
        mock_existing = MockBox(self.SAMPLE_LABEL)
        mock_client.rule_labels.get_label.return_value = (mock_existing, None, None)
        mock_client.rule_labels.delete_label.return_value = (None, None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            id=3687131,
            name="Example",
            state="absent",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_rule_labels,
        )

        with pytest.raises(AnsibleExitJson) as result:
            zia_rule_labels.main()

        mock_client.rule_labels.get_label.assert_called_once()
        assert result.value.result["changed"] is True

    def test_list_labels_error(self, mock_client):
        """Test handling error when listing labels."""
        mock_client.rule_labels.list_labels.return_value = (None, None, "List error")

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="Test",
            state="present",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_rule_labels,
        )

        with pytest.raises(AnsibleFailJson) as result:
            zia_rule_labels.main()

        assert "error" in result.value.result["msg"].lower()

    def test_add_label_error(self, mock_client):
        """Test handling error when adding label."""
        mock_client.rule_labels.list_labels.return_value = ([], None, None)
        mock_client.rule_labels.add_label.return_value = (None, None, "Add failed")

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="Test",
            state="present",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_rule_labels,
        )

        with pytest.raises(AnsibleFailJson) as result:
            zia_rule_labels.main()

        assert "error" in result.value.result["msg"].lower()

    def test_update_label_error(self, mock_client):
        """Test handling error when updating label."""
        existing_label = dict(self.SAMPLE_LABEL)
        existing_label["description"] = "Old"
        mock_existing = MockBox(existing_label)
        mock_client.rule_labels.list_labels.return_value = ([mock_existing], None, None)
        mock_client.rule_labels.update_label.return_value = (None, None, "Update failed")

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="Example",
            description="New description",
            state="present",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_rule_labels,
        )

        with pytest.raises(AnsibleFailJson) as result:
            zia_rule_labels.main()

        assert "error" in result.value.result["msg"].lower()

    def test_delete_label_error(self, mock_client):
        """Test handling error when deleting label."""
        mock_existing = MockBox(self.SAMPLE_LABEL)
        mock_client.rule_labels.list_labels.return_value = ([mock_existing], None, None)
        mock_client.rule_labels.delete_label.return_value = (None, None, "Delete failed")

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="Example",
            state="absent",
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_rule_labels,
        )

        with pytest.raises(AnsibleFailJson) as result:
            zia_rule_labels.main()

        assert "error" in result.value.result["msg"].lower()
