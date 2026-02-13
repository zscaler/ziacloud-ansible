# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 Zscaler Inc, <devrel@zscaler.com>
# MIT License

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import sys
import os

COLLECTION_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")
)
if COLLECTION_ROOT not in sys.path:
    sys.path.insert(0, COLLECTION_ROOT)

import pytest
from unittest.mock import MagicMock, patch

from tests.unit.plugins.modules.common.utils import (
    set_module_args,
    AnsibleExitJson,
    AnsibleFailJson,
    ModuleTestCase,
    DEFAULT_PROVIDER,
)

from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)

REAL_ARGUMENT_SPEC = ZIAClientHelper.zia_argument_spec()


class MockBox:
    """Mock Box object to simulate SDK responses"""

    def __init__(self, data):
        self._data = data

    def as_dict(self):
        return self._data

    def __getattr__(self, name):
        return self._data.get(name)


class TestZIARuleLabelsInfoModule(ModuleTestCase):
    """Unit tests for zia_rule_labels_info module."""

    SAMPLE_LABEL = {
        "id": 3687131,
        "name": "Example",
        "description": "Example description",
    }

    SAMPLE_LABEL_2 = {
        "id": 3687132,
        "name": "Example_2",
        "description": "Example 2 description",
    }

    @pytest.fixture
    def mock_client(self):
        """Create a mock ZIA client that preserves argument_spec"""
        with patch(
            "ansible_collections.zscaler.ziacloud.plugins.modules.zia_rule_labels_info.ZIAClientHelper"
        ) as mock_class:
            base_spec = REAL_ARGUMENT_SPEC.copy()
            base_spec.update(
                name=dict(type="str", required=False),
                id=dict(type="int", required=False),
            )
            mock_class.zia_argument_spec.return_value = base_spec
            client_instance = MagicMock()
            mock_class.return_value = client_instance
            yield client_instance

    def test_get_label_by_id(self, mock_client):
        """Test fetching a rule label by ID."""
        mock_label = MockBox(self.SAMPLE_LABEL)
        mock_client.rule_labels.get_label.return_value = (
            mock_label,
            None,
            None,
        )

        set_module_args(provider=DEFAULT_PROVIDER, id=3687131)

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_rule_labels_info,
        )

        with pytest.raises(AnsibleExitJson) as result:
            zia_rule_labels_info.main()

        mock_client.rule_labels.get_label.assert_called_once()
        assert result.value.result["changed"] is False
        assert len(result.value.result["labels"]) == 1
        assert result.value.result["labels"][0]["name"] == "Example"

    def test_get_label_by_name(self, mock_client):
        """Test fetching a rule label by name."""
        mock_labels = [MockBox(self.SAMPLE_LABEL), MockBox(self.SAMPLE_LABEL_2)]
        mock_client.rule_labels.list_labels.return_value = (
            mock_labels,
            None,
            None,
        )

        set_module_args(provider=DEFAULT_PROVIDER, name="Example")

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_rule_labels_info,
        )

        with pytest.raises(AnsibleExitJson) as result:
            zia_rule_labels_info.main()

        assert result.value.result["changed"] is False
        assert len(result.value.result["labels"]) == 1
        assert result.value.result["labels"][0]["name"] == "Example"

    def test_get_all_labels(self, mock_client):
        """Test fetching all rule labels."""
        mock_labels = [MockBox(self.SAMPLE_LABEL), MockBox(self.SAMPLE_LABEL_2)]
        mock_client.rule_labels.list_labels.return_value = (
            mock_labels,
            None,
            None,
        )

        set_module_args(provider=DEFAULT_PROVIDER)

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_rule_labels_info,
        )

        with pytest.raises(AnsibleExitJson) as result:
            zia_rule_labels_info.main()

        assert result.value.result["changed"] is False
        assert len(result.value.result["labels"]) == 2

    def test_get_label_by_id_not_found(self, mock_client):
        """Test fetching a non-existent rule label by ID."""
        mock_client.rule_labels.get_label.return_value = (
            None,
            None,
            "Not Found",
        )

        set_module_args(provider=DEFAULT_PROVIDER, id=999999999)

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_rule_labels_info,
        )

        with pytest.raises(AnsibleFailJson) as result:
            zia_rule_labels_info.main()

        assert "Failed to retrieve Rule Label" in result.value.result["msg"]

    def test_get_label_by_name_not_found(self, mock_client):
        """Test fetching a non-existent rule label by name."""
        mock_labels = [MockBox(self.SAMPLE_LABEL)]
        mock_client.rule_labels.list_labels.return_value = (
            mock_labels,
            None,
            None,
        )

        set_module_args(provider=DEFAULT_PROVIDER, name="NonExistent")

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_rule_labels_info,
        )

        with pytest.raises(AnsibleFailJson) as result:
            zia_rule_labels_info.main()

        assert "not found" in result.value.result["msg"]

    def test_api_error_on_list(self, mock_client):
        """Test handling API error when listing labels."""
        mock_client.rule_labels.list_labels.return_value = (
            None,
            None,
            "API Error",
        )

        set_module_args(provider=DEFAULT_PROVIDER)

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_rule_labels_info,
        )

        with pytest.raises(AnsibleFailJson) as result:
            zia_rule_labels_info.main()

        assert "Error retrieving Rule Labels" in result.value.result["msg"]
