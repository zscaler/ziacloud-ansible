# -*- coding: utf-8 -*-
# Copyright (c) 2023 Zscaler Inc, <devrel@zscaler.com>
# MIT License - Auto-generated

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
    def __init__(self, data):
        self._data = data or {}

    def as_dict(self):
        return self._data

    def get(self, key, default=None):
        return self._data.get(key, default)

    def __getattr__(self, name):
        return self._data.get(name)


class TestZIAFileTypeCategoriesInfoModule(ModuleTestCase):
    @pytest.fixture
    def mock_client(self):
        with patch(
            "ansible_collections.zscaler.ziacloud.plugins.modules.zia_file_type_categories_info.ZIAClientHelper"
        ) as mock_class:
            mock_class.zia_argument_spec.return_value = REAL_ARGUMENT_SPEC.copy()
            client_instance = MagicMock()
            mock_class.return_value = client_instance

            client_instance.file_type_control_rule.list_file_type_categories.return_value = (
                [
                    MockBox({"id": 1, "name": "PDF", "extension": "pdf"}),
                    MockBox({"id": 2, "name": "DOC", "extension": "doc"}),
                ],
                None,
                None,
            )
            yield client_instance

    def test_list_all_categories(self, mock_client):
        """Test listing all file type categories with no params."""
        mock_client.file_type_control_rule.list_file_type_categories.return_value = (
            [
                MockBox({"id": 1, "name": "PDF"}),
                MockBox({"id": 2, "name": "DOC"}),
            ],
            None,
            None,
        )
        set_module_args(provider=DEFAULT_PROVIDER)

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_file_type_categories_info,
        )

        with pytest.raises(AnsibleExitJson) as result:
            zia_file_type_categories_info.main()

        mock_client.file_type_control_rule.list_file_type_categories.assert_called_once()
        assert result.value.result["changed"] is False
        assert "file_type_categories" in result.value.result
        assert len(result.value.result["file_type_categories"]) == 2

    def test_list_with_enums(self, mock_client):
        """Test listing file type categories with enums parameter."""
        mock_client.file_type_control_rule.list_file_type_categories.return_value = (
            [MockBox({"id": 1, "name": "PDF"})],
            None,
            None,
        )
        set_module_args(
            provider=DEFAULT_PROVIDER,
            enums=["ZSCALERDLP"],
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_file_type_categories_info,
        )

        with pytest.raises(AnsibleExitJson) as result:
            zia_file_type_categories_info.main()

        call_args = mock_client.file_type_control_rule.list_file_type_categories.call_args
        assert call_args[1]["query_params"]["enums"] == ["ZSCALERDLP"]

    def test_list_with_exclude_custom_file_types(self, mock_client):
        """Test listing with exclude_custom_file_types parameter."""
        mock_client.file_type_control_rule.list_file_type_categories.return_value = (
            [MockBox({"id": 1, "name": "PDF"})],
            None,
            None,
        )
        set_module_args(
            provider=DEFAULT_PROVIDER,
            enums=["FILETYPECATEGORYFORFILETYPECONTROL"],
            exclude_custom_file_types=True,
        )

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_file_type_categories_info,
        )

        with pytest.raises(AnsibleExitJson) as result:
            zia_file_type_categories_info.main()

        call_args = mock_client.file_type_control_rule.list_file_type_categories.call_args
        assert call_args[1]["query_params"]["exclude_custom_file_types"] is True

    def test_empty_result(self, mock_client):
        """Test empty result from API."""
        mock_client.file_type_control_rule.list_file_type_categories.return_value = (
            [],
            None,
            None,
        )
        set_module_args(provider=DEFAULT_PROVIDER)

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_file_type_categories_info,
        )

        with pytest.raises(AnsibleExitJson) as result:
            zia_file_type_categories_info.main()

        assert result.value.result["file_type_categories"] == []

    def test_api_error(self, mock_client):
        """Test API error handling."""
        mock_client.file_type_control_rule.list_file_type_categories.return_value = (
            None,
            None,
            "API Error",
        )
        set_module_args(provider=DEFAULT_PROVIDER)

        from ansible_collections.zscaler.ziacloud.plugins.modules import (
            zia_file_type_categories_info,
        )

        with pytest.raises(AnsibleFailJson) as result:
            zia_file_type_categories_info.main()

        assert "API Error" in result.value.result["msg"]
