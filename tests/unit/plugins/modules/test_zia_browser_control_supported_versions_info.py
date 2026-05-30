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


class TestZIABrowserControlSupportedVersionsInfoModule(ModuleTestCase):
    """Unit tests for zia_browser_control_supported_versions_info module."""

    @property
    def SAMPLE_CHROME(self):
        return {
            "browser_type": "CHROME",
            "versions": ["CH143", "CH142"],
            "older_versions": ["CH100", "CH99"],
        }

    @property
    def SAMPLE_FIREFOX(self):
        return {
            "browser_type": "FIREFOX",
            "versions": ["MF145"],
            "older_versions": ["MF100"],
        }

    @pytest.fixture
    def mock_client(self):
        with patch("ansible_collections.zscaler.ziacloud.plugins.modules.zia_browser_control_supported_versions_info.ZIAClientHelper") as mock_class:
            base_spec = REAL_ARGUMENT_SPEC.copy()
            base_spec.update(
                browser_type=dict(
                    type="str",
                    required=False,
                    choices=["OPERA", "FIREFOX", "MSIE", "MSEDGE", "CHROME", "SAFARI", "OTHER", "MSCHREDGE"],
                ),
                versions=dict(type="list", elements="str", required=False),
                older_versions=dict(type="list", elements="str", required=False),
                query=dict(type="str", required=False),
            )
            mock_class.zia_argument_spec.return_value = base_spec
            client_instance = MagicMock()
            mock_class.return_value = client_instance
            yield client_instance

    def test_get_all_supported_versions(self, mock_client):
        mock_client.secure_browsing.get_supported_browser_versions.return_value = (
            [MockBox(self.SAMPLE_CHROME), MockBox(self.SAMPLE_FIREFOX)],
            None,
            None,
        )

        set_module_args(provider=DEFAULT_PROVIDER)

        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_browser_control_supported_versions_info

        with pytest.raises(AnsibleExitJson) as result:
            zia_browser_control_supported_versions_info.main()

        assert result.value.result["changed"] is False
        assert len(result.value.result["browsers"]) == 2

    def test_filter_by_browser_type(self, mock_client):
        mock_client.secure_browsing.get_supported_browser_versions.return_value = (
            [MockBox(self.SAMPLE_CHROME), MockBox(self.SAMPLE_FIREFOX)],
            None,
            None,
        )

        set_module_args(provider=DEFAULT_PROVIDER, browser_type="CHROME")

        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_browser_control_supported_versions_info

        with pytest.raises(AnsibleExitJson) as result:
            zia_browser_control_supported_versions_info.main()

        assert result.value.result["changed"] is False
        assert len(result.value.result["browsers"]) == 1
        assert result.value.result["browsers"][0]["browser_type"] == "CHROME"

    def test_filter_no_match(self, mock_client):
        mock_client.secure_browsing.get_supported_browser_versions.return_value = (
            [MockBox(self.SAMPLE_CHROME)],
            None,
            None,
        )

        set_module_args(provider=DEFAULT_PROVIDER, browser_type="SAFARI")

        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_browser_control_supported_versions_info

        with pytest.raises(AnsibleExitJson) as result:
            zia_browser_control_supported_versions_info.main()

        assert result.value.result["browsers"] == []

    def test_filter_by_versions(self, mock_client):
        mock_client.secure_browsing.get_supported_browser_versions.return_value = (
            [MockBox(self.SAMPLE_CHROME), MockBox(self.SAMPLE_FIREFOX)],
            None,
            None,
        )

        set_module_args(provider=DEFAULT_PROVIDER, versions=["CH143"])

        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_browser_control_supported_versions_info

        with pytest.raises(AnsibleExitJson) as result:
            zia_browser_control_supported_versions_info.main()

        browsers = result.value.result["browsers"]
        assert len(browsers) == 1
        assert browsers[0]["browser_type"] == "CHROME"
        # versions narrowed to only the searched token; older_versions emptied
        assert browsers[0]["versions"] == ["CH143"]
        assert browsers[0]["older_versions"] == []

    def test_filter_by_older_versions(self, mock_client):
        mock_client.secure_browsing.get_supported_browser_versions.return_value = (
            [MockBox(self.SAMPLE_CHROME), MockBox(self.SAMPLE_FIREFOX)],
            None,
            None,
        )

        set_module_args(provider=DEFAULT_PROVIDER, older_versions=["CH100"])

        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_browser_control_supported_versions_info

        with pytest.raises(AnsibleExitJson) as result:
            zia_browser_control_supported_versions_info.main()

        browsers = result.value.result["browsers"]
        assert len(browsers) == 1
        assert browsers[0]["browser_type"] == "CHROME"
        # older_versions narrowed to the searched token; versions emptied
        assert browsers[0]["older_versions"] == ["CH100"]
        assert browsers[0]["versions"] == []

    def test_filter_versions_combined_with_browser_type(self, mock_client):
        mock_client.secure_browsing.get_supported_browser_versions.return_value = (
            [MockBox(self.SAMPLE_CHROME), MockBox(self.SAMPLE_FIREFOX)],
            None,
            None,
        )

        # browser_type CHROME AND versions MF145 (only Firefox has MF145) -> no match
        set_module_args(provider=DEFAULT_PROVIDER, browser_type="CHROME", versions=["MF145"])

        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_browser_control_supported_versions_info

        with pytest.raises(AnsibleExitJson) as result:
            zia_browser_control_supported_versions_info.main()

        assert result.value.result["browsers"] == []

    def test_jmespath_query_projection(self, mock_client):
        mock_client.secure_browsing.get_supported_browser_versions.return_value = (
            [MockBox(self.SAMPLE_CHROME), MockBox(self.SAMPLE_FIREFOX)],
            None,
            None,
        )

        set_module_args(provider=DEFAULT_PROVIDER, query="[?contains(versions, 'CH143')].browser_type")

        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_browser_control_supported_versions_info

        with pytest.raises(AnsibleExitJson) as result:
            zia_browser_control_supported_versions_info.main()

        assert result.value.result["browsers"] == ["CHROME"]

    def test_jmespath_query_no_match_returns_empty(self, mock_client):
        mock_client.secure_browsing.get_supported_browser_versions.return_value = (
            [MockBox(self.SAMPLE_CHROME)],
            None,
            None,
        )

        set_module_args(provider=DEFAULT_PROVIDER, query="[?browser_type=='SAFARI']")

        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_browser_control_supported_versions_info

        with pytest.raises(AnsibleExitJson) as result:
            zia_browser_control_supported_versions_info.main()

        assert result.value.result["browsers"] == []

    def test_invalid_jmespath_query_fails(self, mock_client):
        mock_client.secure_browsing.get_supported_browser_versions.return_value = (
            [MockBox(self.SAMPLE_CHROME)],
            None,
            None,
        )

        set_module_args(provider=DEFAULT_PROVIDER, query="[?broken(")

        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_browser_control_supported_versions_info

        with pytest.raises(AnsibleFailJson) as result:
            zia_browser_control_supported_versions_info.main()

        assert "JMESPath" in result.value.result["msg"]

    def test_api_error(self, mock_client):
        mock_client.secure_browsing.get_supported_browser_versions.return_value = (None, None, "API Error")

        set_module_args(provider=DEFAULT_PROVIDER)

        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_browser_control_supported_versions_info

        with pytest.raises(AnsibleFailJson) as result:
            zia_browser_control_supported_versions_info.main()

        assert "Error retrieving supported browser versions" in result.value.result["msg"]
