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

SAMPLE_ACTIONS = [
    "ALLOW_STREAMING_VIEW_LISTEN",
    "ALLOW_STREAMING_UPLOAD",
    "BLOCK_STREAMING_UPLOAD",
    "CAUTION_STREAMING_VIEW_LISTEN",
    "ISOLATE_STREAMING_VIEW_LISTEN",
]


class TestCloudAppControlRuleActionsInfoModule(ModuleTestCase):
    @pytest.fixture
    def mock_client(self):
        with patch("ansible_collections.zscaler.ziacloud.plugins.modules.zia_cloud_app_control_rule_actions_info.ZIAClientHelper") as mock_class:
            mock_class.zia_argument_spec.return_value = REAL_ARGUMENT_SPEC.copy()
            client_instance = MagicMock()
            mock_class.return_value = client_instance

            client_instance.cloudappcontrol.list_available_actions.return_value = (
                list(SAMPLE_ACTIONS),
                None,
                None,
            )
            yield client_instance

    def test_list_all_actions(self, mock_client):
        set_module_args(provider=DEFAULT_PROVIDER, type="STREAMING_MEDIA", cloud_apps=["DROPBOX"])
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_cloud_app_control_rule_actions_info

        with pytest.raises(AnsibleExitJson) as result:
            zia_cloud_app_control_rule_actions_info.main()
        res = result.value.result
        assert res["changed"] is False
        assert res["available_actions"] == SAMPLE_ACTIONS
        assert "ISOLATE_STREAMING_VIEW_LISTEN" not in res["available_actions_without_isolate"]
        assert res["isolate_actions"] == ["ISOLATE_STREAMING_VIEW_LISTEN"]

    def test_action_prefixes_filter(self, mock_client):
        set_module_args(
            provider=DEFAULT_PROVIDER,
            type="STREAMING_MEDIA",
            cloud_apps=["DROPBOX"],
            action_prefixes=["ALLOW", "BLOCK"],
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_cloud_app_control_rule_actions_info

        with pytest.raises(AnsibleExitJson) as result:
            zia_cloud_app_control_rule_actions_info.main()
        filtered = result.value.result["filtered_actions"]
        assert filtered == [
            "ALLOW_STREAMING_VIEW_LISTEN",
            "ALLOW_STREAMING_UPLOAD",
            "BLOCK_STREAMING_UPLOAD",
        ]

    def test_api_error(self, mock_client):
        mock_client.cloudappcontrol.list_available_actions.return_value = (None, None, "API Error")
        set_module_args(provider=DEFAULT_PROVIDER, type="STREAMING_MEDIA", cloud_apps=["DROPBOX"])
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_cloud_app_control_rule_actions_info

        with pytest.raises(AnsibleFailJson):
            zia_cloud_app_control_rule_actions_info.main()

    def test_missing_cloud_apps_fails(self, mock_client):
        set_module_args(provider=DEFAULT_PROVIDER, type="STREAMING_MEDIA", cloud_apps=[])
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_cloud_app_control_rule_actions_info

        with pytest.raises(AnsibleFailJson):
            zia_cloud_app_control_rule_actions_info.main()

    def test_jmespath_query_filter(self, mock_client):
        set_module_args(
            provider=DEFAULT_PROVIDER,
            type="STREAMING_MEDIA",
            cloud_apps=["DROPBOX"],
            query="[?starts_with(@, 'ALLOW')]",
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_cloud_app_control_rule_actions_info

        with pytest.raises(AnsibleExitJson) as result:
            zia_cloud_app_control_rule_actions_info.main()
        res = result.value.result
        assert res["available_actions"] == [
            "ALLOW_STREAMING_VIEW_LISTEN",
            "ALLOW_STREAMING_UPLOAD",
        ]
        # Derived lists are computed from the narrowed action list
        assert res["isolate_actions"] == []
        assert res["available_actions_without_isolate"] == [
            "ALLOW_STREAMING_VIEW_LISTEN",
            "ALLOW_STREAMING_UPLOAD",
        ]

    def test_jmespath_query_exclude_isolate(self, mock_client):
        set_module_args(
            provider=DEFAULT_PROVIDER,
            type="STREAMING_MEDIA",
            cloud_apps=["DROPBOX"],
            query="[?!starts_with(@, 'ISOLATE')]",
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_cloud_app_control_rule_actions_info

        with pytest.raises(AnsibleExitJson) as result:
            zia_cloud_app_control_rule_actions_info.main()
        res = result.value.result
        assert "ISOLATE_STREAMING_VIEW_LISTEN" not in res["available_actions"]
        assert res["isolate_actions"] == []

    def test_jmespath_query_no_match_returns_empty(self, mock_client):
        set_module_args(
            provider=DEFAULT_PROVIDER,
            type="STREAMING_MEDIA",
            cloud_apps=["DROPBOX"],
            query="[?@ == 'DOES_NOT_EXIST']",
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_cloud_app_control_rule_actions_info

        with pytest.raises(AnsibleExitJson) as result:
            zia_cloud_app_control_rule_actions_info.main()
        assert result.value.result["available_actions"] == []

    def test_invalid_jmespath_query_fails(self, mock_client):
        set_module_args(
            provider=DEFAULT_PROVIDER,
            type="STREAMING_MEDIA",
            cloud_apps=["DROPBOX"],
            query="[?broken(",
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_cloud_app_control_rule_actions_info

        with pytest.raises(AnsibleFailJson) as result:
            zia_cloud_app_control_rule_actions_info.main()
        assert "JMESPath" in result.value.result["msg"]
