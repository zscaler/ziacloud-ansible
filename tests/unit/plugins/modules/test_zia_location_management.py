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


class TestLocationManagementModule(ModuleTestCase):
    @pytest.fixture
    def mock_client(self):
        with patch("ansible_collections.zscaler.ziacloud.plugins.modules.zia_location_management.ZIAClientHelper") as mock_class:
            mock_class.zia_argument_spec.return_value = REAL_ARGUMENT_SPEC.copy()
            client_instance = MagicMock()
            mock_class.return_value = client_instance

            client_instance.locations.add_location.return_value = (MockBox({"id": 1, "name": "test", "whitelist_urls": [], "blacklist_urls": []}), None, None)
            client_instance.locations.delete_location.return_value = (
                MockBox({"id": 1, "name": "test", "whitelist_urls": [], "blacklist_urls": []}),
                None,
                None,
            )
            client_instance.locations.get_location.return_value = (MockBox({"id": 1, "name": "test", "whitelist_urls": [], "blacklist_urls": []}), None, None)
            client_instance.locations.update_location.return_value = (
                MockBox({"id": 1, "name": "test", "whitelist_urls": [], "blacklist_urls": []}),
                None,
                None,
            )
            client_instance.locations.list_locations.return_value = ([], None, None)
            client_instance.locations.list_sub_locations.return_value = ([], None, None)
            yield client_instance

    def test_list_or_get(self, mock_client):
        mock_client.locations.list_locations.return_value = ([], None, None)
        set_module_args(provider=DEFAULT_PROVIDER, name="test", state="present")
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_location_management

        with pytest.raises(AnsibleExitJson) as result:
            zia_location_management.main()
        assert result.value.result.get("changed", False) is True

    def test_get_by_id(self, mock_client):
        mock_item = MockBox({"id": 1, "name": "test"})
        mock_client.locations.get_location.return_value = (mock_item, None, None)
        set_module_args(provider=DEFAULT_PROVIDER, id=1, name="test")
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_location_management

        with pytest.raises(AnsibleExitJson) as result:
            zia_location_management.main()
        assert result.value.result.get("changed") in (True, False)

    def test_api_error(self, mock_client):
        mock_client.locations.list_locations.return_value = (None, None, "API Error")
        set_module_args(provider=DEFAULT_PROVIDER, name="test", state="present")
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_location_management

        with pytest.raises(AnsibleFailJson):
            zia_location_management.main()

    def test_extranet_fields_passed_to_create(self, mock_client):
        """Extranet attributes must be forwarded to the SDK create payload (profile=EXTRANET)."""
        mock_client.locations.list_locations.return_value = ([], None, None)
        mock_client.locations.add_location.return_value = (MockBox({"id": 10, "name": "USA_SJC_300"}), None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="USA_SJC_300",
            country="UNITED_STATES",
            tz="UNITED_STATES_AMERICA_LOS_ANGELES",
            profile="EXTRANET",
            default_extranet_dns=True,
            default_extranet_ts_pool=True,
            extranet={"id": 22394092},
            extranet_dns={"id": 1322259},
            extranet_ip_pool={"id": 1322260},
            state="present",
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_location_management

        with pytest.raises(AnsibleExitJson):
            zia_location_management.main()

        mock_client.locations.add_location.assert_called_once()
        _args, kwargs = mock_client.locations.add_location.call_args
        assert kwargs.get("extranet") == {"id": 22394092}
        assert kwargs.get("extranet_dns") == {"id": 1322259}
        assert kwargs.get("extranet_ip_pool") == {"id": 1322260}
        assert kwargs.get("default_extranet_dns") is True
        assert kwargs.get("default_extranet_ts_pool") is True

    def test_extranet_idempotent_when_only_name_differs(self, mock_client):
        """Re-running with the same extranet IDs must be a no-op even though the API
        echoes back extra fields (e.g. name) on the id-reference objects."""
        existing = MockBox(
            {
                "id": 25417068,
                "name": "USA_SJC_300",
                "country": "UNITED_STATES",
                "tz": "UNITED_STATES_AMERICA_LOS_ANGELES",
                "profile": "EXTRANET",
                "ofw_enabled": True,
                "ips_control": True,
                "default_extranet_dns": True,
                "default_extranet_ts_pool": True,
                "extranet": {"id": 22394092, "name": "NewExtranet 8432"},
                "extranet_dns": {"id": 1322259, "name": "NewExtranet 5127"},
                "extranet_ip_pool": {"id": 1322260, "name": "NewExtranet 5141"},
            }
        )
        mock_client.locations.list_locations.return_value = ([existing], None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="USA_SJC_300",
            country="UNITED_STATES",
            tz="UNITED_STATES_AMERICA_LOS_ANGELES",
            profile="EXTRANET",
            ofw_enabled=True,
            ips_control=True,
            default_extranet_dns=True,
            default_extranet_ts_pool=True,
            extranet={"id": 22394092},
            extranet_dns={"id": 1322259},
            extranet_ip_pool={"id": 1322260},
            state="present",
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_location_management

        with pytest.raises(AnsibleExitJson) as result:
            zia_location_management.main()

        mock_client.locations.update_location.assert_not_called()
        mock_client.locations.add_location.assert_not_called()
        assert result.value.result["changed"] is False

    def test_extranet_id_change_triggers_update(self, mock_client):
        """A genuine change to an extranet reference id must trigger an update."""
        existing = MockBox(
            {
                "id": 25417068,
                "name": "USA_SJC_300",
                "profile": "EXTRANET",
                "extranet": {"id": 11111111, "name": "Old Extranet"},
            }
        )
        mock_client.locations.list_locations.return_value = ([existing], None, None)
        mock_client.locations.update_location.return_value = (MockBox({"id": 25417068, "name": "USA_SJC_300"}), None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="USA_SJC_300",
            profile="EXTRANET",
            extranet={"id": 22394092},
            state="present",
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_location_management

        with pytest.raises(AnsibleExitJson) as result:
            zia_location_management.main()

        mock_client.locations.update_location.assert_called_once()
        assert result.value.result["changed"] is True

    def test_sublocation_lookup_uses_sublocations_endpoint(self, mock_client):
        """When parent_id is set, the module must look up sublocations under the parent."""
        mock_client.locations.list_sub_locations.return_value = ([], None, None)
        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="AWS_VPC_Sublocation",
            parent_id=21858266,
            ip_addresses=["10.5.0.0-10.5.255.255"],
            state="present",
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_location_management

        with pytest.raises(AnsibleExitJson):
            zia_location_management.main()

        mock_client.locations.list_sub_locations.assert_called_once()
        _args, kwargs = mock_client.locations.list_sub_locations.call_args
        assert kwargs.get("location_id") == 21858266
        # The top-level listing must NOT be used for a sublocation lookup
        mock_client.locations.list_locations.assert_not_called()

    def test_sublocation_idempotent_no_recreate(self, mock_client):
        """A second run with an existing sublocation must not attempt to create it again."""
        existing_sub = MockBox(
            {
                "id": 99,
                "name": "AWS_VPC_Sublocation",
                "parent_id": 21858266,
                "ip_addresses": ["10.5.0.0-10.5.255.255"],
                # 'profile' has an argument-spec default of "NONE", so the persisted
                # resource must echo it back for the comparison to be a true no-op.
                "profile": "NONE",
            }
        )
        mock_client.locations.list_sub_locations.return_value = ([existing_sub], None, None)

        set_module_args(
            provider=DEFAULT_PROVIDER,
            name="AWS_VPC_Sublocation",
            parent_id=21858266,
            ip_addresses=["10.5.0.0-10.5.255.255"],
            state="present",
        )
        from ansible_collections.zscaler.ziacloud.plugins.modules import zia_location_management

        with pytest.raises(AnsibleExitJson) as result:
            zia_location_management.main()

        mock_client.locations.add_location.assert_not_called()
        assert result.value.result["changed"] is False
