# -*- coding: utf-8 -*-
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

from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
    to_snake_case,
    convert_keys_to_snake_case,
    deleteNone,
    validate_latitude,
    validate_longitude,
    diff_suppress_func_coordinate,
    convert_to_minutes,
    normalize_list,
    normalize_boolean_attributes,
    preprocess_rule,
)


class TestToSnakeCase:
    def test_simple_camel(self):
        assert to_snake_case("simpleCase") == "simple_case"

    def test_pascal(self):
        assert to_snake_case("PascalCase") == "pascal_case"

    def test_multiple_caps(self):
        assert to_snake_case("HTTPResponse") == "h_t_t_p_response"

    def test_single_word(self):
        assert to_snake_case("lower") == "lower"


class TestConvertKeysToSnakeCase:
    def test_dict_keys(self):
        data = {"camelCase": 1, "AnotherKey": 2}
        result = convert_keys_to_snake_case(data)
        assert result == {"camel_case": 1, "another_key": 2}

    def test_nested_dict(self):
        data = {"innerCamel": {"nestedKey": 1}}
        result = convert_keys_to_snake_case(data)
        assert result == {"inner_camel": {"nested_key": 1}}

    def test_list_of_dicts(self):
        data = [{"camelCase": 1}]
        result = convert_keys_to_snake_case(data)
        assert result == [{"camel_case": 1}]

    def test_primitive(self):
        assert convert_keys_to_snake_case(42) == 42
        assert convert_keys_to_snake_case("str") == "str"


class TestDeleteNone:
    def test_removes_none_values(self):
        d = {"a": 1, "b": None, "c": 3}
        result = deleteNone(d)
        assert result == {"a": 1, "c": 3}

    def test_removes_none_keys(self):
        d = {None: 1, "a": 2}
        result = deleteNone(d)
        assert "a" in result
        assert None not in result

    def test_nested_dict(self):
        d = {"a": {"b": None, "c": 1}}
        result = deleteNone(d)
        assert result == {"a": {"c": 1}}

    def test_list(self):
        d = [1, None, 2]
        result = deleteNone(d)
        assert result == [1, 2]

    def test_tuple(self):
        d = (1, None, 2)
        result = deleteNone(d)
        assert result == (1, 2)


class TestValidateLatitude:
    def test_valid(self):
        assert validate_latitude(0) == (None, None)
        assert validate_latitude(90) == (None, None)
        assert validate_latitude(-90) == (None, None)

    def test_out_of_range_high(self):
        err = validate_latitude(91)
        assert err[1] is not None
        assert "90" in err[1][0]

    def test_out_of_range_low(self):
        err = validate_latitude(-91)
        assert err[1] is not None
        assert "-90" in err[1][0]

    def test_invalid_value(self):
        err = validate_latitude("not_a_number")
        assert err[1] is not None
        assert "float" in err[1][0]


class TestValidateLongitude:
    def test_valid(self):
        assert validate_longitude(0) == (None, None)
        assert validate_longitude(180) == (None, None)
        assert validate_longitude(-180) == (None, None)

    def test_out_of_range_high(self):
        err = validate_longitude(181)
        assert err[1] is not None
        assert "180" in err[1][0]

    def test_out_of_range_low(self):
        err = validate_longitude(-181)
        assert err[1] is not None
        assert "-180" in err[1][0]

    def test_invalid_value(self):
        err = validate_longitude("x")
        assert err[1] is not None


class TestDiffSuppressFuncCoordinate:
    def test_both_none(self):
        assert diff_suppress_func_coordinate(None, None) is True

    def test_one_none(self):
        assert diff_suppress_func_coordinate(None, 1.0) is False
        assert diff_suppress_func_coordinate(1.0, None) is False

    def test_equal_values(self):
        assert diff_suppress_func_coordinate(1.0, 1.0) is True

    def test_small_diff_rounds_equal(self):
        assert diff_suppress_func_coordinate(1.0000001, 1.0) is True

    def test_larger_diff(self):
        assert diff_suppress_func_coordinate(1.001, 1.0) is False

    def test_invalid_value(self):
        assert diff_suppress_func_coordinate("abc", 1.0) is False


class TestConvertToMinutes:
    def test_minute(self):
        assert convert_to_minutes(5, "MINUTE") == 5

    def test_hour(self):
        assert convert_to_minutes(2, "HOUR") == 120

    def test_day(self):
        assert convert_to_minutes(1, "DAY") == 1440

    def test_unknown_unit(self):
        assert convert_to_minutes(10, "UNKNOWN") == 10


class TestNormalizeList:
    def test_sorts_and_lowers(self):
        result = normalize_list(["C", "a", "B"])
        assert result == ["a", "b", "c"]

    def test_strips_whitespace(self):
        result = normalize_list(["  a  ", "b"])
        assert result == ["a", "b"]

    def test_removes_empty(self):
        result = normalize_list(["a", "", "  ", "b"])
        assert result == ["a", "b"]

    def test_removes_duplicates(self):
        result = normalize_list(["a", "A", "a"])
        assert result == ["a"]

    def test_not_list(self):
        assert normalize_list("not a list") == []
        assert normalize_list(None) == []


class TestNormalizeBooleanAttributes:
    def test_sets_none_to_false(self):
        rule = {"enabled": None}
        result = normalize_boolean_attributes(rule, ["enabled"])
        assert result["enabled"] is False

    def test_preserves_true(self):
        rule = {"enabled": True}
        result = normalize_boolean_attributes(rule, ["enabled"])
        assert result["enabled"] is True

    def test_multiple_attrs(self):
        rule = {"a": None, "b": True}
        result = normalize_boolean_attributes(rule, ["a", "b"])
        assert result["a"] is False
        assert result["b"] is True


class TestPreprocessRule:
    def test_dict_list_to_ids(self):
        rule = {"groups": [{"id": 1, "name": "g1"}, {"id": 2, "name": "g2"}]}
        result = preprocess_rule(rule, ["groups"])
        assert result["groups"] == [1, 2]

    def test_simple_list_sorted(self):
        rule = {"labels": [3, 1, 2]}
        result = preprocess_rule(rule, ["labels"])
        assert result["labels"] == [1, 2, 3]

    def test_none_unchanged(self):
        rule = {"groups": None}
        result = preprocess_rule(rule, ["groups"])
        assert result["groups"] is None


class TestIsValidIpv4OrRange:
    def test_valid_single_ip(self):
        from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
            is_valid_ipv4_or_range,
        )

        assert is_valid_ipv4_or_range("192.168.1.1") is True

    def test_invalid_ip(self):
        from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
            is_valid_ipv4_or_range,
        )

        assert is_valid_ipv4_or_range("999.999.999.999") is False

    def test_valid_range(self):
        from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
            is_valid_ipv4_or_range,
        )

        assert is_valid_ipv4_or_range("192.168.1.1-192.168.1.10") is True


class TestValidateLocaleCode:
    def test_valid_locale(self):
        from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
            validate_locale_code,
            HAS_BABEL,
        )

        if not HAS_BABEL:
            pytest.skip("babel not installed")
        assert validate_locale_code("en-US") is True

    def test_invalid_locale(self):
        from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
            validate_locale_code,
            HAS_BABEL,
        )

        if not HAS_BABEL:
            pytest.skip("babel not installed")
        assert validate_locale_code("xx-XX") is False


class TestProcessVpnCredentials:
    def test_empty(self):
        from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
            process_vpn_credentials,
        )

        assert process_vpn_credentials([]) == []
        assert process_vpn_credentials(None) == []

    def test_ufqdn_valid(self):
        from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
            process_vpn_credentials,
        )

        creds = [{"type": "UFQDN", "fqdn": "host.example.com"}]
        result = process_vpn_credentials(creds)
        assert len(result) == 1
        assert result[0]["type"] == "UFQDN"
        assert result[0]["fqdn"] == "host.example.com"

    def test_ufqdn_missing_fqdn(self):
        from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
            process_vpn_credentials,
        )

        creds = [{"type": "UFQDN"}]
        with pytest.raises(ValueError, match="FQDN"):
            process_vpn_credentials(creds)

    def test_ip_valid(self):
        from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
            process_vpn_credentials,
        )

        creds = [{"type": "IP", "ip_address": "192.168.1.1"}]
        result = process_vpn_credentials(creds)
        assert len(result) == 1
        assert result[0]["type"] == "IP"
        assert result[0]["ip_address"] == "192.168.1.1"

    def test_ip_missing_address(self):
        from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
            process_vpn_credentials,
        )

        creds = [{"type": "IP"}]
        with pytest.raises(ValueError, match="IP address"):
            process_vpn_credentials(creds)


class TestCollectAllItems:
    def test_two_tuple_error(self):
        from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
            collect_all_items,
        )

        def fn(_):
            return ([], "error")

        items, err = collect_all_items(fn)
        assert items is None
        assert err == "error"

    def test_two_tuple_success(self):
        from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
            collect_all_items,
        )

        def fn(_):
            return (["a", "b"], None)

        items, err = collect_all_items(fn)
        assert items == ["a", "b"]
        assert err is None

    def test_three_tuple_error(self):
        from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
            collect_all_items,
        )

        def fn(_):
            return ([], None, "err")

        items, err = collect_all_items(fn)
        assert items is None
        assert err == "err"

    def test_three_tuple_paginated_success(self):
        """Paginated 3-tuple with has_next - collects all pages."""
        from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
            collect_all_items,
        )

        resp_no_next = MagicMock()
        resp_no_next.has_next.return_value = False

        resp_has_next = MagicMock()
        resp_has_next.has_next.return_value = True
        resp_has_next.next.return_value = (["c", "d"], resp_no_next, None)

        def fn(_):
            return (["a", "b"], resp_has_next, None)

        items, err = collect_all_items(fn)
        assert items == ["a", "b", "c", "d"]
        assert err is None

    def test_three_tuple_unexpected_structure(self):
        """Non-2 and non-3 tuple returns error."""
        from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
            collect_all_items,
        )

        def fn(_):
            return ("not a tuple",)

        items, err = collect_all_items(fn)
        assert items is None
        assert "Unexpected" in err


class TestValidateIso3166:
    def test_validate_iso3166_with_pycountry(self):
        try:
            import pycountry
            from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
                validate_iso3166_alpha2,
            )
            assert validate_iso3166_alpha2("US") is True
            assert validate_iso3166_alpha2("BR") is True
            assert validate_iso3166_alpha2("XX") is False
        except ImportError:
            pytest.skip("pycountry not installed")


class TestParseRfc1123:
    def test_parse_rfc1123_success(self):
        from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
            parse_rfc1123_to_epoch_millis,
            HAS_PYTZ,
        )

        if not HAS_PYTZ:
            pytest.skip("pytz not installed")
        result = parse_rfc1123_to_epoch_millis("Mon, 02 Jan 2006 15:04:05 UTC")
        assert isinstance(result, int)
        assert result > 0

    def test_parse_rfc1123_invalid(self):
        from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
            parse_rfc1123_to_epoch_millis,
            HAS_PYTZ,
        )

        if not HAS_PYTZ:
            pytest.skip("pytz not installed")
        with pytest.raises(ValueError, match="Failed to parse"):
            parse_rfc1123_to_epoch_millis("not-a-date")


class TestValidateLocationMgmt:
    def test_surrogate_ip_requires_idle_time(self):
        from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
            validate_location_mgmt,
        )

        with pytest.raises(ValueError, match="idle_time_in_minutes"):
            validate_location_mgmt({"surrogate_ip": True, "idle_time_in_minutes": None})

    def test_idle_time_out_of_range(self):
        from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
            validate_location_mgmt,
        )

        with pytest.raises(ValueError, match="1 to 720"):
            validate_location_mgmt({"idle_time_in_minutes": 1000})

    def test_surrogate_ip_requires_auth(self):
        from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
            validate_location_mgmt,
        )

        with pytest.raises(ValueError, match="Authentication required"):
            validate_location_mgmt({
                "surrogate_ip": True,
                "idle_time_in_minutes": 60,
                "auth_required": False,
            })

    def test_parent_id_requires_ip_addresses(self):
        from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
            validate_location_mgmt,
        )

        with pytest.raises(ValueError, match="ip_addresses"):
            validate_location_mgmt({
                "parent_id": 123,
                "ip_addresses": [],
            })
