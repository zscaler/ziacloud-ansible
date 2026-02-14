# Copyright (c) 2023 Zscaler Inc, <devrel@zscaler.com>
# MIT License
#
# Common utilities for unit testing Ansible modules.
# Adapted from ZPA collection and Palo Alto Networks testing patterns.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
from unittest.mock import MagicMock, patch

import pytest
from ansible.module_utils import basic
from ansible.module_utils._text import to_bytes


class MockBox:
    """
    A mock Box object that behaves like the Zscaler SDK response objects.
    The SDK returns Box objects which have an as_dict() method.
    """

    def __init__(self, data=None, **kwargs):
        if data is None:
            data = {}
        self._data = dict(data, **kwargs)

    def as_dict(self):
        """Convert to regular dict, like SDK objects do."""
        return self._data.copy()

    def __getattr__(self, name):
        return self._data.get(name)


def set_module_args(**args):
    """
    Set module arguments for testing.
    This injects arguments into the module's input.
    Compatible with Ansible 2.14+ through 2.19+.
    """
    # Minimal internal parameters - only those needed for module init.
    # Avoid params that cause "Unsupported parameters" in newer Ansible.
    if "_ansible_remote_tmp" not in args:
        args["_ansible_remote_tmp"] = "/tmp"
    if "_ansible_keep_remote_files" not in args:
        args["_ansible_keep_remote_files"] = False
    if "_ansible_tmpdir" not in args:
        args["_ansible_tmpdir"] = "/tmp"

    # Create the args JSON for basic._ANSIBLE_ARGS (works for all versions)
    args_json = json.dumps({"ANSIBLE_MODULE_ARGS": args})
    basic._ANSIBLE_ARGS = to_bytes(args_json)

    # Also patch _load_params to return our args directly (for Ansible 2.17+)
    def _mock_load_params():
        return args

    basic._load_params = _mock_load_params


class AnsibleExitJson(SystemExit):
    """
    Exception raised when module calls exit_json().
    Inherits from SystemExit so it won't be caught by 'except Exception'.
    """

    def __init__(self, kwargs):
        self.result = kwargs
        super().__init__(0)


class AnsibleFailJson(SystemExit):
    """
    Exception raised when module calls fail_json().
    Inherits from SystemExit so it won't be caught by 'except Exception'.
    """

    def __init__(self, kwargs):
        self.result = kwargs
        super().__init__(1)


def exit_json(*args, **kwargs):
    """Mock exit_json that raises an exception for testing"""
    if "changed" not in kwargs:
        kwargs["changed"] = False
    raise AnsibleExitJson(kwargs)


def fail_json(*args, **kwargs):
    """Mock fail_json that raises an exception for testing"""
    kwargs["failed"] = True
    raise AnsibleFailJson(kwargs)


class ModuleTestCase:
    """
    Base class for module unit tests.
    Provides common fixtures and helper methods.
    """

    @pytest.fixture(autouse=True)
    def module_mock(self):
        """
        Automatically mock exit_json and fail_json for all tests.
        This allows us to capture module output.
        """
        with patch.multiple(basic.AnsibleModule, exit_json=exit_json, fail_json=fail_json):
            yield

    @pytest.fixture
    def zia_client_mock(self):
        """
        Mock the ZIAClientHelper to avoid actual API calls.
        Returns the mocked client for further configuration.
        """
        with patch("ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.ZIAClientHelper") as client_mock:
            yield client_mock.return_value

    @pytest.fixture
    def mock_client(self):
        """
        Mock the ZIAClientHelper class and return the mock instance.
        This is the primary fixture used by module tests.
        """
        with patch("ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client.ZIAClientHelper") as mock_zia_client_helper_class:
            mock_client_instance = MagicMock()
            mock_zia_client_helper_class.return_value = mock_client_instance
            yield mock_client_instance

    def _run_module(self, module, module_args):
        """
        Run a module with given arguments and return the result.
        Expects module to call exit_json (success).
        """
        set_module_args(**module_args)

        with pytest.raises(AnsibleExitJson) as ex:
            module.main()
        return ex.value.args[0]

    def _run_module_fail(self, module, module_args):
        """
        Run a module with given arguments expecting failure.
        Expects module to call fail_json (failure).
        """
        set_module_args(**module_args)

        with pytest.raises(AnsibleFailJson) as ex:
            module.main()
        return ex.value.args[0]


# Provider configuration for ZIA tests
DEFAULT_PROVIDER = {
    "username": "test_username",
    "password": "test_password",
    "cloud": "zscaler",
    "api_key": "test_api_key",
}
