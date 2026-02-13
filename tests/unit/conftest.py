# Copyright (c) 2023 Zscaler Inc, <devrel@zscaler.com>
# MIT License
#
# Pytest configuration for unit tests

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import sys
import os

import pytest

# Set up the ansible_collections namespace properly
# The collection is at: /path/to/ansible_collections/zscaler/ziacloud
COLLECTION_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)

# Go up to ansible_collections parent
ANSIBLE_COLLECTIONS_PARENT = os.path.abspath(
    os.path.join(COLLECTION_ROOT, "..", "..", "..")
)

# Add to sys.path if not already there
if ANSIBLE_COLLECTIONS_PARENT not in sys.path:
    sys.path.insert(0, ANSIBLE_COLLECTIONS_PARENT)

# Also add collection root for local imports
if COLLECTION_ROOT not in sys.path:
    sys.path.insert(0, COLLECTION_ROOT)


# Store original _load_params function
_original_load_params = None


@pytest.fixture(autouse=True)
def reset_module_args():
    """
    Reset Ansible module args between tests.
    This prevents test pollution.
    """
    from ansible.module_utils import basic

    global _original_load_params

    # Save original _load_params on first run
    if _original_load_params is None and hasattr(basic, '_load_params'):
        _original_load_params = basic._load_params

    # Clear the old-style args
    basic._ANSIBLE_ARGS = None

    # Clear the environment variable used by Ansible 2.15+
    if "ANSIBLE_MODULE_ARGS" in os.environ:
        del os.environ["ANSIBLE_MODULE_ARGS"]

    yield

    # Clean up after test
    basic._ANSIBLE_ARGS = None
    if "ANSIBLE_MODULE_ARGS" in os.environ:
        del os.environ["ANSIBLE_MODULE_ARGS"]

    # Restore original _load_params if it was patched
    if _original_load_params is not None:
        basic._load_params = _original_load_params
