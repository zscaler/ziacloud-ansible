# -*- coding: utf-8 -*-

# Copyright: (c) 2023, William Guilherme  (@willguibr)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):
    # Common configuration for all ZIA services

    # Formatted for Modules
    CREDENTIALS_SET = """
options:
    username:
        description: ""
        required: true
        type: str
    password:
        description: ""
        required: true
        type: str
    api_key:
        description: ""
        required: true
        type: str
    cloud:
        description: ""
        required: true
        type: str
    """

    PROVIDER = r"""
options:
    provider:
        description:
            - A dict object containing connection details.
        version_added: 1.0.0
        required: true
        type: dict
        suboptions:
            username:
                description: ""
                required: true
                type: str
            password:
                description: ""
                required: true
                type: str
            api_key:
                description: ""
                required: true
                type: str
            cloud:
                description: ""
                required: true
                type: str
"""

    ENABLED_STATE = """
options:
    state:
        description:
            - The state.
        type: str
        default: present
        choices:
            - present
            - absent
            - enabled
            - disabled
"""
