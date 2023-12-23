# -*- coding: utf-8 -*-

# Copyright: (c) 2023, William Guilherme  (@willguibr)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):
    # Standard files documentation fragment
    DOCUMENTATION = r"""
options:
    username:
        description:
            - A string that contains the email ID of the API admin
        required: true
        type: str
    password:
        description:
            - A string that contains the password for the API admin
        required: true
        type: str
    api_key:
        description:
            - A string that contains the obfuscated API key
        required: true
        type: str
    cloud:
        description:
            - The Zscaler cloud name was provisioned for your organization
        required: true
        type: str
        choices: ['zscloud', 'zscaler', 'zscalerone', 'zscalertwo', 'zscalerthree', 'zscalerbeta', 'zscalergov', 'zscalerten']
"""

    # Formatted for Modules
    CREDENTIALS_SET = """
options:
    username:
        description:
            - A string that contains the email ID of the API admin
        required: true
        type: str
    password:
        description:
            - A string that contains the password for the API admin
        required: true
        type: str
    api_key:
        description:
            - A string that contains the obfuscated API key
        required: true
        type: str
    cloud:
        description:
            - The Zscaler cloud name was provisioned for your organization
        required: true
        type: str
        choices: ['zscloud', 'zscaler', 'zscalerone', 'zscalertwo', 'zscalerthree', 'zscalerbeta', 'zscalergov', 'zscalerten']
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
                description:
                    - A string that contains the email ID of the API admin
                required: true
                type: str
            password:
                description:
                    - A string that contains the password for the API admin
                required: true
                type: str
            api_key:
                description:
                    - A string that contains the obfuscated API key
                required: true
                type: str
            cloud:
                description:
                    - The Zscaler cloud name was provisioned for your organization
                required: true
                type: str
                choices: ['zscloud', 'zscaler', 'zscalerone', 'zscalertwo', 'zscalerthree', 'zscalerbeta', 'zscalergov', 'zscalerten']
"""

    STATE = r"""
options:
    state:
        description:
            - The state.
        type: str
        default: present
        choices:
            - present
            - absent
"""

    ENABLED_STATE = r"""
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
