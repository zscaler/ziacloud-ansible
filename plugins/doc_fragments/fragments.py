# -*- coding: utf-8 -*-

# Copyright (c) 2023 Zscaler Inc, <devrel@zscaler.com>

#                              MIT License
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):
    # Standard files documentation fragment

    DOCUMENTATION = r"""
options:
    username:
        description:
            - A string that contains the email ID of the API admin.
        required: true
        type: str
    password:
        description:
            - A string that contains the password for the API admin.
        required: true
        type: str
    api_key:
        description:
            - A string that contains the obfuscated API key.
        required: true
        type: str
    cloud:
        description:
            - The Zscaler cloud name was provisioned for your organization.
        required: true
        type: str
        choices:
            - zscloud
            - zscaler
            - zscalerone
            - zscalertwo
            - zscalerthree
            - zscalerbeta
            - zscalergov
            - zscalerten
    sandbox_token:
        description:
            - A string that contains the Sandbox API Key.
        type: str
        required: false
"""

    PROVIDER = r"""
options:
    provider:
        description:
            - A dict object containing connection details. This is optional; credentials can also be provided directly at the top level.
        type: dict
        required: False
        suboptions:
            username:
                description:
                    - A string that contains the email ID of the API admin.
                type: str
                required: True
            password:
                description:
                    - A string that contains the password for the API admin.
                type: str
                required: True
            api_key:
                description:
                    - A string that contains the obfuscated API key.
                type: str
                required: True
            cloud:
                description:
                    - The Zscaler cloud name was provisioned for your organization.
                type: str
                required: True
                choices:
                    - zscloud
                    - zscaler
                    - zscalerone
                    - zscalertwo
                    - zscalerthree
                    - zscalerbeta
                    - zscalergov
                    - zscalerten
            sandbox_token:
                description:
                    - A string that contains the Sandbox API Key.
                type: str
                required: False
"""

    STATE = r"""
options:
    state:
        description:
            - Specifies the desired state of the resource.
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
            - Specifies the desired state of the resource.
        type: str
        default: present
        choices:
            - present
            - absent
            - enabled
            - disabled
"""
