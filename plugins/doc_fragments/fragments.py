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
    DOCUMENTATION = r"""
options:
    username:
        description:
            - A string that contains the email ID of the API admin.
        required: false
        type: str
    password:
        description:
            - A string that contains the password for the API admin.
        required: false
        type: str
    api_key:
        description:
            - A string that contains the obfuscated API key.
        required: false
        type: str
    cloud:
        description:
            - The Zscaler cloud name provisioned for your organization.
        required: false
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
            - beta
            - production
    use_legacy_client:
        description:
            - Whether to use the legacy Zscaler API client.
        required: false
        type: bool
        default: false
    sandbox_token:
        description:
            - A string that contains the Sandbox API Key.
        type: str
        required: false
    sandbox_cloud:
        description:
            - The Sandbox cloud environment for API access.
        type: str
        required: false
    client_id:
        description:
            - The client ID for OAuth2 authentication.
        type: str
        required: false
    client_secret:
        description:
            - The client secret for OAuth2 authentication.
        type: str
        required: false
    private_key:
        description:
            - The private key for JWT-based OAuth2 authentication.
        type: str
        required: false
    vanity_domain:
        description:
            - The vanity domain provisioned by Zscaler for OAuth2 flows.
        type: str
        required: false
"""

    PROVIDER = r"""
options:
    provider:
        description:
            - A dict containing authentication credentials.
        type: dict
        required: false
        suboptions:
            username:
                description:
                    - Email ID of the API admin.
                type: str
                required: false
            password:
                description:
                    - Password for the API admin.
                type: str
                required: false
            api_key:
                description:
                    - Obfuscated API key.
                type: str
                required: false
            cloud:
                description:
                    - Zscaler cloud name.
                type: str
                required: false
                choices:
                    - zscloud
                    - zscaler
                    - zscalerone
                    - zscalertwo
                    - zscalerthree
                    - zscalerbeta
                    - zscalergov
                    - zscalerten
                    - beta
                    - production
            use_legacy_client:
                description:
                    - Whether to use the legacy Zscaler API client.
                type: bool
                required: false
                default: false
            sandbox_token:
                description:
                    - Sandbox API Key.
                type: str
                required: false
            sandbox_cloud:
                description:
                    - Sandbox Cloud environment.
                type: str
                required: false
            client_id:
                description:
                    - OAuth2 client ID.
                type: str
                required: false
            client_secret:
                description:
                    - OAuth2 client secret.
                type: str
                required: false
            private_key:
                description:
                    - Private key for OAuth2 JWT.
                type: str
                required: false
            vanity_domain:
                description:
                    - Vanity domain for OAuth2.
                type: str
                required: false
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

    MODIFIED_STATE = r"""
options:
    state:
        description:
            - Specifies the desired state of the resource.
        type: str
        default: present
        choices:
            - present
"""
