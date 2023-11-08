#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, William Guilherme <wguilherme@securitygeek.io>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: zia_traffic_forwarding_gre_internal_ranges_info
short_description: "GRE tunnel internal IP address ranges."
description:
  - Gets the next available GRE tunnel internal IP address ranges.
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
options:
  username:
    description: "Username of admin user that is provisioned"
    required: true
    type: str
  password:
    description: "Password of the admin user"
    required: true
    type: str
  api_key:
    description: "The obfuscated form of the API key"
    required: true
    type: str
  base_url:
    description: "The host and basePath for the cloud services API"
    required: true
    type: str
  start_ip_address:
    description: "Starting IP address in the range"
    required: true
    type: str
  end_ip_address:
    description: "Ending IP address in the range"
    required: true
    type: str
"""

EXAMPLES = """
- name: Retrieve Details Available GRE Internal Ranges.
  willguibr.ziacloud.zia_traffic_forwarding_gre_internal_ranges_info:

"""

RETURN = """
# Returns information on all available GRE Internal Ranges.
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.willguibr.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)
from ansible_collections.willguibr.ziacloud.plugins.module_utils.zia_gre_internal_ranges import (
    ZiaGREInternalRangesService,
)
