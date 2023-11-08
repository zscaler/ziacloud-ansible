#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, William Guilherme <wguilherme@securitygeek.io>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: zia_traffic_forwarding_gre_tunnels_info
short_description: ""
description:
  - ""
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
"""

EXAMPLES = """
- name: Gather Information Details of a ZIA User Role
  willguibr.ziacloud.zia_traffic_forwarding_gre_tunnels_info:

- name: Gather Information Details of a ZIA Admin User by Name
  willguibr.ziacloud.zia_traffic_forwarding_gre_tunnels_info:
    name: "IOS"
"""

RETURN = """
# Returns information on a specified ZIA Admin User.
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.willguibr.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)
from ansible_collections.willguibr.ziacloud.plugins.module_utils.zia_traffic_forwarding_gre_tunnels import (
    ZiaGRETunnelsService,
)
