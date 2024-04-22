#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 Zscaler Inc, <devrel@zscaler.com>

#                             MIT License
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

DOCUMENTATION = r"""
---
module: zia_cloud_firewall_ip_destination_groups_facts
short_description: "Gets a list of all IP destination groups"
description:
  - "Gets a list of all IP destination groups"
author:
  - William Guilherme (@willguibr)
version_added: "0.1.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation

options:
  id:
    description: "Unique identifer for the destination IP group"
    required: false
    type: int
  name:
    description: "Destination IP group name"
    required: false
    type: str
  exclude_type:
    description: Filter based on the IP destination group's type.
    required: false
    type: str
    choices:
      - DSTN_IP
      - DSTN_FQDN
      - DSTN_DOMAIN
      - DSTN_OTHER
"""

EXAMPLES = r"""
- name: Gather Information of all Destination Group
  zscaler.ziacloud.zia_fw_filtering_ip_destination_groups_facts:
    provider: '{{ provider }}'

- name: Gather Information of a Destination Group by Name
  zscaler.ziacloud.zia_fw_filtering_ip_destination_groups_facts:
    provider: '{{ provider }}'
    name: "example"
"""

RETURN = r"""
# Returns information on a specific or all destination groups.
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    group_id = module.params.get("id")
    group_name = module.params.get("name")
    exclude_type = module.params.get("exclude_type")
    client = ZIAClientHelper(module)
    groups = []

    if group_id is not None:
        group = client.firewall.get_ip_destination_group(group_id).to_dict()
        groups = [group]
    else:
        # Pass the exclude_type parameter to the SDK method
        groups = client.firewall.list_ip_destination_groups(
            exclude_type=exclude_type
        ).to_list()
        if group_name is not None:
            group = None
            for dest in groups:
                if dest.get("name") == group_name:
                    group = dest
                    break
            if group is None:
                module.fail_json(
                    msg=f"Failed to retrieve destination ip group: '{group_name}'"
                )
            groups = [group]
    module.exit_json(changed=False, data=groups)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        name=dict(type="str", required=False),
        id=dict(type="int", required=False),
        exclude_type=dict(
            type="str",
            required=False,
            choices=[
                "DSTN_IP",
                "DSTN_FQDN",
                "DSTN_DOMAIN",
                "DSTN_OTHER",
            ],
        ),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
