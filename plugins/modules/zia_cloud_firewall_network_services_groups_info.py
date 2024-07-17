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
module: zia_cloud_firewall_network_services_groups_info
short_description: "Gets a list of all network service groups."
description:
  - "Gets a list of all network service groups."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
notes:
    - Check mode is not supported.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation

options:
  id:
    description: "A unique identifier of the network services groups"
    required: false
    type: int
  name:
    description: "The name of the network services groups"
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Gather Information Details of all network services groups
  zscaler.ziacloud.zia_cloud_firewall_network_services_groups_info:
    provider: '{{ provider }}'

- name: Gather Information Details of a specific network services group
  zscaler.ziacloud.zia_cloud_firewall_network_services_groups_info:
    provider: '{{ provider }}'
    name: "Corporate Custom SSH TCP_10022"
"""

RETURN = r"""
# Returns information on a specific Network Services Groups.
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    group_id = module.params.get("id", None)
    group_name = module.params.get("name", None)
    client = ZIAClientHelper(module)
    service_groups = []

    if group_id is not None:
        service_group = client.firewall.get_network_svc_group(group_id).to_dict()
        service_groups = [service_group]
    else:
        service_groups = client.firewall.list_network_svc_groups(
            search=group_name
        ).to_list()
        if not service_groups:
            module.fail_json(
                msg="Failed to retrieve network services group: '%s'" % (group_name)
            )
        elif group_name is not None:
            service_group = None
            for service in service_groups:
                if service.get("name", None) == group_name:
                    service_group = service
                    break

            if service_group is None:
                module.fail_json(
                    msg="Failed to retrieve network services group: '%s'. Available services: %s"
                    % (group_name, service_groups)
                )
            service_groups = [service_group]

    module.exit_json(changed=False, data=service_groups)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        name=dict(type="str", required=False),
        id=dict(type="int", required=False),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
