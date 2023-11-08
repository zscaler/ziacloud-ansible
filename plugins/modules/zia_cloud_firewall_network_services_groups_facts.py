#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, Zscaler Technology Alliances <zscaler-partner-labs@z-bd.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: zia_cloud_firewall_network_services_groups_facts
short_description: "Gets a list of all network service groups."
description:
  - "Gets a list of all network service groups."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
extends_documentation_fragment:
    - zscaler.ziacloud.fragments.credentials_set
    - zscaler.ziacloud.fragments.provider
options:
  id:
    description: ""
    required: false
    type: int
  name:
    description: ""
    required: true
    type: str
"""

EXAMPLES = """
- name: Gather Information Details of all network services groups
  zscaler.ziacloud.zia_fw_filtering_network_services_groups_facts:

- name: Gather Information Details of a specific network services group
  zscaler.ziacloud.zia_fw_filtering_network_services_groups_facts:
    name: "Corporate Custom SSH TCP_10022"
"""

RETURN = """
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
