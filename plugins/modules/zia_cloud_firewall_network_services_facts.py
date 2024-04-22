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
module: zia_cloud_firewall_network_services_facts
short_description: "Gets a list of all network services."
description:
  - "Gets a list of all network services."
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
    description: "The unique identifier for the network services"
    required: false
    type: int
  name:
    description: "The network services name"
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Gather Information Details of all Network Services
  zscaler.ziacloud.zia_cloud_firewall_network_services_facts:
    provider: '{{ provider }}'

- name: Gather Information Details of a Network Services by Name
  zscaler.ziacloud.zia_cloud_firewall_network_services_facts:
    provider: '{{ provider }}'
    name: "ICMP_ANY"
"""

RETURN = r"""
# Returns information on a specific network services.
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    service_id = module.params.get("id", None)
    service_name = module.params.get("name", None)
    client = ZIAClientHelper(module)
    services = []
    if service_id is not None:
        service = client.firewall.get_network_service(service_id).to_dict()
        services = [service]
    else:
        services = client.firewall.list_network_services().to_list()
        if service_name is not None:
            service = None
            for svc in services:
                if svc.get("name", None) == service_name:
                    service = svc
                    break
            if service is None:
                module.fail_json(
                    msg="Failed to retrieve service: '%s'" % (service_name)
                )
            services = [service]
    module.exit_json(changed=False, data=services)


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
