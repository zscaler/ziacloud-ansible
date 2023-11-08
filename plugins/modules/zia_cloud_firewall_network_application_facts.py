#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 Zscaler Technology Alliances, <zscaler-partner-labs@z-bd.com>

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

DOCUMENTATION = """
---
module: zia_cloud_firewall_network_application_facts
short_description: "Gets a list of all network application groups."
description:
  - "Gets a list of all network application groups."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
"""

EXAMPLES = """
- name: Gather Information Details of all Network Applicactions
  zscaler.ziacloud.zia_fw_network_application_facts:

- name: Gather Information Details of a Network Applicaction
  zscaler.ziacloud.zia_fw_network_application_facts:
    name: "APNS"
"""

RETURN = """
# Returns information on a specified Network Application(s).
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    network_app_id = module.params.get("id", None)
    network_app_name = module.params.get("name", None)
    client = ZIAClientHelper(module)
    network_apps = []
    if network_app_id is not None:
        network_app = client.firewall.get_network_app(network_app_id).to_dict()
        network_apps = [network_app]
    else:
        network_apps = client.firewall.list_network_apps().to_list()
        if network_app_name is not None:
            network_app = None
            for app in network_apps:
                if app.get("name", None) == network_app_name:
                    network_app = app
                    break
            if network_app is None:
                module.fail_json(
                    msg="Failed to retrieve network application: '%s'"
                    % (network_app_name)
                )
            network_apps = [network_app]
    module.exit_json(changed=False, data=network_apps)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        name=dict(type="str", required=False),
        id=dict(type="str", required=False),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
