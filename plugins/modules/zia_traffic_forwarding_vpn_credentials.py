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
module: zia_traffic_forwarding_vpn_credentials
short_description: "Adds VPN credentials that can be associated to locations."
description:
  - "Adds VPN credentials that can be associated to locations."
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
    description:
      - VPN credential id
    required: false
    type: int
  type:
    description:
      - VPN authentication type (i.e., how the VPN credential is sent to the server).
      - It is not modifiable after VpnCredential is created.
    required: false
    type: str
    default: "UFQDN"
    choices:
    - IP
    - UFQDN
  fqdn:
    description: "Fully Qualified Domain Name. Applicable only to UFQDN or XAUTH (or HOSTED_MOBILE_USERS) auth type."
    required: false
    type: str
  pre_shared_key:
    description: "Pre-shared key. This is a required field for UFQDN and IP auth type."
    required: false
    type: bool
  comments:
    description: "Additional information about this VPN credential."
    required: false
    type: str
  state:
    description:
      - Whether the app connector group should be present or absent.
    type: str
    choices:
        - present
        - absent
    default: present

"""

EXAMPLES = """

- name: Create/Update/Delete VPN Credentials Type IP.
  zscaler.ziacloud.zia_traffic_forwarding_vpn_credentials:
    type: "IP"
    ip_address: "1.1.1.1"
    comments: "Created via Ansible"
    pre_shared_key: "newPassword123!"

- name: Create/Update/Delete VPN Credentials Type UFQDN.
  zscaler.ziacloud.zia_traffic_forwarding_vpn_credentials:
    type: "UFQDN"
    ip_address: "sjc-1-37@acme.com"
    comments: "Created via Ansible"
    pre_shared_key: "newPassword123!"
"""

RETURN = """
# The newly created vpn credential resource record.
"""


from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    client = ZIAClientHelper(module)
    state = module.params.get("state", None)
    vpn_credentials = dict()
    params = [
        "id",
        "type",
        "fqdn",
        "ip_address",
        "pre_shared_key",
        "comments",
    ]
    for param_name in params:
        vpn_credentials[param_name] = module.params.get(param_name, None)
    vpn_id = module.params.get("id", None)
    fqdn = module.params.get("fqdn", None)
    existing_vpn_credentials = None
    if vpn_id is not None or fqdn is not None:
        if vpn_id is not None:
            vpn_box = client.traffic.get_vpn_credential(credential_id=vpn_id)
            if vpn_box is not None:
                existing_vpn_credentials = vpn_box.to_dict()
        else:
            vpn_box = client.traffic.get_vpn_credential(fqdn=fqdn)
            if vpn_box is not None:
                existing_vpn_credentials = vpn_box.to_dict()
    if existing_vpn_credentials is not None:
        id = existing_vpn_credentials.get("id")
        existing_vpn_credentials.update(vpn_credentials)
        existing_vpn_credentials["id"] = id
    if state == "present":
        if existing_vpn_credentials is not None:
            """Update"""
            existing_vpn_credentials = client.traffic.update_vpn_credential(
                credential_id=existing_vpn_credentials.get("id"),
                pre_shared_key=existing_vpn_credentials.get("pre_shared_key"),
                comments=existing_vpn_credentials.get("comments"),
            ).to_dict()
            module.exit_json(changed=True, data=existing_vpn_credentials)
        else:
            """Create"""
            vpn_credentials = client.traffic.add_vpn_credential(
                authentication_type=vpn_credentials.get("type"),
                pre_shared_key=vpn_credentials.get("pre_shared_key"),
                ip_address=vpn_credentials.get("ip_address"),
                fqdn=vpn_credentials.get("fqdn"),
                comments=vpn_credentials.get("comments"),
            ).to_dict()
            module.exit_json(changed=True, data=vpn_credentials)
    elif state == "absent":
        if existing_vpn_credentials is not None:
            code = client.traffic.delete_vpn_credential(
                credential_id=existing_vpn_credentials.get("id")
            )
            if code > 299:
                module.exit_json(changed=False, data=None)
            module.exit_json(changed=True, data=existing_vpn_credentials)
    module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        type=dict(type="str", required=False, default="UFQDN", choices=["UFQDN", "IP"]),
        fqdn=dict(type="str", required=False),
        ip_address=dict(type="str", required=False),
        pre_shared_key=dict(type="str", required=False),
        comments=dict(type="str", required=False),
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
