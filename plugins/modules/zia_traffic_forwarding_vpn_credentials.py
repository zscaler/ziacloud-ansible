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
module: zia_traffic_forwarding_vpn_credentials
short_description: "Adds VPN credentials that can be associated to locations."
description:
  - "Adds VPN credentials that can be associated to locations."
author:
  - William Guilherme (@willguibr)
version_added: "1.0.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
notes:
    - Check mode is supported.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation
  - zscaler.ziacloud.fragments.state

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
    choices:
    - IP
    - UFQDN
  fqdn:
    description: "Fully Qualified Domain Name. Applicable only to UFQDN or XAUTH (or HOSTED_MOBILE_USERS) auth type."
    required: false
    type: str
  pre_shared_key:
    description:
        - This is a required field for UFQDN and IP auth type.
    required: false
    type: str
  update_psk:
    description:
        - This is a required when updating the pre_shared_key value.
    required: false
    type: bool
  comments:
    description:
        - Additional information about this VPN credential.
    required: false
    type: str
  ip_address:
    description:
        - Static IP address for VPN that is self-provisioned or provisioned by Zscaler.
        - This is a required field for IP auth type and is not applicable to other auth types.
    required: false
    type: str
"""

EXAMPLES = r"""

- name: Create/Update/Delete VPN Credentials Type IP.
  zscaler.ziacloud.zia_traffic_forwarding_vpn_credentials:
    provider: '{{ provider }}'
    type: "IP"
    ip_address: "1.1.1.1"
    comments: "Created via Ansible"
    pre_shared_key: "newPassword123!"

- name: Create/Update/Delete VPN Credentials Type UFQDN.
  zscaler.ziacloud.zia_traffic_forwarding_vpn_credentials:
    provider: '{{ provider }}'
    type: "UFQDN"
    ip_address: "sjc-1-37@acme.com"
    comments: "Created via Ansible"
    pre_shared_key: "newPassword123!"
"""

RETURN = r"""
# The newly created vpn credential resource record.
"""


from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
    deleteNone,
)
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def validate_vpn_credential_type(vpn_credentials):
    """Validate the VPN credential type and required attributes."""
    vpn_type = vpn_credentials.get("type")
    if vpn_type not in ["IP", "UFQDN"]:
        raise ValueError(f"Invalid type '{vpn_type}'. Must be one of ['IP', 'UFQDN']")

    ip_address = vpn_credentials.get("ip_address")
    fqdn = vpn_credentials.get("fqdn")

    if vpn_type == "IP" and not ip_address:
        raise ValueError("ip_address is required for VPN credentials of type 'IP'")
    if vpn_type == "UFQDN" and not fqdn:
        raise ValueError("fqdn is required for VPN credentials of type 'UFQDN'")


def find_existing_credential(client, vpn_params):
    """Find existing credential by ID or lookup by fqdn/ip_address."""
    if vpn_params["id"]:
        vpn_box, _, error = client.traffic_vpn_credentials.get_vpn_credential(
            credential_id=vpn_params["id"]
        )
        if error:
            return None, f"Failed to get VPN credential: {to_native(error)}"
        return (vpn_box.as_dict() if vpn_box else None), None

    # If no ID, try lookup by listing all credentials and matching fqdn/ip
    all_vpn_creds, _, error = client.traffic_vpn_credentials.list_vpn_credentials()
    if error:
        return None, f"Failed to list VPN credentials: {to_native(error)}"

    lookup_key = "fqdn" if vpn_params["type"] == "UFQDN" else "ip_address"
    lookup_value = vpn_params[lookup_key]

    if not lookup_value:
        return None, None

    for cred in all_vpn_creds:
        cred_dict = cred.as_dict()
        if cred_dict.get(lookup_key) == lookup_value:
            return cred_dict, None

    return None, None


def core(module):
    client = ZIAClientHelper(module)
    state = module.params.get("state")
    update_psk_flag = module.params.get("update_psk", False)

    # Gather core VPN credential parameters
    vpn_params = {
        "id": module.params.get("id"),
        "type": module.params.get("type"),
        "fqdn": module.params.get("fqdn"),
        "ip_address": module.params.get("ip_address"),
        "pre_shared_key": module.params.get("pre_shared_key"),
        "comments": module.params.get("comments"),
        "disabled": module.params.get("disabled"),
    }

    try:
        validate_vpn_credential_type(vpn_params)
    except ValueError as e:
        module.fail_json(msg=to_native(e))

    existing_vpn, error = find_existing_credential(client, vpn_params)
    if error:
        module.fail_json(msg=error)

    if existing_vpn and "id" in existing_vpn:
        vpn_params["id"] = existing_vpn["id"]

    if module.check_mode:
        changed = (
            (state == "present" and not existing_vpn)
            or (state == "absent" and existing_vpn is not None)
            or (state == "present" and update_psk_flag)
        )
        module.exit_json(changed=changed)

    if state == "present":
        if not existing_vpn:
            create_payload = deleteNone({
                "type": vpn_params["type"],
                "fqdn": vpn_params["fqdn"],
                "ip_address": vpn_params["ip_address"],
                "pre_shared_key": vpn_params["pre_shared_key"],
                "comments": vpn_params["comments"],
                "disabled": vpn_params["disabled"],
            })
            module.warn(f"[CREATE] Final Payload to API: {create_payload}")

            new_vpn, _, error = client.traffic_vpn_credentials.add_vpn_credential(**create_payload)
            if error:
                module.fail_json(msg=f"Failed to create VPN credential: {to_native(error)}")
            module.exit_json(changed=True, data=new_vpn.as_dict())

        elif update_psk_flag and vpn_params["pre_shared_key"]:
            if not vpn_params.get("id"):
                module.fail_json(msg="Cannot update credential - no ID found")

            full_update_payload = {
                "credential_id": vpn_params["id"],
                "type": existing_vpn.get("type"),
                "fqdn": existing_vpn.get("fqdn"),
                "ip_address": existing_vpn.get("ip_address"),
                "pre_shared_key": vpn_params.get("pre_shared_key"),
                "comments": vpn_params.get("comments") or existing_vpn.get("comments"),
                "disabled": vpn_params.get("disabled") if vpn_params.get("disabled") is not None else existing_vpn.get("disabled"),
            }
            final_payload = deleteNone(full_update_payload)
            module.warn(f"[UPDATE] Final Payload to API: {final_payload}")

            updated_vpn, _, error = client.traffic_vpn_credentials.update_vpn_credential(**final_payload)
            if error:
                module.fail_json(msg=f"Failed to update VPN credential: {to_native(error)}")
            module.exit_json(changed=True, data=updated_vpn.as_dict() if updated_vpn else {"id": vpn_params["id"]})
        else:
            # No update required. Remove pre_shared_key from output to avoid drift.
            existing_vpn.pop("pre_shared_key", None)
            module.exit_json(changed=False, data=existing_vpn)

    elif state == "absent":
        if existing_vpn and existing_vpn.get("id"):
            _, error = client.traffic_vpn_credentials.delete_vpn_credential(
                credential_id=existing_vpn["id"]
            )
            if error:
                module.fail_json(msg=f"Failed to delete VPN credential: {to_native(error)}")
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)

    module.exit_json(changed=False)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        type=dict(type="str", required=True, choices=["UFQDN", "IP"]),
        fqdn=dict(type="str", required=False),
        ip_address=dict(type="str", required=False),
        pre_shared_key=dict(type="str", required=False, no_log=True),
        update_psk=dict(
            type="bool",
            required=False,
            default=False,
            description="Must be set to True to update pre-shared key"
        ),
        comments=dict(type="str", required=False),
        disabled=dict(type="bool", required=False),
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ("type", "UFQDN", ["fqdn"]),
            ("type", "IP", ["ip_address"]),
        ]
    )
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
