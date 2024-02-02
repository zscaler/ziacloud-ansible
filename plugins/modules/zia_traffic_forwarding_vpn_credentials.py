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
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider

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


def normalize_vpn_creds(vpn, exclude_keys=None):
    """
    Normalize VPN credentials data by setting computed values.
    """
    if exclude_keys is None:
        exclude_keys = []

    normalized = vpn.copy()
    for key in exclude_keys:
        normalized.pop(key, None)

    return normalized


def validate_vpn_credential_type(vpn_credentials):
    """
    Validate the VPN credential type and ensure required attributes are provided.
    """
    vpn_type = vpn_credentials.get("type")
    ip_address = vpn_credentials.get("ip_address")
    fqdn = vpn_credentials.get("fqdn")

    if vpn_type == "IP" and not ip_address:
        raise ValueError(
            "Invalid input argument, ip_address is required for VPN credentials of type 'IP'."
        )
    if vpn_type == "UFQDN" and not fqdn:
        raise ValueError(
            "Invalid input argument, fqdn attribute is required for VPN credentials of type 'UFQDN'."
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

    # Validate VPN credential type
    validate_vpn_credential_type(vpn_credentials)

    update_psk_flag = module.params.get("update_psk", False)

    existing_vpn_credentials = None
    vpn_id = module.params.get("id", None)
    fqdn = module.params.get("fqdn", None)
    ip_address = module.params.get("ip_address", None)

    if vpn_id is not None or fqdn is not None or ip_address is not None:
        # Try to find the VPN credential by ID or FQDN
        vpn_box = (
            client.traffic.get_vpn_credential(credential_id=vpn_id)
            if vpn_id
            else client.traffic.get_vpn_credential(fqdn=fqdn)
        )
        existing_vpn_credentials = vpn_box.to_dict() if vpn_box else None

    if vpn_id is not None or fqdn is not None or ip_address is not None:
        # If not found, list all VPN credentials and check again
        all_vpn_credentials = client.traffic.list_vpn_credentials()
        for vpn_cred in all_vpn_credentials:
            if vpn_id and vpn_cred.get("id") == vpn_id:
                existing_vpn_credentials = vpn_cred
                break
            if fqdn and vpn_cred.get("fqdn") == fqdn:
                existing_vpn_credentials = vpn_cred
                break
            if ip_address and vpn_cred.get("ip_address") == ip_address:
                existing_vpn_credentials = vpn_cred
                break

    provided_keys = [key for key in params if vpn_credentials.get(key) is not None]

    # Normalize and compare existing and desired VPN credentials data
    desired_vpn_creds = normalize_vpn_creds(vpn_credentials, exclude_keys=provided_keys)
    current_vpn_creds = (
        normalize_vpn_creds(existing_vpn_credentials, exclude_keys=params)
        if existing_vpn_credentials
        else {}
    )

    differences_detected = False
    for key, value in desired_vpn_creds.items():
        current_value = current_vpn_creds.get(key)
        if key != "pre_shared_key" and current_value != value:
            differences_detected = True
            module.warn(
                f"Difference detected in {key}. Current: {current_value}, Desired: {value}"
            )

    # Check if the pre_shared_key needs to be updated
    if update_psk_flag and "pre_shared_key" in vpn_credentials:
        differences_detected = True

    if state == "present":
        if existing_vpn_credentials:
            # Building the payload for the update API call
            update_payload = {
                key: vpn_credentials[key]
                for key in provided_keys
                if key != "update_psk"
            }

            # Set the credential_id for the update
            update_payload["credential_id"] = existing_vpn_credentials.get("id")

            # Include pre_shared_key in the payload only if update_psk_flag is True
            if update_psk_flag and "pre_shared_key" in vpn_credentials:
                update_payload["pre_shared_key"] = vpn_credentials["pre_shared_key"]

            module.warn(f"Final payload being sent to SDK: {update_payload}")
            if differences_detected:
                updated_vpn = client.traffic.update_vpn_credential(
                    **update_payload
                ).to_dict()
                module.exit_json(changed=True, data=updated_vpn)
            else:
                module.exit_json(
                    changed=False,
                    data=existing_vpn_credentials,
                    msg="No changes detected.",
                )
        else:
            create_vpn = deleteNone(
                {
                    "authentication_type": vpn_credentials.get("type"),
                    "fqdn": vpn_credentials.get("fqdn"),
                    "ip_address": vpn_credentials.get("ip_address"),
                    "pre_shared_key": vpn_credentials.get("pre_shared_key"),
                    "comments": vpn_credentials.get("comments"),
                }
            )
            module.warn("Payload for SDK: {}".format(create_vpn))
            new_vpn = client.traffic.add_vpn_credential(**create_vpn).to_dict()
            module.exit_json(changed=True, data=new_vpn)
    elif state == "absent":
        if existing_vpn_credentials and existing_vpn_credentials.get("id"):
            code = client.traffic.delete_vpn_credential(
                credential_id=existing_vpn_credentials.get("id")
            )
            if code == 204:
                module.exit_json(changed=True, data=existing_vpn_credentials)
            else:
                module.fail_json(msg="Failed to delete the VPN credential", code=code)
        else:
            module.exit_json(
                changed=False,
                data={},
                msg="VPN credential not found or already deleted.",
            )

    module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        id=dict(type="int", required=False),
        type=dict(
            type="str",
            required=False,
            default="UFQDN",
            choices=["UFQDN", "IP", "CN", "XAUTH"],
        ),
        fqdn=dict(type="str", required=False),
        ip_address=dict(type="str", required=False),
        pre_shared_key=dict(type="str", required=False, no_log=True),
        update_psk=dict(type="bool", required=False, Default=False),
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
