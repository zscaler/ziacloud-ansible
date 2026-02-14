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
module: zia_casb_tenant_info
short_description: "Gets information about CASB SaaS application tenants"
description:
  - "Gets SaaS Security API tenants (cloud app tenants)."
  - "Retrieves a specific tenant by tenant_id or tenant_name."
  - "Supports optional filters for active tenants, deleted tenants, app type, etc."
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
  tenant_id:
    description:
      - The unique identifier for the CASB tenant.
    required: false
    type: int
  tenant_name:
    description:
      - The name of the CASB tenant.
    required: false
    type: str
  active_only:
    description:
      - Return only active tenants.
    required: false
    type: bool
  include_deleted:
    description:
      - Include deleted tenants in the results.
    required: false
    type: bool
  app_type:
    description:
      - Filter tenants by application type.
    required: false
    type: str
    choices:
      - ANY
      - FILE
      - EMAIL
      - CRM
      - ITSM
      - COLLAB
      - REPO
      - STORAGE
      - TP_APP
      - GENAI
      - MISC
  app:
    description:
      - Filter tenants by sanctioned SaaS application (e.g., BOX, DROPBOX).
    required: false
    type: str
  scan_config_tenants_only:
    description:
      - Return only tenants with scan config.
    required: false
    type: bool
  include_bucket_ready_s3_tenants:
    description:
      - Include S3 tenants ready for bucket creation.
    required: false
    type: bool
  filter_by_feature:
    description:
      - Filter tenants by supported features.
    required: false
    type: list
    elements: str
"""

EXAMPLES = r"""
- name: Get all CASB tenants
  zscaler.ziacloud.zia_casb_tenant_info:
    provider: '{{ provider }}'

- name: Get a CASB tenant by ID
  zscaler.ziacloud.zia_casb_tenant_info:
    provider: '{{ provider }}'
    tenant_id: 15881081

- name: Get a CASB tenant by name
  zscaler.ziacloud.zia_casb_tenant_info:
    provider: '{{ provider }}'
    tenant_name: "My Tenant"

- name: Get active tenants for BOX app
  zscaler.ziacloud.zia_casb_tenant_info:
    provider: '{{ provider }}'
    active_only: true
    app: BOX
"""

RETURN = r"""
tenants:
  description: A list of CASB tenants fetched based on the given criteria.
  returned: always
  type: list
  elements: dict
  contains:
    tenant_id:
      description: The unique identifier for the CASB tenant.
      returned: always
      type: int
    tenant_name:
      description: The name of the tenant.
      returned: always
      type: str
    saas_application:
      description: The SaaS application (e.g., BOX, DROPBOX).
      returned: when available
      type: str
    enterprise_tenant_id:
      description: Enterprise tenant identifier.
      returned: when available
      type: str
    modified_time:
      description: Last modified timestamp.
      returned: when available
      type: int
    last_tenant_validation_time:
      description: Last validation timestamp.
      returned: when available
      type: int
    tenant_deleted:
      description: Whether the tenant has been deleted.
      returned: when available
      type: bool
    tenant_webhook_enabled:
      description: Whether webhook is enabled.
      returned: when available
      type: bool
    re_auth:
      description: Whether re-authentication is required.
      returned: when available
      type: bool
    features_supported:
      description: List of supported features.
      returned: when available
      type: list
    status:
      description: Tenant status list.
      returned: when available
      type: list
    zscaler_app_tenant_id:
      description: Zscaler app tenant ID reference.
      returned: when available
      type: list
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)


def core(module):
    tenant_id = module.params.get("tenant_id")
    tenant_name = module.params.get("tenant_name")
    active_only = module.params.get("active_only")
    include_deleted = module.params.get("include_deleted")
    app_type = module.params.get("app_type")
    app = module.params.get("app")
    scan_config_tenants_only = module.params.get("scan_config_tenants_only")
    include_bucket_ready_s3_tenants = module.params.get("include_bucket_ready_s3_tenants")
    filter_by_feature = module.params.get("filter_by_feature")

    query_params = {}
    if tenant_id is not None:
        query_params["tenantId"] = str(tenant_id)
    if tenant_name:
        query_params["tenantName"] = tenant_name
    if active_only is not None:
        query_params["activeOnly"] = active_only
    if include_deleted is not None:
        query_params["includeDeleted"] = include_deleted
    if app_type:
        query_params["appType"] = app_type
    if app:
        query_params["app"] = app.upper()
    if scan_config_tenants_only is not None:
        query_params["scanConfigTenantsOnly"] = scan_config_tenants_only
    if include_bucket_ready_s3_tenants is not None:
        query_params["includeBucketReadyS3Tenants"] = include_bucket_ready_s3_tenants
    if filter_by_feature:
        query_params["filterByFeature"] = filter_by_feature

    client = ZIAClientHelper(module)
    result, _unused, error = client.saas_security_api.list_casb_tenant_lite(query_params=query_params if query_params else None)
    if error:
        module.fail_json(msg=f"Error retrieving CASB tenants: {to_native(error)}")
    tenants_list = [t.as_dict() for t in result] if result else []

    matched = None
    for t in tenants_list:
        tid = t.get("tenant_id")
        tname = t.get("tenant_name")
        if tenant_id is not None and tid == tenant_id:
            matched = t
            break
        if tenant_name and tname == tenant_name:
            matched = t
            break

    if tenant_id is not None or tenant_name:
        if matched is None:
            module.fail_json(msg=f"CASB tenant with name '{tenant_name}' or id '{tenant_id}' not found. " "Omit tenant_id and tenant_name to list all tenants.")
        tenants_out = [matched]
    else:
        tenants_out = tenants_list

    module.exit_json(changed=False, tenants=tenants_out)


def main():
    app_type_choices = [
        "ANY",
        "FILE",
        "EMAIL",
        "CRM",
        "ITSM",
        "COLLAB",
        "REPO",
        "STORAGE",
        "TP_APP",
        "GENAI",
        "MISC",
    ]
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        tenant_id=dict(type="int", required=False),
        tenant_name=dict(type="str", required=False),
        active_only=dict(type="bool", required=False),
        include_deleted=dict(type="bool", required=False),
        app_type=dict(type="str", required=False, choices=app_type_choices),
        app=dict(type="str", required=False),
        scan_config_tenants_only=dict(type="bool", required=False),
        include_bucket_ready_s3_tenants=dict(type="bool", required=False),
        filter_by_feature=dict(type="list", elements="str", required=False),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
