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
module: zia_file_type_control_rules
short_description: "Adds a new File Type Control policy rule."
description: "Adds a new File Type Control policy rule."
author:
  - William Guilherme (@willguibr)
version_added: "2.0.0"
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
    description: System generated identifier for a file-type policy
    required: false
    type: int
  name:
    description: "Name of the file type control rule"
    required: true
    type: str
  description:
    description: "Additional information about the rule"
    required: false
    type: str
  enabled:
    description:
        - Determines whether the file type control rule is enabled or disabled
    required: false
    type: bool
  capture_pcap:
    description:
        - Indicates whether packet capture (PCAP) is enabled or not
    required: false
    type: bool
    default: false
  active_content:
    description: Flag to check whether a file has active content or not
    required: false
    type: bool
  unscannable:
    description: Flag to check whether a file is unscannable or not
    required: false
    type: bool
  order:
    description: "Rule order number of the file type control rule"
    required: false
    type: int
  min_size:
    description: "The minimum file size (in KB) used for evaluation of the DLP policy rule."
    required: false
    type: int
  max_size:
    description: "Maximum file size (in KB) used for evaluation of the FTP rule"
    required: false
    type: int
  time_quota:
    description:
        - Action must be set to CAUTION
        - Time quota in minutes, after which the file type control rule is applied.
        - The allowed range is between 15 minutes and 600 minutes.
        - If not set, no quota is enforced. If a policy rule action is set to BLOCK, this field is not applicable.
    required: false
    type: int
  size_quota:
    description:
        - Action must be set to CAUTION
        - Size quota in MB beyond which the file type control rule is applied.
        - The allowed range is between 10 MB and 100000 MB
        - If not set, no quota is enforced. If a policy rule action is set to BLOCK, this field is not applicable.
    required: false
    type: int
  rank:
    description:
        - Admin rank of the admin who creates this rule
    required: false
    default: 7
    type: int
  filtering_action:
    description:
      - Action taken when traffic matches policy.
      - This field is not applicable to the Lite API.
    required: false
    type: str
    choices:
        - BLOCK
        - CAUTION
        - ALLOW
  operation:
    description: File operation performed. This field is not applicable to the Lite API.
    required: false
    type: str
    choices:
        - UPLOAD
        - DOWNLOAD
        - UPLOAD_DOWNLOAD
  protocols:
    description:
        - Protocol criteria
    required: true
    type: list
    elements: str
    choices:
        - ANY_RULE
        - SMRULEF_CASCADING_ALLOWED
        - FOHTTP_RULE
        - FTP_RULE
        - SSL_RULE
        - HTTPS_RULE
        - HTTP_RULE
  locations:
    description:
        - Name-ID pairs of locations for which rule must be applied
    type: list
    elements: int
    required: false
  groups:
    description:
        - Name-ID pairs of groups for which rule must be applied
    type: list
    elements: int
    required: false
  departments:
    description:
        - Name-ID pairs of departments for which rule will be applied
    type: list
    elements: int
    required: false
  users:
    description:
        - Name-ID pairs of users for which rule must be applied
    type: list
    elements: int
    required: false
  url_categories:
    description:
      - The URL categories to which the rule applies
      - Use the info resource zia_url_categories_info to retrieve the category names.
    required: false
    type: list
    elements: str
  device_groups:
    description:
      - Name-ID pairs of device groups for which the rule must be applied.
      - This field is applicable for devices that are managed using Zscaler Client Connector.
      - If no value is set, this field is ignored during the policy evaluation.
    type: list
    elements: int
    required: false
  devices:
    description:
      - Name-ID pairs of devices for which rule must be applied.
      - Specifies devices that are managed using Zscaler Client Connector.
      - If no value is set, this field is ignored during the policy evaluation.
    type: list
    elements: int
    required: false
  time_windows:
    description:
        - Name-ID pairs of time interval during which rule must be enforced.
    type: list
    elements: int
    required: false
  location_groups:
    description:
        - Name-ID pairs of the location groups to which the rule must be applied.
    type: list
    elements: int
    required: false
  labels:
    description:
        - The file type control rule label. Rule labels allow you to logically group your organization policy rules.
        - Policy rules that are not associated with a rule label are grouped under the Untagged label.
    type: list
    elements: int
    required: false
  zpa_app_segments:
    description:
      - The list of ZPA Application Segments for which this rule is applicable.
      - This field is applicable only for the ZPA forwarding method.
    type: list
    elements: dict
    required: false
    suboptions:
      external_id:
        description: Indicates the external ID. Applicable only when this reference is of an external entity.
        type: str
        required: true
      name:
        description: The name of the Application Segment
        type: str
        required: true
  device_trust_levels:
    description:
        - List of device trust levels for which the rule must be applied.
        - This field is applicable for devices that are managed using Zscaler Client Connector.
        - The trust levels are assigned to the devices based on your posture configurations.
        - If no value is set, this field is ignored during the policy evaluation.
    type: list
    elements: str
    required: false
    choices:
        - ANY
        - UNKNOWN_DEVICETRUSTLEVEL
        - LOW_TRUST
        - MEDIUM_TRUST
        - HIGH_TRUST
  cloud_applications:
    description:
        - The list of cloud applications to which the File Type Control policy rule must be applied
        - Use the info resource zia_cloud_applications_info to retrieve the list of supported app_policy and ssl_policy applications
    type: list
    elements: str
    required: false
  file_types:
    description:
        - List of URL categories for which rule must be applied
    type: list
    elements: str
    required: false
    choices:
        - ANY
        - NONE
        - FTCATEGORY_JAVASCRIPT
        - FTCATEGORY_FLASH
        - FTCATEGORY_JAVA_APPLET
        - FTCATEGORY_HTA
        - FTCATEGORY_HAR
        - FTCATEGORY_ZIP
        - FTCATEGORY_GZIP
        - FTCATEGORY_TAR
        - FTCATEGORY_BZIP2
        - FTCATEGORY_RAR
        - FTCATEGORY_STUFFIT
        - FTCATEGORY_ISO
        - FTCATEGORY_CAB
        - FTCATEGORY_P7Z
        - FTCATEGORY_SCZIP
        - FTCATEGORY_DMG
        - FTCATEGORY_PKG
        - FTCATEGORY_NUPKG
        - FTCATEGORY_MF
        - FTCATEGORY_EGG
        - FTCATEGORY_ALZ
        - FTCATEGORY_LZ4
        - FTCATEGORY_LZOP
        - FTCATEGORY_ZST
        - FTCATEGORY_RZIP
        - FTCATEGORY_LZIP
        - FTCATEGORY_LRZIP
        - FTCATEGORY_DACT
        - FTCATEGORY_ZPAQ
        - FTCATEGORY_BH
        - FTCATEGORY_B64
        - FTCATEGORY_LZMA
        - FTCATEGORY_XZ
        - FTCATEGORY_FCL
        - FTCATEGORY_ZIPX
        - FTCATEGORY_CPIO
        - FTCATEGORY_LZH
        - FTCATEGORY_MP3
        - FTCATEGORY_WAV
        - FTCATEGORY_OGG_VORBIS
        - FTCATEGORY_M3U
        - FTCATEGORY_VPR
        - FTCATEGORY_AAC
        - FTCATEGORY_ADE
        - FTCATEGORY_DB2
        - FTCATEGORY_SQL
        - FTCATEGORY_EDMX
        - FTCATEGORY_FRM
        - FTCATEGORY_ACCDB
        - FTCATEGORY_DBF
        - FTCATEGORY_VIRTUAL_HARD_DISK
        - FTCATEGORY_DB
        - FTCATEGORY_SDB
        - FTCATEGORY_KDBX
        - FTCATEGORY_DXL
        - FTCATEGORY_WINDOWS_EXECUTABLES
        - FTCATEGORY_MICROSOFT_INSTALLER
        - FTCATEGORY_WINDOWS_LIBRARY
        - FTCATEGORY_WINDOWS_LNK
        - FTCATEGORY_PYTHON
        - FTCATEGORY_POWERSHELL
        - FTCATEGORY_VISUAL_BASIC_SCRIPT
        - FTCATEGORY_MSP
        - FTCATEGORY_REG
        - FTCATEGORY_BAT
        - FTCATEGORY_BASH_SCRIPTS
        - FTCATEGORY_SHELL_SCRAP
        - FTCATEGORY_DEB
        - FTCATEGORY_APPX
        - FTCATEGORY_MSC
        - FTCATEGORY_ELF
        - FTCATEGORY_MACH
        - FTCATEGORY_DRV
        - FTCATEGORY_GBA
        - FTCATEGORY_SMD
        - FTCATEGORY_XBEH
        - FTCATEGORY_PSX
        - FTCATEGORY_THREETWOX
        - FTCATEGORY_NDS
        - FTCATEGORY_BITMAP
        - FTCATEGORY_PHOTOSHOP
        - FTCATEGORY_WINDOWS_META_FORMAT
        - FTCATEGORY_GIF
        - FTCATEGORY_JPEG
        - FTCATEGORY_PNG
        - FTCATEGORY_WEBP
        - FTCATEGORY_TIFF
        - FTCATEGORY_DCM
        - FTCATEGORY_THREEDM
        - FTCATEGORY_KML
        - FTCATEGORY_JPD
        - FTCATEGORY_DNG
        - FTCATEGORY_RWZ
        - FTCATEGORY_GREENSHOT
        - FTCATEGORY_IMG
        - FTCATEGORY_HIGH_EFFICIENCY_IMAGE_FILES
        - FTCATEGORY_AAF
        - FTCATEGORY_OMFI
        - FTCATEGORY_PLS
        - FTCATEGORY_HLP
        - FTCATEGORY_MDZ
        - FTCATEGORY_MST
        - FTCATEGORY_WINDOWS_SCRIPT_FILES
        - FTCATEGORY_GRP
        - FTCATEGORY_PIF
        - FTCATEGORY_JOB
        - FTCATEGORY_PSW
        - FTCATEGORY_ONENOTE
        - FTCATEGORY_CATALOG
        - FTCATEGORY_NETMON
        - FTCATEGORY_HIVE
        - FTCATEGORY_APK
        - FTCATEGORY_IPA
        - FTCATEGORY_MOBILECONFIG
        - FTCATEGORY_MS_POWERPOINT
        - FTCATEGORY_MS_WORD
        - FTCATEGORY_MS_EXCEL
        - FTCATEGORY_MS_RTF
        - FTCATEGORY_MS_MDB
        - FTCATEGORY_MS_MSG
        - FTCATEGORY_MS_PST
        - FTCATEGORY_MS_VSIX
        - FTCATEGORY_VSDX
        - FTCATEGORY_OAB
        - FTCATEGORY_OLM
        - FTCATEGORY_MS_PUB
        - FTCATEGORY_TNEF
        - FTCATEGORY_ENCROFF
        - FTCATEGORY_OPEN_OFFICE_DOC
        - FTCATEGORY_OPEN_OFFICE_DRAWINGS
        - FTCATEGORY_OPEN_OFFICE_PRESENTATIONS
        - FTCATEGORY_OPEN_OFFICE_SPREADSHEETS
        - FTCATEGORY_ENCRYPT
        - FTCATEGORY_PDF_DOCUMENT
        - FTCATEGORY_POSTSCRIPT
        - FTCATEGORY_COMPILED_HTML_HELP
        - FTCATEGORY_DWG
        - FTCATEGORY_CGR
        - FTCATEGORY_SLDPRT
        - FTCATEGORY_TXT
        - FTCATEGORY_UNK
        - FTCATEGORY_IPT
        - FTCATEGORY_XPS
        - FTCATEGORY_CSV
        - FTCATEGORY_STL
        - FTCATEGORY_IQY
        - FTCATEGORY_CERT
        - FTCATEGORY_INTERNET_SIGNUP
        - FTCATEGORY_PCAP
        - FTCATEGORY_TTF
        - FTCATEGORY_CRX
        - FTCATEGORY_CER
        - FTCATEGORY_DER
        - FTCATEGORY_P7B
        - FTCATEGORY_PEM
        - FTCATEGORY_JKS
        - FTCATEGORY_KEY
        - FTCATEGORY_P12
        - FTCATEGORY_CHEMDRAW_FILES
        - FTCATEGORY_CML
        - FTCATEGORY_BPL
        - FTCATEGORY_CCC
        - FTCATEGORY_CP
        - FTCATEGORY_DEVFILE
        - FTCATEGORY_MM
        - FTCATEGORY_AES
        - FTCATEGORY_WOFF2
        - FTCATEGORY_STEP_FILES
        - FTCATEGORY_RVT
        - FTCATEGORY_EMF
        - FTCATEGORY_PCD
        - FTCATEGORY_INF
        - FTCATEGORY_SAM
        - FTCATEGORY_PMD
        - FTCATEGORY_EOT
        - FTCATEGORY_OPENXML
        - FTCATEGORY_FODT
        - FTCATEGORY_JOBOPTIONS
        - FTCATEGORY_IDML
        - FTCATEGORY_CXP
        - FTCATEGORY_ENEX
        - FTCATEGORY_OTF
        - FTCATEGORY_LGX
        - FTCATEGORY_CBZ
        - FTCATEGORY_DPB
        - FTCATEGORY_GLB
        - FTCATEGORY_PM3
        - FTCATEGORY_CD3
        - FTCATEGORY_FLN
        - FTCATEGORY_IVR
        - FTCATEGORY_VU3
        - FTCATEGORY_PFB
        - FTCATEGORY_WIM
        - FTCATEGORY_APPLE_DOCUMENTS
        - FTCATEGORY_TABLEAU_FILES
        - FTCATEGORY_AUTOCAD
        - FTCATEGORY_INTEGRATED_CIRCUIT_FILES
        - FTCATEGORY_LOG_FILES
        - FTCATEGORY_EML_FILES
        - FTCATEGORY_DAT
        - FTCATEGORY_INI
        - FTCATEGORY_THREED
        - FTCATEGORY_THREEDA
        - FTCATEGORY_THREEDFA
        - FTCATEGORY_THREEDL
        - FTCATEGORY_THREEDZ
        - FTCATEGORY_APR
        - FTCATEGORY_REALFLOW
        - FTCATEGORY_COMP
        - FTCATEGORY_DDF
        - FTCATEGORY_DEM
        - FTCATEGORY_THREEDS_MAX
        - FTCATEGORY_GSP
        - FTCATEGORY_HCL
        - FTCATEGORY_MOTION_ANALYSIS
        - FTCATEGORY_IGS
        - FTCATEGORY_K3D
        - FTCATEGORY_LIGHTSCAPE
        - FTCATEGORY_AUTODESK_MAYA
        - FTCATEGORY_MXS
        - FTCATEGORY_OBJ
        - FTCATEGORY_SHP
        - FTCATEGORY_SPB
        - FTCATEGORY_WRL
        - FTCATEGORY_TMP
        - FTCATEGORY_MUI
        - FTCATEGORY_HBS
        - FTCATEGORY_ICS
        - FTCATEGORY_PUB
        - FTCATEGORY_DRAWIO
        - FTCATEGORY_PRT
        - FTCATEGORY_PS2
        - FTCATEGORY_PS3
        - FTCATEGORY_ACIS
        - FTCATEGORY_VDA
        - FTCATEGORY_PARASOLID
        - FTCATEGORY_PGP
        - FTCATEGORY_BIN
        - FTCATEGORY_JSON
        - FTCATEGORY_XML
        - FTCATEGORY_BINHEX
        - FTCATEGORY_QUARKXPRESS
        - FTCATEGORY_GO_FILES
        - FTCATEGORY_SWIFT_FILES
        - FTCATEGORY_RUBY_FILES
        - FTCATEGORY_PERL_FILES
        - FTCATEGORY_MATLAB_FILES
        - FTCATEGORY_INCLUDE_FILES
        - FTCATEGORY_JAVA_FILES
        - FTCATEGORY_MAKE_FILES
        - FTCATEGORY_YAML_FILES
        - FTCATEGORY_VISUAL_BASIC_FILES
        - FTCATEGORY_C_FILES
        - FTCATEGORY_XAML
        - FTCATEGORY_BASIC_SOURCE_CODE
        - FTCATEGORY_SCT
        - FTCATEGORY_A_FILE
        - FTCATEGORY_MS_CPP_FILES
        - FTCATEGORY_ASM
        - FTCATEGORY_BORLAND_CPP_FILES
        - FTCATEGORY_CLW
        - FTCATEGORY_COBOL
        - FTCATEGORY_CSX
        - FTCATEGORY_DELPHI
        - FTCATEGORY_DMD
        - FTCATEGORY_DSP
        - FTCATEGORY_F_FILES
        - FTCATEGORY_NATVIS
        - FTCATEGORY_NCB
        - FTCATEGORY_NFM
        - FTCATEGORY_POD
        - FTCATEGORY_QLIKVIEW_FILES
        - FTCATEGORY_RES_FILES
        - FTCATEGORY_RPY
        - FTCATEGORY_RSP
        - FTCATEGORY_SAS
        - FTCATEGORY_SC
        - FTCATEGORY_SCALA
        - FTCATEGORY_SWC
        - FTCATEGORY_TCC
        - FTCATEGORY_TLH
        - FTCATEGORY_TLI
        - FTCATEGORY_VISUAL_CPP_FILES
        - FTCATEGORY_X1B
        - FTCATEGORY_IFC
        - FTCATEGORY_BCP
        - FTCATEGORY_FOR
        - FTCATEGORY_NCI
        - FTCATEGORY_AU3
        - FTCATEGORY_BGI
        - FTCATEGORY_MANIFEST
        - FTCATEGORY_NLS
        - FTCATEGORY_TLB
        - FTCATEGORY_ASHX
        - FTCATEGORY_EXP
        - FTCATEGORY_FLASH_VIDEO
        - FTCATEGORY_AVI
        - FTCATEGORY_MPEG
        - FTCATEGORY_MP4
        - FTCATEGORY_3GPP
        - FTCATEGORY_QUICKTIME_VIDEO
        - FTCATEGORY_WINDOWS_MEDIA_MOVIE
        - FTCATEGORY_MKV
        - FTCATEGORY_WEBM
        - FTCATEGORY_VS4
        - FTCATEGORY_TS
"""

EXAMPLES = r"""
- name: Create/Update/Delete a file type control rule.
  zscaler.ziacloud.zia_url_filtering_rules:
    provider: '{{ provider }}'
    name: "URL_Ansible_Example"
    description: "URL_Ansible_Example"
    enabled: "ENABLED"
    action: "ALLOW"
    order: 1
    protocols:
      - "HTTPS_RULE"
      - "HTTP_RULE"
    request_methods:
      - "CONNECT"
      - "DELETE"
      - "GET"
      - "HEAD"
      - "OPTIONS"
      - "OTHER"
      - "POST"
      - "PUT"
      - "TRACE"
"""

RETURN = r"""
# The newly created file type control rule resource record.
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


def normalize_rule(rule):
    """Normalize rule data by removing computed values."""
    if not rule:
        return {}

    normalized = rule.copy()
    computed_values = []
    for attr in computed_values:
        normalized.pop(attr, None)
    return normalized


def validate_mutually_exclusive_flags(module, rule):
    """
    Validates mutually exclusive booleans in File Type Control Rule.
    """
    if rule.get("active_content") and rule.get("unscannable"):
        module.fail_json(
            msg="The attributes 'active_content' and 'unscannable' are mutually exclusive. Only one can be set to True."
        )


def preprocess_rule(rule, params):
    for attr in params:
        if attr in rule and rule[attr] is not None:
            if isinstance(rule[attr], list):
                if all(isinstance(item, dict) and "id" in item for item in rule[attr]):
                    rule[attr] = [item["id"] for item in rule[attr]]
                else:
                    rule[attr] = sorted(rule[attr])
    return rule


def core(module):
    state = module.params.get("state", None)
    client = ZIAClientHelper(module)

    params = [
        "id",
        "name",
        "description",
        "enabled",
        "order",
        "rank",
        "filtering_action",
        "protocols",
        "operation",
        "active_content",
        "unscannable",
        "capture_pcap",
        "time_quota",
        "size_quota",
        "max_size",
        "min_size",
        "url_categories",
        "cloud_applications",
        "file_types",
        "device_trust_levels",
        "time_windows",
        "location_groups",
        "locations",
        "groups",
        "departments",
        "users",
        "labels",
        "device_groups",
        "devices",
    ]

    # Only include attributes that are explicitly set in the playbook
    rule = {}
    for param in params:
        if param in module.params:
            rule[param] = module.params[param]

    module.debug(f"Initial parameters received (only explicitly set values): {rule}")

    validate_mutually_exclusive_flags(module, rule)

    rule_id = rule.get("id")
    rule_name = rule.get("name")

    existing_rule = None
    if rule_id is not None:
        module.debug(f"Fetching existing rule with ID: {rule_id}")
        result, _unused, error = client.file_type_control_rule.get_rule(rule_id=rule_id)
        if error:
            module.fail_json(
                msg=f"Error fetching rule with id {rule_id}: {to_native(error)}"
            )
        if result:
            existing_rule = result.as_dict()
            module.warn(f"Raw existing rule keys: {existing_rule.keys()}")
            module.warn(
                f"user_agent_types from API: {existing_rule.get('user_agent_types')}"
            )
    else:
        module.debug(f"Listing rules to find by name: {rule_name}")
        result, _unused, error = client.file_type_control_rule.list_rules()
        if error:
            module.fail_json(msg=f"Error listing rules: {to_native(error)}")
        if result:
            for rule_ in result:
                if rule_.name == rule_name:
                    existing_rule = rule_.as_dict()
                    module.debug(f"Found existing rule by name: {existing_rule}")
                    break

    # Normalize and compare
    desired_rule = normalize_rule(rule)

    for k in [
        "device_trust_levels",
        "protocols",
        "file_types",
        "cloud_applications",
        "url_categories",
    ]:
        if k in desired_rule and isinstance(desired_rule[k], list):
            desired_rule[k] = sorted(desired_rule[k])

    current_rule = normalize_rule(existing_rule) if existing_rule else {}

    for k in [
        "device_trust_levels",
        "protocols",
        "file_types",
        "cloud_applications",
        "url_categories",
    ]:
        if k in current_rule and isinstance(current_rule[k], list):
            current_rule[k] = sorted(current_rule[k])

    module.debug(f"Normalized desired rule: {desired_rule}")
    module.debug(f"Normalized current rule: {current_rule}")

    desired_rule_preprocessed = preprocess_rule(desired_rule, params)
    existing_rule_preprocessed = preprocess_rule(current_rule, params)
    module.debug(f"Preprocessed desired rule: {desired_rule_preprocessed}")
    module.debug(f"Preprocessed current rule: {existing_rule_preprocessed}")

    differences_detected = False
    list_attributes = [
        "protocols",
        "url_categories",
        "cloud_applications",
        "file_types",
        "device_trust_levels",
        "time_windows",
        "location_groups",
        "locations",
        "groups",
        "departments",
        "users",
        "labels",
        "device_groups",
        "devices",
    ]

    # Attributes where order should be ignored
    order_agnostic_attributes = [
        "device_trust_levels",
        "protocols",
        "file_types",
        "cloud_applications",
        "url_categories",
    ]

    for key in params:
        desired_value = desired_rule_preprocessed.get(key)
        current_value = existing_rule_preprocessed.get(key)

        if key == "id" and desired_value is None and current_value is not None:
            continue

        if key == "enabled" and "state" in current_rule:
            current_value = current_rule["state"] == "ENABLED"

        # Special handling for list attributes - treat empty list and None as equivalent
        if key in list_attributes:
            if desired_value in (None, []) and current_value in (None, []):
                continue
            if desired_value is None:
                desired_value = []
            if current_value is None:
                current_value = []

        # Special handling for quota fields - treat 0 and None as equivalent
        if key in ["time_quota", "size_quota", "min_size", "max_size"]:
            if desired_value in (None, 0) and current_value in (None, 0):
                continue
            if desired_value is None:
                desired_value = 0
            if current_value is None:
                current_value = 0

        if isinstance(desired_value, list) and isinstance(current_value, list):
            if key in order_agnostic_attributes:
                # For order-agnostic attributes, compare sets instead of sorted lists
                if set(desired_value) != set(current_value):
                    differences_detected = True
                    module.warn(
                        f"Difference detected in {key}. Current: {current_value}, Desired: {desired_value}"
                    )
            else:
                # For other list attributes, maintain original comparison logic
                if all(isinstance(x, int) for x in desired_value) and all(
                    isinstance(x, int) for x in current_value
                ):
                    desired_value = sorted(desired_value)
                    current_value = sorted(current_value)
                if current_value != desired_value:
                    differences_detected = True
                    module.warn(
                        f"Difference detected in {key}. Current: {current_value}, Desired: {desired_value}"
                    )
        elif current_value != desired_value:
            differences_detected = True
            module.warn(
                f"Difference detected in {key}. Current: {current_value}, Desired: {desired_value}"
            )

    if module.check_mode:
        if state == "present" and not existing_rule:
            action = "create"
        elif differences_detected:
            action = "update"
        elif state == "absent" and existing_rule:
            action = "delete"
        else:
            action = "do nothing"

        module.debug(f"Check mode - would {action}")

        if state == "present" and (existing_rule is None or differences_detected):
            module.exit_json(changed=True)
        elif state == "absent" and existing_rule is not None:
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)

    module.warn(f"Final payload being sent to SDK: {rule}")
    if state == "present":
        if existing_rule:
            if differences_detected:
                rule_id_to_update = existing_rule.get("id")
                if not rule_id_to_update:
                    module.fail_json(
                        msg="Cannot update rule: ID is missing from the existing resource."
                    )

                update_data = deleteNone(
                    {
                        "rule_id": rule_id_to_update,
                        "name": desired_rule.get("name"),
                        "description": desired_rule.get("description"),
                        "enabled": desired_rule.get("enabled"),
                        "order": desired_rule.get("order"),
                        "rank": desired_rule.get("rank"),
                        "filtering_action": desired_rule.get("filtering_action"),
                        "operation": desired_rule.get("operation"),
                        "active_content": desired_rule.get("active_content"),
                        "unscannable": desired_rule.get("unscannable"),
                        "capture_pcap": desired_rule.get("capture_pcap"),
                        "protocols": desired_rule.get("protocols"),
                        "file_types": desired_rule.get("file_types"),
                        "cloud_applications": desired_rule.get("cloud_applications"),
                        "device_trust_levels": desired_rule.get("device_trust_levels"),
                        "locations": desired_rule.get("locations"),
                        "groups": desired_rule.get("groups"),
                        "departments": desired_rule.get("departments"),
                        "users": desired_rule.get("users"),
                        "url_categories": desired_rule.get("url_categories"),
                        "time_quota": desired_rule.get("time_quota"),
                        "size_quota": desired_rule.get("size_quota"),
                        "max_size": desired_rule.get("max_size"),
                        "min_size": desired_rule.get("min_size"),
                        "time_windows": desired_rule.get("time_windows"),
                        "location_groups": desired_rule.get("location_groups"),
                        "labels": desired_rule.get("labels"),
                        "device_groups": desired_rule.get("device_groups"),
                        "devices": desired_rule.get("devices"),
                        "zpa_app_segments": desired_rule.get("zpa_app_segments"),
                    }
                )

                module.warn("Payload Update for SDK: {}".format(update_data))
                updated_rule, _unused, error = (
                    client.file_type_control_rule.update_rule(**update_data)
                )
                if error:
                    module.fail_json(msg=f"Error updating rule: {to_native(error)}")
                module.exit_json(changed=True, data=updated_rule.as_dict())
            else:
                module.exit_json(changed=False, data=existing_rule)
        else:
            module.warn("Creating new rule as no existing rule found")
            """Create"""
            create_data = deleteNone(
                {
                    "name": desired_rule.get("name"),
                    "description": desired_rule.get("description"),
                    "enabled": desired_rule.get("enabled"),
                    "order": desired_rule.get("order"),
                    "rank": desired_rule.get("rank"),
                    "filtering_action": desired_rule.get("filtering_action"),
                    "operation": desired_rule.get("operation"),
                    "active_content": desired_rule.get("active_content"),
                    "unscannable": desired_rule.get("unscannable"),
                    "capture_pcap": desired_rule.get("capture_pcap"),
                    "protocols": desired_rule.get("protocols"),
                    "file_types": desired_rule.get("file_types"),
                    "cloud_applications": desired_rule.get("cloud_applications"),
                    "device_trust_levels": desired_rule.get("device_trust_levels"),
                    "locations": desired_rule.get("locations"),
                    "groups": desired_rule.get("groups"),
                    "departments": desired_rule.get("departments"),
                    "users": desired_rule.get("users"),
                    "url_categories": desired_rule.get("url_categories"),
                    "time_quota": desired_rule.get("time_quota"),
                    "size_quota": desired_rule.get("size_quota"),
                    "max_size": desired_rule.get("max_size"),
                    "min_size": desired_rule.get("min_size"),
                    "time_windows": desired_rule.get("time_windows"),
                    "location_groups": desired_rule.get("location_groups"),
                    "labels": desired_rule.get("labels"),
                    "device_groups": desired_rule.get("device_groups"),
                    "devices": desired_rule.get("devices"),
                    "zpa_app_segments": desired_rule.get("zpa_app_segments"),
                }
            )
            module.warn("Payload for SDK: {}".format(create_data))
            new_rule, _unused, error = client.file_type_control_rule.add_rule(
                **create_data
            )
            if error:
                module.fail_json(msg=f"Error creating rule: {to_native(error)}")
            module.exit_json(changed=True, data=new_rule.as_dict())

    elif state == "absent":
        if existing_rule:
            rule_id_to_delete = existing_rule.get("id")
            if not rule_id_to_delete:
                module.fail_json(
                    msg="Cannot delete rule: ID is missing from the existing resource."
                )

            module.debug(f"About to delete rule with ID: {rule_id_to_delete}")
            _unused, _unused, error = client.file_type_control_rule.delete_rule(
                rule_id=rule_id_to_delete
            )
            if error:
                module.fail_json(msg=f"Error deleting rule: {to_native(error)}")
            module.debug(f"Successfully deleted rule with ID: {rule_id_to_delete}")
            module.exit_json(changed=True, data=existing_rule)
        else:
            module.debug("No rule found to delete")
            module.exit_json(changed=False, data={})

    else:
        module.debug(f"Unhandled state: {state}")
        module.exit_json(changed=False, data={})


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    id_spec = dict(
        type="list",
        elements="int",
        required=False,
    )
    external_id_name_dict_spec = dict(
        external_id=dict(type="str", required=True),
        name=dict(type="str", required=True),
    )

    external_id_name_list_spec = dict(
        type="list",
        elements="dict",
        required=False,
        options=external_id_name_dict_spec,
    )
    argument_spec.update(
        id=dict(type="int", required=False),
        name=dict(type="str", required=True),
        description=dict(type="str", required=False),
        enabled=dict(type="bool", required=False),
        order=dict(type="int", required=False),
        rank=dict(type="int", required=False, default=7),
        time_quota=dict(type="int", required=False),
        size_quota=dict(type="int", required=False),
        max_size=dict(type="int", required=False),
        min_size=dict(type="int", required=False),
        active_content=dict(type="bool", required=False),
        capture_pcap=dict(type="bool", required=False, default=False),
        unscannable=dict(type="bool", required=False),
        cloud_applications=dict(type="list", elements="str", required=False),
        device_trust_levels=dict(
            type="list",
            elements="str",
            required=False,
            choices=[
                "ANY",
                "UNKNOWN_DEVICETRUSTLEVEL",
                "LOW_TRUST",
                "MEDIUM_TRUST",
                "HIGH_TRUST",
            ],
        ),
        url_categories=dict(type="list", elements="str", required=False),
        file_types=dict(
            type="list",
            elements="str",
            required=False,
            choices=[
                "ANY",
                "NONE",
                "FTCATEGORY_JAVASCRIPT",
                "FTCATEGORY_FLASH",
                "FTCATEGORY_JAVA_APPLET",
                "FTCATEGORY_HTA",
                "FTCATEGORY_HAR",
                "FTCATEGORY_ZIP",
                "FTCATEGORY_GZIP",
                "FTCATEGORY_TAR",
                "FTCATEGORY_BZIP2",
                "FTCATEGORY_RAR",
                "FTCATEGORY_STUFFIT",
                "FTCATEGORY_ISO",
                "FTCATEGORY_CAB",
                "FTCATEGORY_P7Z",
                "FTCATEGORY_SCZIP",
                "FTCATEGORY_DMG",
                "FTCATEGORY_PKG",
                "FTCATEGORY_NUPKG",
                "FTCATEGORY_MF",
                "FTCATEGORY_EGG",
                "FTCATEGORY_ALZ",
                "FTCATEGORY_LZ4",
                "FTCATEGORY_LZOP",
                "FTCATEGORY_ZST",
                "FTCATEGORY_RZIP",
                "FTCATEGORY_LZIP",
                "FTCATEGORY_LRZIP",
                "FTCATEGORY_DACT",
                "FTCATEGORY_ZPAQ",
                "FTCATEGORY_BH",
                "FTCATEGORY_B64",
                "FTCATEGORY_LZMA",
                "FTCATEGORY_XZ",
                "FTCATEGORY_FCL",
                "FTCATEGORY_ZIPX",
                "FTCATEGORY_CPIO",
                "FTCATEGORY_LZH",
                "FTCATEGORY_MP3",
                "FTCATEGORY_WAV",
                "FTCATEGORY_OGG_VORBIS",
                "FTCATEGORY_M3U",
                "FTCATEGORY_VPR",
                "FTCATEGORY_AAC",
                "FTCATEGORY_ADE",
                "FTCATEGORY_DB2",
                "FTCATEGORY_SQL",
                "FTCATEGORY_EDMX",
                "FTCATEGORY_FRM",
                "FTCATEGORY_ACCDB",
                "FTCATEGORY_DBF",
                "FTCATEGORY_VIRTUAL_HARD_DISK",
                "FTCATEGORY_DB",
                "FTCATEGORY_SDB",
                "FTCATEGORY_KDBX",
                "FTCATEGORY_DXL",
                "FTCATEGORY_WINDOWS_EXECUTABLES",
                "FTCATEGORY_MICROSOFT_INSTALLER",
                "FTCATEGORY_WINDOWS_LIBRARY",
                "FTCATEGORY_WINDOWS_LNK",
                "FTCATEGORY_PYTHON",
                "FTCATEGORY_POWERSHELL",
                "FTCATEGORY_VISUAL_BASIC_SCRIPT",
                "FTCATEGORY_MSP",
                "FTCATEGORY_REG",
                "FTCATEGORY_BAT",
                "FTCATEGORY_BASH_SCRIPTS",
                "FTCATEGORY_SHELL_SCRAP",
                "FTCATEGORY_DEB",
                "FTCATEGORY_APPX",
                "FTCATEGORY_MSC",
                "FTCATEGORY_ELF",
                "FTCATEGORY_MACH",
                "FTCATEGORY_DRV",
                "FTCATEGORY_GBA",
                "FTCATEGORY_SMD",
                "FTCATEGORY_XBEH",
                "FTCATEGORY_PSX",
                "FTCATEGORY_THREETWOX",
                "FTCATEGORY_NDS",
                "FTCATEGORY_BITMAP",
                "FTCATEGORY_PHOTOSHOP",
                "FTCATEGORY_WINDOWS_META_FORMAT",
                "FTCATEGORY_GIF",
                "FTCATEGORY_JPEG",
                "FTCATEGORY_PNG",
                "FTCATEGORY_WEBP",
                "FTCATEGORY_TIFF",
                "FTCATEGORY_DCM",
                "FTCATEGORY_THREEDM",
                "FTCATEGORY_KML",
                "FTCATEGORY_JPD",
                "FTCATEGORY_DNG",
                "FTCATEGORY_RWZ",
                "FTCATEGORY_GREENSHOT",
                "FTCATEGORY_IMG",
                "FTCATEGORY_HIGH_EFFICIENCY_IMAGE_FILES",
                "FTCATEGORY_AAF",
                "FTCATEGORY_OMFI",
                "FTCATEGORY_PLS",
                "FTCATEGORY_HLP",
                "FTCATEGORY_MDZ",
                "FTCATEGORY_MST",
                "FTCATEGORY_WINDOWS_SCRIPT_FILES",
                "FTCATEGORY_GRP",
                "FTCATEGORY_PIF",
                "FTCATEGORY_JOB",
                "FTCATEGORY_PSW",
                "FTCATEGORY_ONENOTE",
                "FTCATEGORY_CATALOG",
                "FTCATEGORY_NETMON",
                "FTCATEGORY_HIVE",
                "FTCATEGORY_APK",
                "FTCATEGORY_IPA",
                "FTCATEGORY_MOBILECONFIG",
                "FTCATEGORY_MS_POWERPOINT",
                "FTCATEGORY_MS_WORD",
                "FTCATEGORY_MS_EXCEL",
                "FTCATEGORY_MS_RTF",
                "FTCATEGORY_MS_MDB",
                "FTCATEGORY_MS_MSG",
                "FTCATEGORY_MS_PST",
                "FTCATEGORY_MS_VSIX",
                "FTCATEGORY_VSDX",
                "FTCATEGORY_OAB",
                "FTCATEGORY_OLM",
                "FTCATEGORY_MS_PUB",
                "FTCATEGORY_TNEF",
                "FTCATEGORY_ENCROFF",
                "FTCATEGORY_OPEN_OFFICE_DOC",
                "FTCATEGORY_OPEN_OFFICE_DRAWINGS",
                "FTCATEGORY_OPEN_OFFICE_PRESENTATIONS",
                "FTCATEGORY_OPEN_OFFICE_SPREADSHEETS",
                "FTCATEGORY_ENCRYPT",
                "FTCATEGORY_PDF_DOCUMENT",
                "FTCATEGORY_POSTSCRIPT",
                "FTCATEGORY_COMPILED_HTML_HELP",
                "FTCATEGORY_DWG",
                "FTCATEGORY_CGR",
                "FTCATEGORY_SLDPRT",
                "FTCATEGORY_TXT",
                "FTCATEGORY_UNK",
                "FTCATEGORY_IPT",
                "FTCATEGORY_XPS",
                "FTCATEGORY_CSV",
                "FTCATEGORY_STL",
                "FTCATEGORY_IQY",
                "FTCATEGORY_CERT",
                "FTCATEGORY_INTERNET_SIGNUP",
                "FTCATEGORY_PCAP",
                "FTCATEGORY_TTF",
                "FTCATEGORY_CRX",
                "FTCATEGORY_CER",
                "FTCATEGORY_DER",
                "FTCATEGORY_P7B",
                "FTCATEGORY_PEM",
                "FTCATEGORY_JKS",
                "FTCATEGORY_KEY",
                "FTCATEGORY_P12",
                "FTCATEGORY_CHEMDRAW_FILES",
                "FTCATEGORY_CML",
                "FTCATEGORY_BPL",
                "FTCATEGORY_CCC",
                "FTCATEGORY_CP",
                "FTCATEGORY_DEVFILE",
                "FTCATEGORY_MM",
                "FTCATEGORY_AES",
                "FTCATEGORY_WOFF2",
                "FTCATEGORY_STEP_FILES",
                "FTCATEGORY_RVT",
                "FTCATEGORY_EMF",
                "FTCATEGORY_PCD",
                "FTCATEGORY_INF",
                "FTCATEGORY_SAM",
                "FTCATEGORY_PMD",
                "FTCATEGORY_EOT",
                "FTCATEGORY_OPENXML",
                "FTCATEGORY_FODT",
                "FTCATEGORY_JOBOPTIONS",
                "FTCATEGORY_IDML",
                "FTCATEGORY_CXP",
                "FTCATEGORY_ENEX",
                "FTCATEGORY_OTF",
                "FTCATEGORY_LGX",
                "FTCATEGORY_CBZ",
                "FTCATEGORY_DPB",
                "FTCATEGORY_GLB",
                "FTCATEGORY_PM3",
                "FTCATEGORY_CD3",
                "FTCATEGORY_FLN",
                "FTCATEGORY_IVR",
                "FTCATEGORY_VU3",
                "FTCATEGORY_PFB",
                "FTCATEGORY_WIM",
                "FTCATEGORY_APPLE_DOCUMENTS",
                "FTCATEGORY_TABLEAU_FILES",
                "FTCATEGORY_AUTOCAD",
                "FTCATEGORY_INTEGRATED_CIRCUIT_FILES",
                "FTCATEGORY_LOG_FILES",
                "FTCATEGORY_EML_FILES",
                "FTCATEGORY_DAT",
                "FTCATEGORY_INI",
                "FTCATEGORY_THREED",
                "FTCATEGORY_THREEDA",
                "FTCATEGORY_THREEDFA",
                "FTCATEGORY_THREEDL",
                "FTCATEGORY_THREEDZ",
                "FTCATEGORY_APR",
                "FTCATEGORY_REALFLOW",
                "FTCATEGORY_COMP",
                "FTCATEGORY_DDF",
                "FTCATEGORY_DEM",
                "FTCATEGORY_THREEDS_MAX",
                "FTCATEGORY_GSP",
                "FTCATEGORY_HCL",
                "FTCATEGORY_MOTION_ANALYSIS",
                "FTCATEGORY_IGS",
                "FTCATEGORY_K3D",
                "FTCATEGORY_LIGHTSCAPE",
                "FTCATEGORY_AUTODESK_MAYA",
                "FTCATEGORY_MXS",
                "FTCATEGORY_OBJ",
                "FTCATEGORY_SHP",
                "FTCATEGORY_SPB",
                "FTCATEGORY_WRL",
                "FTCATEGORY_TMP",
                "FTCATEGORY_MUI",
                "FTCATEGORY_HBS",
                "FTCATEGORY_ICS",
                "FTCATEGORY_PUB",
                "FTCATEGORY_DRAWIO",
                "FTCATEGORY_PRT",
                "FTCATEGORY_PS2",
                "FTCATEGORY_PS3",
                "FTCATEGORY_ACIS",
                "FTCATEGORY_VDA",
                "FTCATEGORY_PARASOLID",
                "FTCATEGORY_PGP",
                "FTCATEGORY_BIN",
                "FTCATEGORY_JSON",
                "FTCATEGORY_XML",
                "FTCATEGORY_BINHEX",
                "FTCATEGORY_QUARKXPRESS",
                "FTCATEGORY_GO_FILES",
                "FTCATEGORY_SWIFT_FILES",
                "FTCATEGORY_RUBY_FILES",
                "FTCATEGORY_PERL_FILES",
                "FTCATEGORY_MATLAB_FILES",
                "FTCATEGORY_INCLUDE_FILES",
                "FTCATEGORY_JAVA_FILES",
                "FTCATEGORY_MAKE_FILES",
                "FTCATEGORY_YAML_FILES",
                "FTCATEGORY_VISUAL_BASIC_FILES",
                "FTCATEGORY_C_FILES",
                "FTCATEGORY_XAML",
                "FTCATEGORY_BASIC_SOURCE_CODE",
                "FTCATEGORY_SCT",
                "FTCATEGORY_A_FILE",
                "FTCATEGORY_MS_CPP_FILES",
                "FTCATEGORY_ASM",
                "FTCATEGORY_BORLAND_CPP_FILES",
                "FTCATEGORY_CLW",
                "FTCATEGORY_COBOL",
                "FTCATEGORY_CSX",
                "FTCATEGORY_DELPHI",
                "FTCATEGORY_DMD",
                "FTCATEGORY_DSP",
                "FTCATEGORY_F_FILES",
                "FTCATEGORY_NATVIS",
                "FTCATEGORY_NCB",
                "FTCATEGORY_NFM",
                "FTCATEGORY_POD",
                "FTCATEGORY_QLIKVIEW_FILES",
                "FTCATEGORY_RES_FILES",
                "FTCATEGORY_RPY",
                "FTCATEGORY_RSP",
                "FTCATEGORY_SAS",
                "FTCATEGORY_SC",
                "FTCATEGORY_SCALA",
                "FTCATEGORY_SWC",
                "FTCATEGORY_TCC",
                "FTCATEGORY_TLH",
                "FTCATEGORY_TLI",
                "FTCATEGORY_VISUAL_CPP_FILES",
                "FTCATEGORY_X1B",
                "FTCATEGORY_IFC",
                "FTCATEGORY_BCP",
                "FTCATEGORY_FOR",
                "FTCATEGORY_NCI",
                "FTCATEGORY_AU3",
                "FTCATEGORY_BGI",
                "FTCATEGORY_MANIFEST",
                "FTCATEGORY_NLS",
                "FTCATEGORY_TLB",
                "FTCATEGORY_ASHX",
                "FTCATEGORY_EXP",
                "FTCATEGORY_FLASH_VIDEO",
                "FTCATEGORY_AVI",
                "FTCATEGORY_MPEG",
                "FTCATEGORY_MP4",
                "FTCATEGORY_3GPP",
                "FTCATEGORY_QUICKTIME_VIDEO",
                "FTCATEGORY_WINDOWS_MEDIA_MOVIE",
                "FTCATEGORY_MKV",
                "FTCATEGORY_WEBM",
                "FTCATEGORY_VS4",
                "FTCATEGORY_TS",
            ],
        ),
        filtering_action=dict(
            type="str", required=False, choices=["ALLOW", "BLOCK", "CAUTION"]
        ),
        operation=dict(
            type="str",
            required=False,
            choices=["UPLOAD", "DOWNLOAD", "UPLOAD_DOWNLOAD"],
        ),
        protocols=dict(
            type="list",
            elements="str",
            required=False,
            choices=[
                "ANY_RULE",
                "SMRULEF_CASCADING_ALLOWED",
                "FOHTTP_RULE",
                "FTP_RULE",
                "SSL_RULE",
                "HTTPS_RULE",
                "HTTP_RULE",
            ],
        ),
        locations=id_spec,
        groups=id_spec,
        departments=id_spec,
        users=id_spec,
        time_windows=id_spec,
        location_groups=id_spec,
        labels=id_spec,
        device_groups=id_spec,
        devices=id_spec,
        zpa_app_segments=external_id_name_list_spec,
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
