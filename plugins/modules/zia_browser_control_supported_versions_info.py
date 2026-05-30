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
module: zia_browser_control_supported_versions_info
short_description: "Gets the supported browsers and their versions"
description:
  - "Retrieves the list of all supported browsers and their versions for the Browser Control policy."
  - "The API returns a flat list with no server-side filtering, so all filtering is performed locally by this module."
author:
  - William Guilherme (@willguibr)
version_added: "2.1.0"
requirements:
    - Zscaler SDK Python can be obtained from PyPI U(https://pypi.org/project/zscaler-sdk-python/)
notes:
    - Check mode is supported.
    - All filters are applied client-side after retrieving the full list.
    - When C(versions) or C(older_versions) is set, matching entries are returned with their
      C(versions) and C(older_versions) lists narrowed to ONLY the requested tokens, so the
      output stays focused on what was searched. A field that was not searched is returned empty.
    - When multiple of C(browser_type), C(versions) and C(older_versions) are set, they are combined with logical AND.
    - C(query) (JMESPath) is applied last, to the already filtered list.
extends_documentation_fragment:
  - zscaler.ziacloud.fragments.provider
  - zscaler.ziacloud.fragments.documentation

options:
  browser_type:
    description:
      - Return only the entry matching a specific browser type.
      - If not set, all supported browsers are returned.
    required: false
    type: str
    choices:
      - OPERA
      - FIREFOX
      - MSIE
      - MSEDGE
      - CHROME
      - SAFARI
      - OTHER
      - MSCHREDGE
  versions:
    description:
      - Return only browser entries whose C(versions) list contains at least one of the supplied values.
      - The returned C(versions) list is narrowed to only the matched values, and C(older_versions) is returned empty unless also searched.
    required: false
    type: list
    elements: str
  older_versions:
    description:
      - Return only browser entries whose C(older_versions) list contains at least one of the supplied values.
      - The returned C(older_versions) list is narrowed to only the matched values, and C(versions) is returned empty unless also searched.
    required: false
    type: list
    elements: str
  query:
    description:
      - An optional JMESPath expression applied locally to the (already filtered) list of browser entries.
      - Use this for advanced filtering/projection that the simple key filters cannot express.
      - See U(https://jmespath.org/) for the expression syntax.
      - Each entry exposes the keys C(browser_type), C(versions) and C(older_versions).
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Get all supported browsers and their versions
  zscaler.ziacloud.zia_browser_control_supported_versions_info:
    provider: '{{ provider }}'

- name: Get supported versions for a specific browser type
  zscaler.ziacloud.zia_browser_control_supported_versions_info:
    provider: '{{ provider }}'
    browser_type: CHROME

# Returns the matching entries with `versions` narrowed to only the searched
# tokens, e.g. [{browser_type: CHROME, versions: [CH143], older_versions: []},
#               {browser_type: FIREFOX, versions: [MF145], older_versions: []}]
- name: Find which browsers support specific current versions (focused output)
  zscaler.ziacloud.zia_browser_control_supported_versions_info:
    provider: '{{ provider }}'
    versions:
      - CH143
      - MF145

# Returns e.g. [{browser_type: CHROME, versions: [], older_versions: [CH100]}]
- name: Find which browsers list a specific older version (focused output)
  zscaler.ziacloud.zia_browser_control_supported_versions_info:
    provider: '{{ provider }}'
    older_versions:
      - CH100

- name: Combine simple filters (CHROME entry that also has version CH143)
  zscaler.ziacloud.zia_browser_control_supported_versions_info:
    provider: '{{ provider }}'
    browser_type: CHROME
    versions:
      - CH143

# --- Advanced local filtering with JMESPath (query is applied last) ---
# Note: a trailing field selector (e.g. ".browser_type") is a JMESPath
# projection and returns ONLY that field. Omit it to return full entries.

- name: Return the full browser entries that currently support version CH143
  zscaler.ziacloud.zia_browser_control_supported_versions_info:
    provider: '{{ provider }}'
    query: "[?contains(versions, 'CH143')]"

- name: Return ONLY the browser type names that support version CH143
  zscaler.ziacloud.zia_browser_control_supported_versions_info:
    provider: '{{ provider }}'
    query: "[?contains(versions, 'CH143')].browser_type"

- name: Project a flat list of browser_type with just its current versions
  zscaler.ziacloud.zia_browser_control_supported_versions_info:
    provider: '{{ provider }}'
    query: "[].{type: browser_type, current: versions}"

- name: Get the full entry for a single browser type via JMESPath
  zscaler.ziacloud.zia_browser_control_supported_versions_info:
    provider: '{{ provider }}'
    query: "[?browser_type=='FIREFOX'] | [0]"

- name: Find browser types that still list any older versions
  zscaler.ziacloud.zia_browser_control_supported_versions_info:
    provider: '{{ provider }}'
    query: "[?length(older_versions) > `0`].browser_type"

# --- Using the result in a playbook ---

- name: Retrieve Chrome supported versions and reuse them
  zscaler.ziacloud.zia_browser_control_supported_versions_info:
    provider: '{{ provider }}'
    browser_type: CHROME
  register: chrome_versions

- name: Show the current Chrome versions
  ansible.builtin.debug:
    msg: "{{ chrome_versions.browsers[0].versions }}"
"""

RETURN = r"""
browsers:
  description: A list of supported browsers and their versions, after any local filtering.
  returned: always
  type: list
  elements: dict
  contains:
    browser_type:
      description: The browser type.
      type: str
      sample: "CHROME"
    versions:
      description: The current versions of the browser.
      type: list
      elements: str
    older_versions:
      description: Earlier versions of the browser.
      type: list
      elements: str
"""

from traceback import format_exc

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zscaler.ziacloud.plugins.module_utils.zia_client import (
    ZIAClientHelper,
)
from ansible_collections.zscaler.ziacloud.plugins.module_utils.utils import (
    filter_by_jmespath,
)


def _narrow_by_versions(browsers, versions, older_versions):
    """
    Filter and focus browser entries by the requested version tokens.

    When ``versions`` and/or ``older_versions`` are supplied, only entries that
    contain at least one requested token (in the corresponding field that was
    searched) are kept. Each returned entry is narrowed so that its ``versions``
    and ``older_versions`` lists contain ONLY the requested tokens, keeping the
    output focused on what was searched instead of the full version catalog.
    """
    req_versions = set(versions or [])
    req_older = set(older_versions or [])

    focused = []
    for b in browsers:
        entry_versions = b.get("versions") or []
        entry_older = b.get("older_versions") or []

        version_match = req_versions.intersection(entry_versions)
        older_match = req_older.intersection(entry_older)

        # An entry qualifies only on a field the user actually searched.
        if not ((versions and version_match) or (older_versions and older_match)):
            continue

        narrowed = dict(b)
        narrowed["versions"] = [v for v in entry_versions if v in req_versions]
        narrowed["older_versions"] = [v for v in entry_older if v in req_older]
        focused.append(narrowed)

    return focused


def core(module):
    browser_type = module.params.get("browser_type")
    versions = module.params.get("versions")
    older_versions = module.params.get("older_versions")
    query = module.params.get("query")
    client = ZIAClientHelper(module)

    result, _unused, error = client.secure_browsing.get_supported_browser_versions()
    if error:
        module.fail_json(msg=f"Error retrieving supported browser versions: {to_native(error)}")

    browsers = [b.as_dict() if hasattr(b, "as_dict") else b for b in result] if result else []

    if browser_type:
        browsers = [b for b in browsers if b.get("browser_type") == browser_type]

    if versions or older_versions:
        browsers = _narrow_by_versions(browsers, versions, older_versions)

    if query:
        try:
            browsers = filter_by_jmespath(browsers, query)
        except (ImportError, ValueError) as e:
            module.fail_json(msg=to_native(e))
        if browsers is None:
            browsers = []

    module.exit_json(changed=False, browsers=browsers)


def main():
    argument_spec = ZIAClientHelper.zia_argument_spec()
    argument_spec.update(
        browser_type=dict(
            type="str",
            required=False,
            choices=[
                "OPERA",
                "FIREFOX",
                "MSIE",
                "MSEDGE",
                "CHROME",
                "SAFARI",
                "OTHER",
                "MSCHREDGE",
            ],
        ),
        versions=dict(type="list", elements="str", required=False),
        older_versions=dict(type="list", elements="str", required=False),
        query=dict(type="str", required=False),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())


if __name__ == "__main__":
    main()
