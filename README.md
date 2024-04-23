# Zscaler Internet Access (ZIA) Ansible Collection (Beta)

[![Galaxy version](https://img.shields.io/badge/dynamic/json?style=flat&label=Galaxy&prefix=v&url=https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections/index/zscaler/ziacloud/versions/?is_highest=true&query=data[0].version)](https://galaxy.ansible.com/ui/repo/published/zscaler/ziacloud/)
[![Ansible Lint](https://github.com/zscaler/ziacloud-ansible/actions/workflows/ansible-test-lint.yml/badge.svg?branch=master)](https://github.com/zscaler/ziacloud-ansible/actions/workflows/ansible-test-lint.yml)
[![sanity](https://github.com/zscaler/ziacloud-ansible/actions/workflows/ansible-test-sanity.yml/badge.svg?branch=master)](https://github.com/zscaler/ziacloud-ansible/actions/workflows/ansible-test-sanity.yml)
[![License](https://img.shields.io/github/license/zscaler/ziacloud-ansible?color=blue)](https://github.com/zscaler/ziacloud-ansible/v2/blob/master/LICENSE)
[![docs passing](https://img.shields.io/readthedocs/ziacloud-ansible)](https://github.com/zscaler/ziacloud-ansible/actions/workflows/pages/pages-build-deployment)
[![Zscaler Community](https://img.shields.io/badge/zscaler-community-blue)](https://community.zscaler.com/)

## Zscaler Support

-> **Disclaimer:** Please refer to our [General Support Statement](https://zscaler.github.io/ziacloud-ansible/support.html) before proceeding with the use of this collection. You can also refer to our [troubleshooting guide](https://zscaler.github.io/ziacloud-ansible/troubleshooting.html) for guidance on typical problems.

This collection contains modules and plugins to assist in automating the configuration and operational tasks on Zscaler Internet Access cloud, and API interactions with Ansible.

- Free software: [MIT License](https://github.com/zscaler/ziacloud-ansible/blob/master/LICENSE)
- [Documentation](https://zscaler.github.io/ziacloud-ansible)
- [Repository](https://github.com/zscaler/ziacloud-ansible)
- [Example Playbooks](https://github.com/zscaler/ziacloud-playbooks)

## Tested Ansible Versions

This collection is tested with the most current Ansible releases.  Ansible versions
before 2.15 are **not supported**.

## Python Version

The minimum python version for this collection is python `3.9`.

## Installation

Install this collection using the Ansible Galaxy CLI:

```bash
ansible-galaxy collection install zscaler.ziacloud
```

You can also include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
  collections:
    - zscaler.ziacloud
```

## Using modules from the ziacloud Collection in your playbooks

It's preferable to use content in this collection using their [Fully Qualified Collection Namespace (FQCN)](https://ansible.readthedocs.io/projects/lint/rules/fqcn/), for example `zscaler.ziacloud.zia_cloud_firewall_filtering_rule`:

```yaml
---
- name: ZIA Cloud Firewall Rule
  hosts: localhost

  vars:
    zia_cloud:
      username: "{{ lookup('env', 'ZIA_USERNAME') }}"
      password: "{{ lookup('env', 'ZIA_PASSWORD') }}"
      api_key: "{{ lookup('env', 'ZIA_API_KEY') }}"
      cloud: "{{ lookup('env', 'ZIA_CLOUD') | default(omit) }}"

  tasks:
    - name: Create/update firewall filtering rule
      zscaler.ziacloud.zia_cloud_firewall_filtering_rule:
        provider: "{{ zia_cloud }}"
        name: "Ansible Example"
        description: "Ansible Example"
        action: "ALLOW"
        rule_state: "ENABLED"
        order: 1
        enable_full_logging: true
        nw_services:
          - "774003"
          - "774013"
      register: created_rule
    - debug:
        msg: "{{ created_rule }}"
```

(Note that [use of the `collections` key is now discouraged](https://ansible-lint.readthedocs.io/rules/fqcn/))

## Releasing, changelogs, versioning and deprecation

The intended release frequency for major and minor versions are performed whenever there is a need for fixing issues or to address security concerns.

Changelog details are created automatically and more recently can be found [here](./CHANGELOG.md), but also the full history is [here](https://github.com/zscaler/ziacloud-ansible/releases).

[Semantic versioning](https://semver.org/) is adhered to for this project.

Deprecations are done by version number, not by date or by age of release. Breaking change deprecations will only be made with major versions.

## Support

The Zscaler Internet Access (ZIA) Collection of Ansible Modules is [certified on Ansible Automation Hub](https://console.redhat.com/ansible/automation-hub/repo/published/zscaler/ziacloud) and officially supported for Ansible subscribers. Ansible subscribers can engage for support through their usual route towards Red Hat.

For those who are not Ansible subscribers, this Collection of Ansible Modules is also [published on Ansible Galaxy](https://galaxy.ansible.com/ui/repo/published/zscaler/ziacloud) and also supported via the formal Zscaler suppport process. Please refer to our [General Support Statement](/docs/support.md)

## MIT License

Copyright (c) 2023 [Zscaler](https://github.com/zscaler)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
