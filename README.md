# Zscaler Internet Access (ZIA) Ansible Collection

[![Galaxy version](https://img.shields.io/badge/dynamic/json?style=flat&label=Galaxy&prefix=v&url=https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections/index/zscaler/ziacloud/versions/?is_highest=true&query=data[0].version)](https://galaxy.ansible.com/ui/repo/published/zscaler/ziacloud/)
[![Ansible Lint](https://github.com/zscaler/ziacloud-ansible/actions/workflows/ansible-test-lint.yml/badge.svg?branch=master)](https://github.com/zscaler/ziacloud-ansible/actions/workflows/ansible-test-lint.yml)
[![sanity](https://github.com/zscaler/ziacloud-ansible/actions/workflows/ansible-test-sanity.yml/badge.svg?branch=master)](https://github.com/zscaler/ziacloud-ansible/actions/workflows/ansible-test-sanity.yml)
[![Documentation Status](https://readthedocs.org/projects/ziacloud-ansible/badge/?version=latest)](https://ziacloud-ansible.readthedocs.io/en/latest/?badge=latest)
[![License](https://img.shields.io/github/license/zscaler/ziacloud-ansible?color=blue)](https://github.com/zscaler/ziacloud-ansible/v2/blob/master/LICENSE)
[![Zscaler Community](https://img.shields.io/badge/zscaler-community-blue)](https://community.zscaler.com/)

## Zscaler Support

-> **Disclaimer:** Please refer to our [General Support Statement](https://zscaler.github.io/ziacloud-ansible/support.html) before proceeding with the use of this collection. You can also refer to our [troubleshooting guide](https://zscaler.github.io/ziacloud-ansible/troubleshooting.html) for guidance on typical problems.

This collection contains modules and plugins to assist in automating the configuration and operational tasks on Zscaler Internet Access cloud, and API interactions with Ansible.

- Free software: [MIT License](https://github.com/zscaler/ziacloud-ansible/blob/master/LICENSE)
- [Documentation](https://zscaler.github.io/ziacloud-ansible)
- [Repository](https://github.com/zscaler/ziacloud-ansible)
- [Example Playbooks](https://github.com/zscaler/ziacloud-playbooks)

## Tested Ansible Versions

This collection is tested with the most current Ansible releases. Ansible versions
before 2.15 are **not supported**.

## Python dependencies

The minimum python version for this collection is python `3.9`.

The Python module dependencies are not automatically handled by `ansible-galaxy`. To manually install these dependencies, you have the following options:

1. Utilize the `requirements.txt` file located [here](https://github.com/zscaler/ziacloud-ansible/blob/master/requirements.txt) to install all required packages:

  ```sh
    pip install -r requirements.txt
  ```

2. Alternatively, install the [Zscaler SDK Python](https://pypi.org/project/zscaler-sdk-python/) package directly:

  ```sh
    pip install zscaler-sdk-python
  ```

## Installation

Install this collection using the Ansible Galaxy CLI:

```sh
ansible-galaxy collection install zscaler.ziacloud
```

You can also include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
  collections:
    - zscaler.ziacloud
```

## Zscaler OneAPI New Framework

The ZIA Ansible Collection now offers support for [OneAPI](https://help.zscaler.com/oneapi/understanding-oneapi) OAuth2 authentication through [Zidentity](https://help.zscaler.com/zidentity/what-zidentity).

**NOTE** As of version v2.0.0, this Ansible Collection offers backwards compatibility to the Zscaler legacy API framework. This is the recommended authentication method for organizations whose tenants are still not migrated to [Zidentity](https://help.zscaler.com/zidentity/what-zidentity).

**NOTE** Notice that OneAPI and Zidentity is not currently supported for the following clouds: `zscalergov` and `zscalerten`. Refer to the [Legacy API Framework](#legacy-api-framework) for more information on how authenticate to these environments

## OneAPI - Using modules from the ziacloud Collection in your playbooks

It's preferable to use content in this collection using their [Fully Qualified Collection Namespace (FQCN)](https://ansible.readthedocs.io/projects/lint/rules/fqcn/), for example `zscaler.ziacloud.zia_cloud_firewall_rule`:

### Examples Usage - Client Secret Authentication

```yaml
---
- name: ZIA Cloud Firewall Rule
  hosts: localhost

  vars:
    zia_cloud:
      client_id: "{{ lookup('env', 'ZSCALER_CLIENT_ID') }}"
      client_secret: "{{ lookup('env', 'ZSCALER_CLIENT_SECRET') }}"
      vanity_domain: "{{ lookup('env', 'ZSCALER_VANITY_DOMAIN') }}"
      cloud: "{{ lookup('env', 'ZSCALER_CLOUD') | default(omit) }}"

  tasks:
    - name: Create/update firewall rule
      zscaler.ziacloud.zia_cloud_firewall_rule:
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

**NOTE**: The `zscaler_cloud` is optional and only required when authenticating to other environments i.e `beta`

⚠️ **WARNING:** Hard-coding credentials into any Ansible playbook configuration is not recommended, and risks secret leakage should this file be committed to public version controls.

### Examples Usage - Private Key Authentication

```yaml
---
- name: ZIA Cloud Firewall Rule
  hosts: localhost

  vars:
    zia_cloud:
      client_id: "{{ client_id | default(omit) }}"
      private_key: "{{ lookup('file', 'private_key.pem') | default(omit) }}"
      vanity_domain: "{{ vanity_domain | default(omit) }}"
      cloud: "{{ cloud | default(omit) }}"

  tasks:
    - name: Create/update firewall rule
      zscaler.ziacloud.zia_cloud_firewall_rule:
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

## Authentication - OneAPI New Framework

As of version v2.0.0, this provider supports authentication via the new Zscaler API framework [OneAPI](https://help.zscaler.com/oneapi/understanding-oneapi)

Zscaler OneAPI uses the OAuth 2.0 authorization framework to provide secure access to Zscaler Internet Access (ZIA) APIs. OAuth 2.0 allows third-party applications to obtain controlled access to protected resources using access tokens. OneAPI uses the Client Credentials OAuth flow, in which client applications can exchange their credentials with the authorization server for an access token and obtain access to the API resources, without any user authentication involved in the process.

- [ZIA API](https://help.zscaler.com/oneapi/understanding-oneapi#:~:text=managed%20using%20OneAPI.-,ZIA%20API,-Zscaler%20Internet%20Access)

### Default Environment variables

You can provide credentials via the `ZSCALER_CLIENT_ID`, `ZSCALER_CLIENT_SECRET`, `ZSCALER_VANITY_DOMAIN`, `ZSCALER_CLOUD` environment variables, representing your Zidentity OneAPI credentials `clientId`, `clientSecret`, `vanityDomain` and `zscaler_cloud` respectively.

| Argument        | Description                                                                                         | Environment Variable     |
|-----------------|-----------------------------------------------------------------------------------------------------|--------------------------|
| `client_id`     | _(String)_ Zscaler API Client ID, used with `client_secret` or `private_key` OAuth auth mode.         | `ZSCALER_CLIENT_ID`      |
| `client_secret` | _(String)_ Secret key associated with the API Client ID for authentication.                         | `ZSCALER_CLIENT_SECRET`  |
| `private_key`    | _(String)_ A string Private key value.                                                              | `ZSCALER_PRIVATE_KEY`    |
| `vanity_domain` | _(String)_ Refers to the domain name used by your organization.                                     | `ZSCALER_VANITY_DOMAIN`  |
| `zscaler_cloud`         | _(String)_ The name of the Zidentity cloud, e.g., beta.                                             | `ZSCALER_CLOUD`          |

### Alternative OneAPI Cloud Environments

OneAPI supports authentication and can interact with alternative Zscaler enviornments i.e `beta`. To authenticate to these environments you must provide the following values:

| Argument         | Description                                                                                         |   | Environment Variable     |
|------------------|-----------------------------------------------------------------------------------------------------|---|--------------------------|
| `vanity_domain`   | _(String)_ Refers to the domain name used by your organization |   | `ZSCALER_VANITY_DOMAIN`  |
| `zscaler_cloud`          | _(String)_ The name of the Zidentity cloud i.e beta      |   | `ZSCALER_CLOUD`          |

For example: Authenticating to Zscaler Beta environment:

```sh
export ZSCALER_VANITY_DOMAIN="acme"
export ZSCALER_CLOUD="beta"
```

### OneAPI (API Client Scope)

OneAPI Resources are automatically created within the ZIdentity Admin UI based on the RBAC Roles
applicable to APIs within the various products. For example, in ZIA, navigate to `Administration -> Role
Management` and select `Add API Role`.

Once this role has been saved, return to the ZIdentity Admin UI and from the Integration menu
select API Resources. Click the `View` icon to the right of Zscaler APIs and under the ZIA
dropdown you will see the newly created Role. In the event a newly created role is not seen in the
ZIdentity Admin UI a `Sync Now` button is provided in the API Resources menu which will initiate an
on-demand sync of newly created roles.

## Legacy API Framework

### ZIA Native Authentication

- As of version v2.0.0, this Ansible Collection offers backwards compatibility to the Zscaler legacy API framework. This is the recommended authentication method for organizations whose tenants are still **NOT** migrated to [Zidentity](https://help.zscaler.com/zidentity/what-zidentity).

### Examples Usage

```yaml
---
- name: ZIA Cloud Firewall Rule
  hosts: localhost

  vars:
    zia_cloud:
      username: "{{ username | default(omit) }}"
      password: "{{ password | default(omit) }}"
      api_key: "{{ api_key | default(omit) }}"
      cloud: "{{ cloud | default(omit) }}"
      use_legacy_client: "{{ use_legacy_client | default(omit) }}"

  tasks:
    - name: Create/update firewall rule
      zscaler.ziacloud.zia_cloud_firewall_rule:
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

The ZIA Cloud is identified by several cloud name prefixes, which determines which API endpoint the requests should be sent to. The following cloud environments are supported:

- `zscaler`
- `zscloud`
- `zscalerone`
- `zscalertwo`
- `zscalerthree`
- `zscalerbeta`
- `zscalergov`
- `zscalerten`
- `zspreview`

### Environment variables

You can provide credentials via the `ZIA_USERNAME`, `ZIA_PASSWORD`, `ZIA_API_KEY`, `ZIA_CLOUD`, `ZSCALER_USE_LEGACY_CLIENT` environment variables, representing your ZIA `username`, `password`, `api_key`,  `zia_cloud` and `use_legacy_client` respectively.

| Argument     | Description | Environment variable |
|--------------|-------------|-------------------|
| `username`       | _(String)_ A string that contains the email ID of the API admin.| `ZIA_USERNAME` |
| `password`       | _(String)_ A string that contains the password for the API admin.| `ZIA_PASSWORD` |
| `api_key`       | _(String)_ A string that contains the obfuscated API key (i.e., the return value of the obfuscateApiKey() method).| `ZIA_API_KEY` |
| `zia_cloud`       | _(String)_ The host and basePath for the cloud services API is `$zsapi.<Zscaler Cloud Name>/api/v1`.| `ZIA_CLOUD` |
| `use_legacy_client`       | _(Bool)_ Enable use of the legacy ZIA API Client.| `ZSCALER_USE_LEGACY_CLIENT` |

```sh
# Change place holder values denoted by brackets to real values, including the
# brackets.

$ export ZIA_USERNAME="[ZIA_USERNAME]"
$ export ZIA_PASSWORD="[ZIA_PASSWORD]"
$ export ZIA_API_KEY="[ZIA_API_KEY]"
$ export ZIA_CLOUD="[ZIA_CLOUD]"
$ export ZSCALER_USE_LEGACY_CLIENT=true
```

⚠️ **WARNING:** Hard-coding credentials into any Ansible playbook configuration is not recommended, and risks secret leakage should this file be committed to public version control

For details about how to retrieve your tenant Base URL and API key/token refer to the Zscaler help portal. <https://help.zscaler.com/zia/getting-started-zia-api>

### Zscaler Sandbox Authentication

As of version v2.0.0, the legacy sandbox authentication environment variables `ZIA_CLOUD` and `ZIA_SANDBOX_TOKEN` are no longer supported.

Authentication to the Zscaler Sandbox service requires the following new environment variables the `ZSCALER_SANDBOX_CLOUD` and `ZSCALER_SANDBOX_TOKEN` or authentication attributes `sandbox_token` and `sandbox_cloud`. For details on how obtain the API Token visit the Zscaler help portal [About Sandbox API Token](https://help.zscaler.com/zia/about-sandbox-api-token)

## Releasing, changelogs, versioning and deprecation

The intended release frequency for major and minor versions are performed whenever there is a need for fixing issues or to address security concerns.

Changelog details are created automatically and more recently can be found [here](./CHANGELOG.md), but also the full history is [here](https://github.com/zscaler/ziacloud-ansible/releases).

[Semantic versioning](https://semver.org/) is adhered to for this project.

Deprecations are done by version number, not by date or by age of release. Breaking change deprecations will only be made with major versions.

## Support

The Zscaler Internet Access (ZIA) Collection of Ansible Modules is [certified on Ansible Automation Hub](https://console.redhat.com/ansible/automation-hub/repo/published/zscaler/ziacloud) and officially supported for Ansible subscribers. Ansible subscribers can engage for support through their usual route towards Red Hat.

For those who are not Ansible subscribers, this Collection of Ansible Modules is also [published on Ansible Galaxy](https://galaxy.ansible.com/ui/repo/published/zscaler/ziacloud) and also supported via the formal Zscaler suppport process. Please refer to our [General Support Statement](https://zscaler.github.io/ziacloud-ansible/support.html)

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
