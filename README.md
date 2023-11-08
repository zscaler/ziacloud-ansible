# Zscaler Internet Access (ZIA) Ansible Collection

This collection contains modules and plugins to assist in automating the configuration and operational tasks on Zscaler Internet Access cloud, and API interactions with Ansible.

- Free software: Apache 2.0 License
- Documentation:
    <https://zscaler.github.io/ziacloud-ansible/>
- Repo:
    <https://github.com/zscaler/ziacloud-ansible>
- Example Playbooks:
    <https://github.com/zscaler/ziacloud-playbooks>

## Tested Ansible Versions

This collection is tested with the most current Ansible 2.9 and 2.10 releases. Ansible versions
before 2.9.10 are **not supported**.

## Included content

- [zia_admin_role_management_info](https://zscaler.github.io/ziacloud-ansible/modules/zia_admin_role_management_info.html) - Gets a list of admin roles
- [zia_cloud_firewall_filtering_rule_info](https://zscaler.github.io/ziacloud-ansible/modules/zia_cloud_firewall_filtering_rule_info.html) - Create/Update/Delete an application segment.
- [zia_cloud_firewall_filtering_rule](https://zscaler.github.io/ziacloud-ansible/modules/zia_cloud_firewall_filtering_rule.html) - Gather information details (ID and/or Name) of a application segment.
- [zia_cloud_firewall_ip_destination_groups_info](https://zscaler.github.io/ziacloud-ansible/modules/zia_cloud_firewall_ip_destination_groups_info.html) - Create/Update/Delete an Application Server.
- [zia_cloud_firewall_ip_destination_groups](https://zscaler.github.io/ziacloud-ansible/modules/zia_cloud_firewall_ip_destination_groups.html) - Gather information details (ID and/or Name) of an application server.
- [zia_cloud_firewall_ip_source_groups_info](https://zscaler.github.io/ziacloud-ansible/modules/zia_cloud_firewall_ip_source_groups_info.html) - Gather information details (ID and/or Name) of an browser access certificate.
- [zia_cloud_firewall_ip_source_groups](https://zscaler.github.io/ziacloud-ansible/modules/zia_cloud_firewall_ip_source_groups.html) - Gather information details (ID and/or Name) of an cloud connector group.
- [zpa_customer_version_profile_info](https://zscaler.github.io/ziacloud-ansible/modules/zpa_customer_version_profile_info.html) - Gather information details (ID and/or Name) of an customer version profile for use in app connector group resource in the `version_profile_id` parameter.
- [zia_cloud_firewall_network_application_groups_info](https://zscaler.github.io/ziacloud-ansible/modules/zia_cloud_firewall_network_application_groups_info.html) - Gather information details (ID and/or Name) of an enrollment certificate for use when creating provisioning keys for connector groups or service edge groups.
- [zia_cloud_firewall_network_application_groups](https://zscaler.github.io/ziacloud-ansible/modules/zia_cloud_firewall_network_application_groups.html) - Gather information details (ID and/or Name) of an identity provider (IdP) created in the ZPA tenant.
- [zia_cloud_firewall_network_services_groups_info](https://zscaler.github.io/ziacloud-ansible/modules/zia_cloud_firewall_network_services_groups_info.html) - Gather information details (ID and/or Name) of an machine group for use in a policy access and/or forwarding rules.
- [zia_cloud_firewall_network_services_groups](https://zscaler.github.io/ziacloud-ansible/modules/zia_cloud_firewall_network_services_groups.html) - Create/Update/Delete a policy access rule.
- [zia_cloud_firewall_network_services_info](https://zscaler.github.io/ziacloud-ansible/modules/zia_cloud_firewall_network_services_info.html) - Gather information details (ID and/or Name) of a policy access rule.
- [zia_cloud_firewall_network_services](https://zscaler.github.io/ziacloud-ansible/modules/zia_cloud_firewall_network_services.html) - Create/Update/Delete a policy access timeout rule.
- [zia_dlp_dictionaries_info](https://zscaler.github.io/ziacloud-ansible/modules/zia_dlp_dictionaries_info.html) - Gather information details (ID and/or Name) of a policy access timeout rule.
- [zia_dlp_dictionaries](https://zscaler.github.io/ziacloud-ansible/modules/zia_dlp_dictionaries.html) - Create/Update/Delete a policy access forwarding rule.
- [zia_location_management_info](https://zscaler.github.io/ziacloud-ansible/modules/zia_location_management_info.html) - Gather information details (ID and/or Name) of a policy access forwarding rule.
- [zia_location_management](https://zscaler.github.io/ziacloud-ansible/modules/zia_location_management.html) - Gather information details (ID and/or Name) of a posture profile to use in a policy access, timeout or forwarding rules.
- [zia_rule_labels_info](https://zscaler.github.io/ziacloud-ansible/modules/zia_rule_labels_info.html) - Create/Update/Delete a provisioning key.
- [zia_rule_labels](https://zscaler.github.io/ziacloud-ansible/modules/zia_rule_labels.html) - Gather information details (ID and/or Name) of a provisioning key.
- [zia_traffic_forwarding_static_ips_info](https://zscaler.github.io/ziacloud-ansible/modules/zia_traffic_forwarding_static_ips_info.html) - Gather information details (ID and/or Name) of a saml attribute.
- [zia_traffic_forwarding_static_ips](https://zscaler.github.io/ziacloud-ansible/modules/zia_traffic_forwarding_static_ips.html) - Gather information details (ID and/or Name) of a scim attribute header.
- [zia_traffic_forwarding_vpn_credentials_info](https://zscaler.github.io/ziacloud-ansible/modules/zia_traffic_forwarding_vpn_credentials_info.html) - Gather information details (ID and/or Name) of a scim group.
- [zia_traffic_forwarding_vpn_credentials](https://zscaler.github.io/ziacloud-ansible/modules/zia_traffic_forwarding_vpn_credentials.html) - Create/Update/Delete a segment group.
- [zia_url_categories_info](https://zscaler.github.io/ziacloud-ansible/modules/zia_url_categories_info.html) - Gather information details (ID and/or Name) of a segment group.
- [zia_url_categories](https://zscaler.github.io/ziacloud-ansible/modules/zia_url_categories.html) - Create/Update/Delete a segment group.
- [zia_url_filtering_rules_info](https://zscaler.github.io/ziacloud-ansible/modules/zia_url_filtering_rules_info.html) - Gather information details (ID and/or Name) of a server group.
- [zia_url_filtering_rules](https://zscaler.github.io/ziacloud-ansible/modules/zia_url_filtering_rules.html) - Gather information details (ID and/or Name) of a service edge group.
- [zia_user_management_department_info](https://zscaler.github.io/ziacloud-ansible/modules/zia_user_management_department_info.html) - Create/Update/Delete an service edge group.
- [zia_user_management_groups_info](https://zscaler.github.io/ziacloud-ansible/modules/zia_user_management_groups_info.html) - Gather information details (ID and/or Name) of a trusted network for use in a policy access and/or forwarding rules.
- [zia_user_management_info](https://zscaler.github.io/ziacloud-ansible/modules/zia_user_management_info.html) - Gather information details (ID and/or Name) of a trusted network for use in a policy access and/or forwarding rules.

## Installation and Usage

Before using the ziacloud collection, you need to install it with the Ansible Galaxy CLI:

```bash
ansible-galaxy collection install zscaler.ziacloud
```

You can also include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
  collections:
    - zscaler.ziacloud
```

### Using modules from the ziacloud Collection in your playbooks

It's preferable to use content in this collection using their Fully Qualified Collection Namespace (FQCN), for example `zscaler.ziacloud.zia_cloud_firewall_filtering_rule`:

```yaml
---
- hosts: localhost
  gather_facts: false
  connection: local

  tasks:
    - name: Get Information Details of All Customer Version Profiles
      zscaler.ziacloud.zia_cloud_firewall_filtering_rule_info:
      register: cloud_firewall_rule

    - name: Create/update  firewall filtering rule
      zscaler.ziacloud.zia_fw_filtering_rule:
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

If you are using versions prior to Ansible 2.10 and this collection's existence, you can also define `collections` in your play and refer to this collection's modules as you did in Ansible 2.9 and below, as in this example:

```yaml
---
- hosts: localhost
  gather_facts: false
  connection: local

  collections:
    - zscaler.ziacloud

  tasks:
    - name: Get Information Details of All Customer Version Profiles
      zpa_customer_version_profile_info:
      register: version_profile_id

    - name: Create App Connector Group Example
      zpa_app_connector_groups:
        name: "Example"
        description: "Example"
        enabled: true
        city_country: "California, US"
        country_code: "US"
        latitude: "37.3382082"
        longitude: "-121.8863286"
        location: "San Jose, CA, USA"
        upgrade_day: "SUNDAY"
        upgrade_time_in_secs: "66600"
        override_version_profile: true
        version_profile_id: "{{ version_profile_id.data[0].id }}"
        dns_query_type: "IPV4"
        ...
```

## Licensing

GNU General Public License v3.0 or later.

See [LICENSE](http://www.apache.org/licenses/) to see the full text.
