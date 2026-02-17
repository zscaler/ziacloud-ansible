.. ...........................................................................
.. © Copyright Zscaler Inc, 2024                                             .
.. ...........................................................................

======================
Releases
======================

Zscaler Internet Access (ZIA) Ansible Collection Changelog
----------------------------------------------------------

Version 2.1.0
==============

v2.1.0 (February 16, 2026)
-------------------------
### Notes

- Python Versions: **v3.9, v3.10, v3.11**

#### Enhancements

* (`#105 <https://github.com/zscaler/ziacloud-ansible/pull/105>`_) - Added the following new resources:
  - `zia_sub_cloud` and `zia_sub_cloud_info` - Manage Zscaler Sub-Clouds in ZIA
  - `zia_extranet` and `zia_extranet_info` - Manage Extranet configurations in ZIA
  - `zia_dc_exclusions` and `zia_dc_exclusions_info` - Manage Extranet configurations in ZIA
  - `zia_tenant_restriction_profile` and `zia_tenant_restriction_profile_info`,
  - `zia_workload_groups` and `zia_workload_groups_info` - Manages workload group for an organization.
  -  `zia_virtual_service_edge_node` and `zia_virtual_service_edge_node` - Retrieves the Virtual Service Edge Nodes (VZEN). This resource can be used to set the corresponding node when configuring the resource `zia_vzen_cluster`.
  - `zia_vzen_cluster` and `zia_vzen_cluster_info` - Manage Virtual Service Edge cluster
  - `zia_custom_file_types` and `zia_custom_file_types_info`
  - `zia_casb_dlp_rules` and   - `zia_casb_dlp_rules_info` - SaaS Security API (Casb DLP Rules)
  - `zia_casb_malware_rules` and   - `zia_casb_malware_rules_info` - SaaS Security API (Casb Malware Rules)
  - `file_type_categories_info` - This resource can be referenced within the `zia_dlp_web_rules` in the attribute `file_type_categories`
  - `zia_cloud_app_control_rule_actions_info` - Get available Cloud App Control rule actions by rule type
  - `zia_browser_control_policy` and `zia_browser_control_policy_info` - Browser Control Policy
  - `zia_casb_tombstone_template_info` - SaaS Security API (Casb Quarantine Tombstone Template)
  - `zia_casb_email_label_info` - SaaS Security API (Casb Quarantine Tombstone Template)
  - `zia_casb_tenant_info` - SaaS Security API (Casb Tenant)

* (`#105 <https://github.com/zscaler/ziacloud-ansible/pull/105>`_) - Added new attributes to ZIA:
  - `zia_firewall_ips_rule`: `is_eun_enabled`, and `eun_template_id`
  - `zia_firewall_dns_rule`: `is_web_eun_enabled` and `default_dns_rule_name_used`
  - `zia_location_management`: `sub_loc_scope_enabled`, `sub_loc_scope`, `sub_loc_scope_values`, `sub_loc_acc_ids`
  - `zia_dlp_web_rules`: `eun_template_id`

Bug Fixes:
---------------

* (`#105 <https://github.com/zscaler/ziacloud-ansible/pull/105>`_) - Improved `zia_client` to support authentication via both OneAPI and legacy methods.
* (`#105 <https://github.com/zscaler/ziacloud-ansible/pull/105>`_) - Fixed URL Categories update method

v2.0.7 (July 25, 2025)
-------------------------

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes:
---------------

* (`#88 <https://github.com/zscaler/ziacloud-ansible/pull/88>`_) - Fixed requirements.txt formatting issues.


v2.0.6 (July 21, 2025)
-------------------------

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes:
---------------

* (`#85 <https://github.com/zscaler/ziacloud-ansible/pull/85>`_) - Fixed `zia_atp_settings` argument count issue.

v2.0.5 (June 23, 2025)
-------------------------

Notes
-----

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes:
---------------

* (`#81 <https://github.com/zscaler/ziacloud-ansible/pull/81>`_) - Fixed `zia_url_categories` mandatory attributes

v2.0.4 (June 5, 2025)
-------------------------

Notes
-----

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes:
---------------

* (`#79 <https://github.com/zscaler/ziacloud-ansible/pull/79>`_) - Fixed pagination for the resource `zia_cloud_applications_info`

v2.0.3 (May, 29 2025)
-------------------------

Notes
-----

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes:
---------------

* (`#76 <https://github.com/zscaler/ziacloud-ansible/pull/76>`_) - Upgraded to (`Zscaler SDK Python v1.4.2 <https://github.com/zscaler/zscaler-sdk-python/releases/tag/v1.4.2>`_)

v2.0.2 (May, 26 2025)
-------------------------

Notes
-----

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes:
---------------

* (`#75 <https://github.com/zscaler/ziacloud-ansible/pull/75>`_) - Added new `source_ip_groups` attribute to `zia_url_filtering_rules`
* (`#75 <https://github.com/zscaler/ziacloud-ansible/pull/75>`_) - Added new `nw_applications` attribute to `zia_cloud_firewall_rule` and `zia_forwarding_control_rule`.
* (`#75 <https://github.com/zscaler/ziacloud-ansible/pull/75>`_) - Fixed drift with the attribute `ip_addresses` within the resource `zia_cloud_firewall_ip_source_groups`

## v2.0.1 (May, 12 2025)

Notes
------

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
----------

* (`#72 <https://github.com/zscaler/ziacloud-ansible/issues/72>`_) - Fixed `all_collect_items` pagination argument count


2.0.0 (May, 6 2025) - BREAKING CHANGES
------------------------------------------

Notes
------

- Python Versions: **v3.9, v3.10, v3.11**

Enhancements - Zscaler OneAPI Support - BREAKING CHANGES
---------------------------------------------------------

* (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_): The ZIA Ansible Collection now offers support for (`OneAPI <https://help.zscaler.com/oneapi/understanding-oneapi>`_) Oauth2 authentication through (`Zidentity <https://help.zscaler.com/zidentity/what-zidentity>`_)

**NOTE** As of version v2.0.0, this collection offers backwards compatibility to the Zscaler legacy API framework. This is the recommended authentication method for organizations whose tenants are still not migrated to (`Zidentity <https://help.zscaler.com/zidentity/what-zidentity>`_)

⚠️ **WARNING**: Please refer to the (`Authentication Page <https://ziacloud-ansible.readthedocs.io/en/latest/authentication.html>`_) for details on authentication requirements prior to upgrading your collection configuration.

⚠️ **WARNING**: Attention Government customers. OneAPI and Zidentity is not currently supported for the following clouds: `zscalergov` and `zscalerten`. Refer to the Legacy API Framework section for more information on how authenticate to these environments using the legacy method.

ENV VARS: ZIA Sandbox Submission - BREAKING CHANGES
----------------------------------------------------

* (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_): Authentication to Zscaler Sandbox service now use the following attributes.

- `sandboxToken` - Can also be sourced from the `ZSCALER_SANDBOX_TOKEN` environment variable.
- `sandboxCloud` - Can also be sourced from the `ZSCALER_SANDBOX_CLOUD` environment variable.

The use of the previous envioronment variables combination `ZIA_SANDBOX_TOKEN` and `ZIA_CLOUD` is now deprecated.

* (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_): The following resources have been renamed:

- `zia_cloud_firewall_filtering_rule.py` - Renamed to `zia_cloud_firewall_rule`
- `zia_cloud_firewall_filtering_rule_info.py.py` - Renamed to `zia_cloud_firewall_rule_info`
- `zia_cloud_firewall_filtering_rule_info.py.py` - Renamed to `zia_cloud_firewall_rule_info`

NEW - RESOURCES
----------------

* (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_): The following new resources and data sources have been introduced:

- Added resource `zia_advanced_settings` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Manages advanced threat configuration settings
- Added info resource `zia_advanced_settings_info` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Retrieves advanced threat configuration settings.
  (`Configuring Advanced Settings <https://help.zscaler.com/zia/configuring-advanced-settings>`_)

- Added resource `zia_atp_malicious_urls` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Manages malicious URLs added to the denylist in ATP policy
- Added info resource `zia_atp_malicious_urls_info` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Retrieves malicious URLs added to the denylist in ATP policy

- Added resource `zia_atp_settings` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Updates the advanced threat configuration settings
- Added info resource `zia_atp_settings_info` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Retrieves the advanced threat configuration settings

- Added resource `zia_atp_security_exceptions` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Manages Security Exceptions (URL Bypass List) for the ATP policy
- Added info resource `zia_atp_security_exceptions_info` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Retrieves information about the security exceptions configured for the ATP policy

- Added resource `zia_atp_malware_inspection` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Updates the traffic inspection configurations of Malware Protection policy
- Added info resource `zia_atp_malware_inspection_info` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Retrieves the traffic inspection configurations of Malware Protection policy.
  (`Malware Protection <https://help.zscaler.com/zia/policies/malware-protection>`_)

- Added resource `zia_atp_malware_protocols` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_): Updates the protocol inspection configurations of Malware Protection policy
- Added info resource `zia_atp_malware_protocols_info` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Retrieves Advanced Threat Protection Malware Protocols configuration. (`Malware Protection <https://help.zscaler.com/zia/policies/malware-protection>`_)

- Added resource `zia_atp_malware_settings` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Manages Advanced Threat Protection Malware Settings.
- Added inforesource `zia_atp_malware_settings_info` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Retrieves Advanced Threat Protection Malware Settings. (`Malware Protection <https://help.zscaler.com/zia/policies/malware-protection>`_)

- Added resource `zia_atp_malware_policy` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Manages Advanced Threat Protection Malware Policy. (`Malware Protection <https://help.zscaler.com/zia/policies/malware-protection>`_)
- Added info resource `zia_atp_malware_policy_info` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Retrieves Advanced Threat Protection Malware Policy. (`Malware Protection <https://help.zscaler.com/zia/policies/malware-protection>`_)

- Added resource `zia_mobile_advanced_threat_settings` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Manages Mobile Malware Protection Policy. (`Mobile Malware Protection <https://help.zscaler.com/zia/understanding-mobile-malware-protection>`_)
- Added info resource `zia_mobile_advanced_threat_settings_info` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Retrieves Mobile Malware Protection Policy (`Mobile Malware Protection <https://help.zscaler.com/zia/understanding-mobile-malware-protection>`_)

- Added resource `zia_end_user_notification` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Manages browser-based end user notification (EUN) configuration details.
- Added resource `zia_end_user_notification_info` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Manages browser-based end user notification (EUN) configuration details. (`Understanding Browser-Based End User Notifications <https://help.zscaler.com/zia/understanding-browser-based-end-user-notifications>`_)

- Added resource `zia_ftp_control_policy` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Updates the FTP Control settings.
- Added resource `zia_ftp_control_policy_info` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Retrieves the FTP Control status and the list of URL categories for which FTP is allowed. (`About FTP Control Policy <https://help.zscaler.com/zia/about-ftp-control>`_)

- Added resource `zia_sandbox_rules` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Manage Sandbox Rules
- Added info resource `zia_sandbox_rules_info` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Retrieve Sandbox Rules information

- Added resource `zia_cloud_firewall_dns_rule` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Manage Cloud Firewall DNS Rules
- Added info resource `zia_cloud_firewall_dns_rule_info` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Manage Cloud Firewall DNS Rules

- Added info resource `zia_cloud_firewall_ips_rules` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Retrieve Cloud Firewall IPS Rules
- Added info resource `zia_cloud_firewall_ips_rules_info` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Retrieve Cloud Firewall IPS Rules

- Added resource `zia_file_type_control_rules` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Manage File Type Control Rules
- Added info resource `zia_file_type_control_rules_info` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Retrieve File Type Control Rules

- Added resource `zia_ssl_inspection_rules` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Manages SSL Inspection Rules.
- Added info resource `zia_ssl_inspection_rules_info` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Retrives SSL Inspection Rules.

- Added resource `zia_nat_control_policy` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Manages NAT Control Policy.
- Added info resource `zia_nat_control_policy_info` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Retrives NAT Control Policy.

- Added and resource `zia_url_filtering_and_cloud_app_settings` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Manages the URL and Cloud App Control advanced policy settings.
- Added info resource `zia_url_filtering_and_cloud_app_settings_info` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Retrives the URL and Cloud App Control advanced policy settings. (`Configuring Advanced Policy Settings <https://help.zscaler.com/zia/configuring-advanced-policy-settings>`_)

- Added info resource `zia_cloud_applications_info` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Retrieves Predefined and User Defined Cloud Applications associated with the DLP rules, Cloud App Control rules, Advanced Settings, Bandwidth Classes, File Type Control rules, and SSL Inspection rules.

- Added resource `zia_dns_gateway` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Manages DNS Gateway object.
- Added info resource `zia_dns_gateway_info` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Retrives DNS Gateway object.

- Added resource `zia_third_party_proxy_service` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Manages third party proxy objects.
- Added info resource `zia_third_party_proxy_service_info` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Retrives third party proxy objects.

- Added resource `zia_nss_servers` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Manages NSS Server objects.
- Added info resource `zia_nss_servers_info` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Retrives NSS Server objects.

- Added resource `zia_cloud_application_instances` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Manages Cloud Application Instances.
- Added info resource `zia_cloud_application_instances_info` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Retrives Cloud Application Instances object.

- Added resource `zia_risk_profiles` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Manages Risk Profiles objects.
- Added info resource `zia_risk_profiles_info` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Retrives Risk Profiles configuration.

- Added resource `zia_remote_assistance` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Manages Remote Assistance configuration.
- Added info resource `zia_remote_assistance_info` - (`#68 <https://github.com/zscaler/ziacloud-ansible/pull/68>`_) - Retrives Remote Assistance configuration.

1.3.5 (March, 20 2025)
-----------------------

Notes
------

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
----------

* (`#62 <https://github.com/zscaler/ziacloud-ansible/pull/62>`_) Added `docs/html` within the `galaxy.yml` file under the `build_ignore` key

1.3.4 (March, 19 2025)
---------------------------

Notes
------

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
----------

* (`#60 <https://github.com/zscaler/ziacloud-ansible/pull/60>`_) Removed `ansible.cfg` from Ansible Automation Hub and Galaxy GitHub Actions workflow
* (`#60 <https://github.com/zscaler/ziacloud-ansible/pull/60>`_)  Fixed Location management drift issues


1.3.3 (March, 19 2025)
---------------------------

Notes
------

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
----------

* (`#56 <https://github.com/zscaler/ziacloud-ansible/pull/56>`_) Removed `ansible.cfg` from Ansible Automation Hub and Galaxy GitHub Actions workflow


1.3.1 (September, 12 2024)
--------------------------

Notes
------

- Python Versions: **v3.9, v3.10, v3.11**

New Feature
-------------

- (`#47 <https://github.com/zscaler/ziacloud-ansible/issues/47>`_) Fixed DLP Engine tests.


1.3.0 (September, 6 2024)
-------------------------

Notes
------

- Python Versions: **v3.9, v3.10, v3.11**

New Feature
-------------

- (`#46 <https://github.com/zscaler/ziacloud-ansible/issues/46>`_) Added new resource `zia_cloud_app_control_rule` and `zia_cloud_app_control_rule_info` for Cloud Application Control rule management.


1.2.0 (July, 22 2024)
----------------------

Notes
------

- Python Versions: **v3.9, v3.10, v3.11**

BREAKING CHANGES
-----------------------

- (`#270 <https://github.com/zscaler/ziacloud-ansible/issues/270>`_) All resources previously named with `_facts` have been moved to `_info` to comply with Red Hat Ansible best practices as described in the following (`Ansible Developer Documentation <https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_general.html#creating-an-info-or-a-facts-module>`_)

NEW FEATURES
------------------
- (`#270 <https://github.com/zscaler/ziacloud-ansible/issues/270>`_) All resources now support `check_mode` for simulation purposes and for validating configuration management playbooks.

1.1.0 (June, 25 2024)
----------------------

Notes
------

- Python Versions: **v3.9, v3.10, v3.11**

Enhancements
-------------

- Added Forwarding Control Rule Resource (`#37 <https://github.com/zscaler/ziacloud-ansible/issues/37>`_)

1.0.17 (May, 04 2024)
----------------------

Notes
------

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
----------

- Updated requirements.txt and documentation (`#34 <https://github.com/zscaler/ziacloud-ansible/issues/34>`_)

1.0.16 (May, 04 2024)
----------------------

Notes
------

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
----------

- Fixed IP Destination and IP Source Group Drift (`#33 <https://github.com/zscaler/ziacloud-ansible/issues/33>`_)

1.0.15 (May, 04 2024)
----------------------

Notes
------

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
----------

- Fixed zia authentication method schema (`#31 <https://github.com/zscaler/ziacloud-ansible/issues/31>`_)

1.0.14 (April, 24 2024)
------------------------

Notes
------

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
----------

- Added collection version to user-agent header (`#30 <https://github.com/zscaler/ziacloud-ansible/issues/30>`_)

1.0.13 (April, 23 2024)
------------------------

Notes
------

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
----------

- Fixed release process for automation hub (`#27 <https://github.com/zscaler/ziacloud-ansible/issues/27>`_)

1.0.12 (April, 23 2024)
------------------------

Notes
------

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
----------

- Removed Beta comment from README and fixed galaxy link on index (`#e47696c <https://github.com/zscaler/ziacloud-ansible/commit/e47696cc8c4ea26e492547a76687dce8dcc71b2a>`_)

1.0.11 (April, 23 2024)
------------------------

Notes
------

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
----------

- Removed Beta from README page (`#658b30b <https://github.com/zscaler/ziacloud-ansible/commit/658b30baa1d1f6204de53c91aeb99f394788f79d>`_)


1.0.10 (April, 23 2024)
------------------------

Notes
------

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
----------

- Fixed linter workflow and documentation (`#45f0f98 <https://github.com/zscaler/ziacloud-ansible/commit/45f0f98fe6e6eebfb83dab7775c847d845ede585>`_)

1.0.9 (April, 23 2024)
----------------------

Notes
------

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
----------

- Fixed makefile doc generation section (`#26024a5 <https://github.com/zscaler/ziacloud-ansible/commit/26024a5073e9b2338b1f656d4ceef54f0f2e131a>`_)

1.0.8 (April, 23 2024)
----------------------

Notes
------

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
----------

- Fixed makefile doc generation section (`#165756c <https://github.com/zscaler/ziacloud-ansible/commit/165756cdab765b556c0a82e4fb01f0612b96bc41>`_)

1.0.7 (April, 23 2024)
----------------------

Notes
------

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
----------

- Removed poetry from release.yml doc generation (`#e0feb95 <https://github.com/zscaler/ziacloud-ansible/commit/e0feb95affb02877cb2c8471dae9137f56d20ccf>`_)

1.0.6 (April, 23 2024)
----------------------

Notes
------

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
----------

- Fixed index.rst document (`#dfef5dc <https://github.com/zscaler/ziacloud-ansible/commit/dfef5dc53b63c3aa7f04bfa9809fdbcc3c06472d>`_)

1.0.5 (April, 23 2024)
----------------------

Notes
------

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
----------

- Fixed index.rst document (`#ddf8eee <https://github.com/zscaler/ziacloud-ansible/commit/ddf8eee851c2e24af6383d39e6535d8e714e51c1>`_)


1.0.4 (April, 23 2024)
----------------------

Notes
------

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
----------

- Temporarily disabled Automation Hub Workflow (`#77ccd0d <https://github.com/zscaler/ziacloud-ansible/commit/77ccd0d306de88422f0718bdfa88c888c41e3042>`_)


1.0.3 (April, 23 2024)
----------------------

Notes
------

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
----------

- Temporarily disabled Automation Hub Workflow (`#e1a4b24 <https://github.com/zscaler/ziacloud-ansible/commit/e1a4b24bb0a0d669073ce79cda7d197ea73c69f7>`_)


1.0.2 (April, 23 2024)
----------------------

Notes
------

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
----------

- Temporarily disabled Automation Hub Workflow (`#78b77bd <https://github.com/zscaler/ziacloud-ansible/commit/78b77bdb1c576306d2c130784a6956e28d8224d6>`_)

1.0.1 (April, 23 2024)
----------------------

Notes
------

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
----------

- Temporarily disabled Automation Hub Workflow (`#66a363f <https://github.com/zscaler/ziacloud-ansible/commit/66a363fc3541ab8998f8bd2d0ab5acd2934f0665>`_)

1.0.0 (April, 22 2024)
----------------------

Notes
------

- Python Versions: **v3.9, v3.10, v3.11**

* Initial release of Zscaler Internet Access Automation collection, referred to as `ziacloud`
  which is part of the Red Hat® Ansible Certified Content.

What's New
----------


Availability
------------

* `Galaxy`_
* `GitHub`_

.. _GitHub:
   https://github.com/zscaler/ziacloud-ansible

.. _Galaxy:
   https://galaxy.ansible.com/ui/repo/published/zscaler/ziacloud/

.. _Automation Hub:
   https://www.ansible.com/products/automation-hub
