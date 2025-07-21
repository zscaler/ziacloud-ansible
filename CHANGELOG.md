# Zscaler Internet Access (ZIA) Ansible Collection Changelog

## v2.0.6 (July 21, 2025)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

[#85](https://github.com/zscaler/ziacloud-ansible/pull/85) - Fixed `zia_atp_settings` argument count issue.

## v2.0.5 (June 23, 2025)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

[#81](https://github.com/zscaler/ziacloud-ansible/pull/81) - Fixed `zia_url_categories` mandatory attributes

## v2.0.4 (June 5, 2025)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

[#79](https://github.com/zscaler/ziacloud-ansible/pull/79) - Fixed pagination for the resource `zia_cloud_applications_info`

## v2.0.3 (May, 29 2025)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

[#76](https://github.com/zscaler/ziacloud-ansible/pull/76) - Upgraded to [Zscaler SDK Python v1.4.2](https://github.com/zscaler/zscaler-sdk-python/releases/tag/v1.4.2)

## v2.0.2 (May, 26 2025)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

[#75](https://github.com/zscaler/ziacloud-ansible/pull/75) - Added new `source_ip_groups` attribute to `zia_url_filtering_rules`
[#75](https://github.com/zscaler/ziacloud-ansible/pull/75) - Added new `nw_applications` attribute to `zia_cloud_firewall_rule` and `zia_forwarding_control_rule`.
[#75](https://github.com/zscaler/ziacloud-ansible/pull/75) - Fixed drift with the attribute `ip_addresses` within the resource `zia_cloud_firewall_ip_source_groups`

## v2.0.1 (May, 12 2025)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

[#72](https://github.com/zscaler/ziacloud-ansible/pull/72) - Fixed `all_collect_items` pagination argument count

## 2.0.0 (May, 6 2025) - BREAKING CHANGES

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

#### Enhancements - Zscaler OneAPI Support - BREAKING CHANGES

[PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68): The ZIA Ansible Collection now offers support for [OneAPI](https://help.zscaler.com/oneapi/understanding-oneapi) Oauth2 authentication through [Zidentity](https://help.zscaler.com/zidentity/what-zidentity).

**NOTE** As of version v2.0.0, this collection offers backwards compatibility to the Zscaler legacy API framework. This is the recommended authentication method for organizations whose tenants are still not migrated to [Zidentity](https://help.zscaler.com/zidentity/what-zidentity).

⚠️ **WARNING**: Please refer to the [Authentication Page](https://ziacloud-ansible.readthedocs.io/en/latest/authentication.html) for details on authentication requirements prior to upgrading your collection configuration.

⚠️ **WARNING**: Attention Government customers. OneAPI and Zidentity is not currently supported for the following clouds: `zscalergov` and `zscalerten`. Refer to the [Legacy API Framework](https://github.com/zscaler/terraform-provider-zpa/blob/master/docs/index) section for more information on how authenticate to these environments using the legacy method.

### ENV VARS: ZIA Sandbox Submission - BREAKING CHANGES

[PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68): Authentication to Zscaler Sandbox service now use the following attributes.

- `sandboxToken` - Can also be sourced from the `ZSCALER_SANDBOX_TOKEN` environment variable.
- `sandboxCloud` - Can also be sourced from the `ZSCALER_SANDBOX_CLOUD` environment variable.

The use of the previous envioronment variables combination `ZIA_SANDBOX_TOKEN` and `ZIA_CLOUD` is now deprecated.

[PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68): The following resources have been renamed:

- `zia_cloud_firewall_filtering_rule.py` - Renamed to `zia_cloud_firewall_rule`
- `zia_cloud_firewall_filtering_rule_info.py.py` - Renamed to `zia_cloud_firewall_rule_info`
- `zia_cloud_firewall_filtering_rule_info.py.py` - Renamed to `zia_cloud_firewall_rule_info`

### NEW - RESOURCES

[PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68): The following new resources and data sources have been introduced:

- Added resource ``zia_advanced_settings`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Manages advanced threat configuration settings
- Added info resource ``zia_advanced_settings_info`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Retrieves advanced threat configuration settings
[Configuring Advanced Settings](https://help.zscaler.com/zia/configuring-advanced-settings)

- Added resource ``zia_atp_malicious_urls`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Manages malicious URLs added to the denylist in ATP policy
- Added info resource ``zia_atp_malicious_urls_info`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Retrieves malicious URLs added to the denylist in ATP policy

- Added resource ``zia_atp_settings`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Updates the advanced threat configuration settings
- Added info resource ``zia_atp_settings_info`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Retrieves the advanced threat configuration settings

- Added resource ``zia_atp_security_exceptions`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Manages Security Exceptions (URL Bypass List) for the ATP policy
- Added info resource ``zia_atp_security_exceptions_info`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Retrieves information about the security exceptions configured for the ATP policy

- Added resource ``zia_atp_malware_inspection`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Updates the traffic inspection configurations of Malware Protection policy
- Added info resource ``zia_atp_malware_inspection_info`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Retrieves the traffic inspection configurations of Malware Protection policy. [Malware Protection](https://help.zscaler.com/zia/policies/malware-protection)
[Malware Protection](https://help.zscaler.com/zia/policies/malware-protection)

- Added resource ``zia_atp_malware_protocols`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68)
- Added info resource ``zia_atp_malware_protocols_info`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Retrieves Advanced Threat Protection Malware Protocols configuration. [Malware Protection](https://help.zscaler.com/zia/policies/malware-protection)

- Added resource ``zia_atp_malware_settings`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Manages Advanced Threat Protection Malware Settings.
- Added inforesource ``zia_atp_malware_settings_info`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Retrieves Advanced Threat Protection Malware Settings. [Malware Protection](https://help.zscaler.com/zia/policies/malware-protection)

- Added resource ``zia_atp_malware_policy`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Manages Advanced Threat Protection Malware Policy. [Malware Protection](https://help.zscaler.com/zia/policies/malware-protection)
- Added info resource ``zia_atp_malware_policy_info`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Retrieves Advanced Threat Protection Malware Policy. [Malware Protection](https://help.zscaler.com/zia/policies/malware-protection)

- Added resource ``zia_mobile_advanced_threat_settings`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Manages Mobile Malware Protection Policy. [Malware Protection](https://help.zscaler.com/zia/policies/malware-protection)
- Added info resource ``zia_mobile_advanced_threat_settings_info`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Retrieves Mobile Malware Protection Policy [Mobile Malware Protection](https://help.zscaler.com/zia/understanding-mobile-malware-protection)

- Added resource ``zia_end_user_notification`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Manages browser-based end user notification (EUN) configuration details.
- Added resource ``zia_end_user_notification_info`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Manages browser-based end user notification (EUN) configuration details. [Understanding Browser-Based End User Notifications](https://help.zscaler.com/zia/understanding-browser-based-end-user-notifications)

- Added resource ``zia_ftp_control_policy`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Updates the FTP Control settings.
- Added resource ``zia_ftp_control_policy_info`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Retrieves the FTP Control status and the list of URL categories for which FTP is allowed. [About FTP Control Policy](https://help.zscaler.com/zia/about-ftp-control)

- Added resource ``zia_sandbox_rules`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Manage Sandbox Rules
- Added info resource ``zia_sandbox_rules_info`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Retrieve Sandbox Rules information

- Added resource ``zia_cloud_firewall_dns_rule`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Manage Cloud Firewall DNS Rules
- Added info resource ``zia_cloud_firewall_dns_rule_info``[PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Manage Cloud Firewall DNS Rules

- Added info resource ``zia_cloud_firewall_ips_rules`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Retrieve Cloud Firewall IPS Rules
- Added info resource ``zia_cloud_firewall_ips_rules_info`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Retrieve Cloud Firewall IPS Rules

- Added resource ``zia_file_type_control_rules`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Manage File Type Control Rules
- Added info resource ``zia_file_type_control_rules_info`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Retrieve File Type Control Rules

- Added resource ``zia_ssl_inspection_rules`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Manages SSL Inspection Rules.
- Added info resource ``zia_ssl_inspection_rules_info`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Retrives SSL Inspection Rules.

- Added resource ``zia_nat_control_policy`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Manages NAT Control Policy.
- Added info resource ``zia_nat_control_policy_info`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Retrives NAT Control Policy.

- Added and resource ``zia_url_filtering_and_cloud_app_settings`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Manages the URL and Cloud App Control advanced policy settings.
- Added info resource ``zia_url_filtering_and_cloud_app_settings_info`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Retrives the URL and Cloud App Control advanced policy settings. [Configuring Advanced Policy Settings](https://help.zscaler.com/zia/configuring-advanced-policy-settings)

- Added info resource ``zia_cloud_applications_info`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Retrieves Predefined and User Defined Cloud Applications associated with the DLP rules, Cloud App Control rules, Advanced Settings, Bandwidth Classes, File Type Control rules, and SSL Inspection rules.

- Added resource ``zia_dns_gateway`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Manages DNS Gateway object.
- Added info resource ``zia_dns_gateway_info`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Retrives DNS Gateway object.

- Added resource ``zia_third_party_proxy_service`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Manages third party proxy objects.
- Added info resource ``zia_third_party_proxy_service_info`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Retrives third party proxy objects.

- Added resource ``zia_nss_servers`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Manages NSS Server objects.
- Added info resource ``zia_nss_servers_info`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Retrives NSS Server objects.

- Added resource ``zia_cloud_application_instances`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Manages Cloud Application Instances.
- Added info resource ``zia_cloud_application_instances_info`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Retrives Cloud Application Instances object.

- Added resource ``zia_risk_profiles`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Manages Risk Profiles objects.
- Added info resource ``zia_risk_profiles_info`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Retrives Risk Profiles configuration.

- Added resource ``zia_remote_assistance`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Manages Remote Assistance configuration.
- Added info resource ``zia_remote_assistance_info`` [PR #68](https://github.com/zscaler/ziacloud-ansible/pull/68) :rocket: - Retrives Remote Assistance configuration.

## v1.3.5 (March, 20 2025)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### New Feature

- [PR #62](https://github.com/zscaler/ziacloud-ansible/pull/62) Added `docs/html` within the `galaxy.yml` file under the `build_ignore` key

## v1.3.4 (March, 19 2025)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### New Feature

- [PR #60](https://github.com/zscaler/ziacloud-ansible/pull/60) Removed `ansible.cfg` from Ansible Automation Hub and Galaxy GitHub Actions workflow
- [PR #60](https://github.com/zscaler/ziacloud-ansible/pull/60) Fixed Location management drift issues

## v1.3.3 (February, 5 2025)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### New Feature

- [PR #60](https://github.com/zscaler/ziacloud-ansible/pull/60) Removed `ansible.cfg` from Ansible Automation Hub and Galaxy GitHub Actions workflow

## v1.3.2 (September, 12 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### New Feature

- [PR #49](https://github.com/zscaler/ziacloud-ansible/pull/49) Upgraded to Zscaler-SDK-Python v0.9.6

## v1.3.1 (September, 12 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### New Feature

- [PR #47](https://github.com/zscaler/ziacloud-ansible/pull/47) Fixed DLP Engine tests.

## v1.3.0 (September, 6 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### New Feature

- [PR #46](https://github.com/zscaler/ziacloud-ansible/pull/46) Added new resource `zia_cloud_app_control_rule` for Cloud Application Control rule management.

## v1.3.0 (September, 6 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### New Feature

- [PR #46](https://github.com/zscaler/ziacloud-ansible/pull/46) Added new resource `zia_cloud_app_control_rule` for Cloud Application Control rule management.

## v1.2.0 (July, 22 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### BREAKING CHANGES

- [PR #40](https://github.com/zscaler/ziacloud-ansible/pull/40) All resources previously named with `_facts` have been moved to `_info` to comply with Red Hat Ansible best practices as described in the following [Ansible Developer Documentation](https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_general.html#creating-an-info-or-a-facts-module)

### New Feature

- [PR #40](https://github.com/zscaler/ziacloud-ansible/pull/40) All resources now support `check_mode` for simulation purposes and for validating configuration management playbooks

## v1.1.0 (June, 25 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Features

- Release v1.1.0 ([98727b7](https://github.com/zscaler/ziacloud-ansible/commit/98727b79f6fd0250e83996bf297db18fcf626cdd))
- **new:** Added Forwarding Control Rule Resource ([#37](https://github.com/zscaler/ziacloud-ansible/issues/37)) ([a0abe94](https://github.com/zscaler/ziacloud-ansible/commit/a0abe943d5cd4a5d76742f13c7e176df9929c4f8))

## v1.0.18 (May, 25 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Features

- Release v1.1.0 ([98727b7](https://github.com/zscaler/ziacloud-ansible/commit/98727b79f6fd0250e83996bf297db18fcf626cdd))
- **new:** Added Forwarding Control Rule Resource ([#37](https://github.com/zscaler/ziacloud-ansible/issues/37)) ([a0abe94](https://github.com/zscaler/ziacloud-ansible/commit/a0abe943d5cd4a5d76742f13c7e176df9929c4f8))

## v1.0.17 (May, 23 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Updated requirements.txt and documentation ([#34](https://github.com/zscaler/ziacloud-ansible/issues/34)) ([337f505](https://github.com/zscaler/ziacloud-ansible/commit/337f5055ed0e667c5143c031e50f38d2c40caff0))

## v1.0.16 (May, 04 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Fixed IP Destination and IP Source Group Drift ([#33](https://github.com/zscaler/ziacloud-ansible/issues/33)) ([2e9531b](https://github.com/zscaler/ziacloud-ansible/commit/2e9531b7a6584c4ab091e5f833e1f6c383ea5a81))

## v1.0.15 (May, 04 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Fixed zia authentication method schema ([#31](https://github.com/zscaler/ziacloud-ansible/issues/31)) ([271ce29](https://github.com/zscaler/ziacloud-ansible/commit/271ce29c308f6cfb101048f5197aff20fb0fdce1))

## v1.0.14 (April, 24 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Added collection version to user-agent header ([#30](https://github.com/zscaler/ziacloud-ansible/issues/30)) ([1fa5f3f](https://github.com/zscaler/ziacloud-ansible/commit/1fa5f3f9c44ecb05846a3263a4afe591a49bf2bb))

## v1.0.13 (April, 23 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Fixed release process for automation hub ([#27](https://github.com/zscaler/ziacloud-ansible/issues/27)) ([a067c69](https://github.com/zscaler/ziacloud-ansible/commit/a067c69e723bcd37c28437115cf734bc9c5e32ce))

## v1.0.12 (April, 23 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Removed Beta comment from README and fixed galaxy link on index ([e47696c](https://github.com/zscaler/ziacloud-ansible/commit/e47696cc8c4ea26e492547a76687dce8dcc71b2a))

## v1.0.11 (April, 23 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Removed Beta from README page ([658b30b](https://github.com/zscaler/ziacloud-ansible/commit/658b30baa1d1f6204de53c91aeb99f394788f79d))

## v1.0.10 (April, 23 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Fixed linter workflow and documentation ([45f0f98](https://github.com/zscaler/ziacloud-ansible/commit/45f0f98fe6e6eebfb83dab7775c847d845ede585))
- Fixed linter workflow and documentation ([093c9ad](https://github.com/zscaler/ziacloud-ansible/commit/093c9add9409b85d17c971346b61f8cd507604ae))

## v1.0.9 (April, 23 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Fixed makefile doc generation section ([26024a5](https://github.com/zscaler/ziacloud-ansible/commit/26024a5073e9b2338b1f656d4ceef54f0f2e131a))

## v1.0.8 (April, 23 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Fixed makefile doc generation section ([165756c](https://github.com/zscaler/ziacloud-ansible/commit/165756cdab765b556c0a82e4fb01f0612b96bc41))

## v1.0.7 (April, 23 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Removed poetry from release.yml doc generation ([e0feb95](https://github.com/zscaler/ziacloud-ansible/commit/e0feb95affb02877cb2c8471dae9137f56d20ccf))

## v1.0.6 (April, 23 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Fixed index.rst document ([dfef5dc](https://github.com/zscaler/ziacloud-ansible/commit/dfef5dc53b63c3aa7f04bfa9809fdbcc3c06472d))

## v1.0.5 (April, 23 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Fixed index.rst document ([ddf8eee](https://github.com/zscaler/ziacloud-ansible/commit/ddf8eee851c2e24af6383d39e6535d8e714e51c1))

## v1.0.4 (April, 23 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Temporarily disabled Automation Hub Workflow ([77ccd0d](https://github.com/zscaler/ziacloud-ansible/commit/77ccd0d306de88422f0718bdfa88c888c41e3042))

## v1.0.3 (April, 23 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Temporarily disabled Automation Hub Workflow ([e1a4b24](https://github.com/zscaler/ziacloud-ansible/commit/e1a4b24bb0a0d669073ce79cda7d197ea73c69f7))

## v1.0.2 (April, 23 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Temporarily disabled Automation Hub Workflow ([78b77bd](https://github.com/zscaler/ziacloud-ansible/commit/78b77bdb1c576306d2c130784a6956e28d8224d6))

## v1.0.1 (April, 23 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Temporarily disabled Automation Hub Workflow ([66a363f](https://github.com/zscaler/ziacloud-ansible/commit/66a363fc3541ab8998f8bd2d0ab5acd2934f0665))

## v1.0.0 (April, 22 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

## Initial Release v1.0.0

[Release Notes](https://github.com/zscaler/ziacloud-ansible/releases/tag/1.0.0)

- 🎉Initial Release🎉
