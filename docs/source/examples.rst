========
Examples
========

What is Zscaler Internet Access
===============================

The Zscaler Internet Access (ZIA) service enables organizations to provide access to internal applications and services while ensuring the security of their networks.
ZIA is an easier to deploy, more cost-effective, and more secure alternative to VPNs. Unlike VPNs, which require users to connect to your network to access your enterprise applications,
ZIA allows you to give users policy-based secure access only to the internal apps they need to get their work done. With ZIA, application access does not require network access.

Activation Status
-----------------

The following module allows for interaction with the ZIA Activation API endpoints and activates the saved configuration changes

.. code-block:: yaml

  - name: Activate ZIA Configuration
    zscaler.ziacloud.zia_activation_status:
      status: 'ACTIVE'

Cloud Firewall Filtering Rule
-----------------------------

The following module allows for interaction with the ZIA Cloud Firewall API endpoints and adds a new Cloud Firewall Filtering policy rule.

.. code-block:: yaml

  - name: Create/Update/Delete Cloud Firewall Filtering Rule
    zscaler.ziacloud.zia_cloud_firewall_filtering_rule:
      provider: '{{ zia_cloud }}'
      name: 'sampleCloudFIrewallRule'
      description: 'TT#1965232865'
      action: 'ALLOW'
      enabled: true
      order: 1
      enable_full_logging: true
      exclude_src_countries: true
      source_countries:
        - 'BR'
        - 'CA'
        - 'US'
      dest_countries:
        - 'BR'
        - 'CA'
        - 'US'
      device_trust_levels:
        - 'UNKNOWN_DEVICETRUSTLEVEL'
        - 'LOW_TRUST'
        - 'MEDIUM_TRUST'
        - 'HIGH_TRUST'
      device_groups:
        - 44772856
      locations:
        - 61188118
      groups:
        - 76662385
      users:
        - 45513075
      departments:
        - 45513014

Cloud Firewall IP Destination Group
-----------------------------------

The following module allows for interaction with the ZIA Cloud Firewall IP Destination Group.
This module creates an IP Destination Group resource, which can then be associated with a Cloud Firewall Filtering Rule.

.. code-block:: yaml

  - name: Create/Update/Delete ip destination group - DSTN_FQDN.
    zscaler.ziacloud.zia_cloud_firewall_ip_destination_groups:
      name: 'sample_DSTN_FQDN'
      description: 'sample_DSTN_FQDN'
      type: 'DSTN_FQDN"
      addresses: [ 'test1.acme.com', 'test2.acme.com', 'test3.acme.com' ]

  - name: Create/Update/Delete ip destination group - DSTN_IP by Country.
    zscaler.ziacloud.zia_cloud_firewall_ip_destination_groups:
      name: 'sample_DSTN_IP_Country'
      description: 'sample_DSTN_IP_Country'
      type: 'DSTN_IP'
      addresses: ['1.2.3.4', '1.2.3.5', '1.2.3.6' ]
      countries: [ 'CA' ]

  - name: Create/Update/Delete ip destination group - DSTN_IP.
    zscaler.ziacloud.zia_cloud_firewall_ip_destination_groups:
      name: 'sample_DSTN_IP'
      description: 'sample_DSTN_IP'
      type: 'DSTN_IP'
      addresses: [ '3.217.228.0-3.217.231.255',
          '3.235.112.0-3.235.119.255',
          '52.23.61.0-52.23.62.25',
          '35.80.88.0-35.80.95.255' ]


Cloud Firewall IP Source Group
------------------------------

The following module allows for interaction with the ZIA Cloud Firewall IP Source Group.
This module creates an IP Source Group resource, which can then be associated with a Cloud Firewall Filtering Rule.

.. code-block:: yaml

  - name: Create/Update/Delete ip source group.
    zscaler.ziacloud.zia_cloud_firewall_ip_source_groups:
      name: 'sample_IPSourceGroup'
      description: 'sample_IPSourceGroup'
      ip_addresses:
          - '192.168.1.1'
          - '192.168.1.2'
          - '192.168.1.3'

Cloud Firewall Network Services Group
-------------------------------------

The following module allows for interaction with the ZIA Cloud Firewall Network Services Group.
This module creates a Network Services Group resource, which can then be associated with a Cloud Firewall Filtering Rule.

.. code-block:: yaml

  - name: Create/Update/Delete Network Services Group.
    zscaler.ziacloud.zia_cloud_firewall_network_services_groups:
      name: 'sample_NetworkServicesGroup'
      description: 'sample_NetworkServicesGroup'
      services:
          - name: [ 'UDP_ANY', 'TCP_ANY' ]

Cloud Firewall Network Services
-------------------------------

The following module allows for interaction with the ZIA Cloud Firewall Network Services.
This module creates a Network Service resource, which can then be associated with a Cloud Firewall Filtering Rule or a Network Services Group.

.. code-block:: yaml

  - name: Create/Update/Delete Network Services.
    zscaler.ziacloud.zia_cloud_firewall_network_services:
      name: 'sample_NetworkServices'
      description: 'sample_NetworkServices'
      src_tcp_ports:
          - start: 5002
            end: 5005
      dest_tcp_ports:
          - start: 5003
            end: 5005
      type: "CUSTOM"

Cloud Firewall Network Application Group
----------------------------------------

The following module allows for interaction with the ZIA Cloud Firewall Network Application Group.
This module creates a Network Application Group resource, which can then be associated with a Cloud Firewall Filtering Rule.

.. code-block:: yaml

  - name: Create/Update/Delete network application group.
    zscaler.ziacloud.zia_cloud_firewall_network_application_group:
      name: "sample_NetworkApplicationGroup"
      network_applications:
          - 'YAMMER'
          - 'OFFICE365'
          - 'SKYPE_FOR_BUSINESS'
          - 'OUTLOOK'
          - 'SHAREPOINT'
          - 'SHAREPOINT_ADMIN'
          - 'SHAREPOINT_BLOG'
          - 'SHAREPOINT_CALENDAR'
          - 'SHAREPOINT_DOCUMENT'
          - 'SHAREPOINT_ONLINE'
          - 'ONEDRIVE'

DLP Web Rule
------------

The following module allows for interaction with the ZIA Data Loss Prevention (DLP) Web Rule API and adds a new inline DLP Web Rule.

.. code-block:: yaml

  - name: Create/Update/Delete DLP Web Rules
    zscaler.ziacloud.zia_dlp_web_rules:
      provider: '{{ zia_cloud }}'
      name: 'sample_DLPWebRule'
      description: 'sample_DLPWebRule'
      action: 'ALLOW'
      enabled: true
      without_content_inspection: false
      zscaler_incident_receiver: false
      order: 1
      rank: 7
      user_risk_score_levels:
        - 'CRITICAL'
        - 'HIGH'
        - 'LOW'
        - 'MEDIUM'
      protocols:
        - 'FTP_RULE'
        - 'HTTPS_RULE'
        - 'HTTP_RULE'
      min_size: 0
      cloud_applications:
        - 'WINDOWS_LIVE_HOTMAIL'
      file_types:
        - 'ASM'
        - 'MATLAB_FILES'
        - 'SAS'
        - 'SCALA'
      locations:
        - 61188118
      groups:
        - 76662385
      users:
        - 45513075
      departments:
        - 45513014

DLP Dictionary
--------------

The following module allows for interaction with the ZIA DLP Dictionary API Endpoint.
This module creates a DLP Dictionary resource, which can then be associated with a custom DLP Engine.

.. code-block:: yaml

  - name: Create/Update/Delete DLP Dictionary.
    zscaler.ziacloud.zia_dlp_dictionaries:
      provider: '{{ zia_cloud }}'
      name: 'sample_DLPDictionary'
      description: 'sampleDLPDictionary'
      custom_phrase_match_type: 'MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY'
      dictionary_type: 'PATTERNS_AND_PHRASES'
      phrases:
        - action: 'PHRASE_COUNT_TYPE_UNIQUE'
          phrase: 'YourPhrase'
      patterns:
        - action: 'PATTERN_COUNT_TYPE_ALL'
          pattern: 'YourPattern'

DLP Engine
----------

The following module allows for interaction with the ZIA DLP Engine API Endpoint.
This module creates a custom DLP Engine resource, which can then be associated with Web DLP Rule.
Before using this module contact Zscaler Support and request the following API methods POST, PUT, and DELETE to be enabled for your organization tenant.

.. code-block:: yaml

  - name: Create/Update/Delete custom dlp engine.
    zscaler.ziacloud.zia_dlp_engine:
      name: 'sample_CustomDLPEngine'
      description: 'sampleCustomDLPEngine'
      engine_expression: "((D63.S > 1))"
      custom_dlp_engine: true

DLP Notification Template
-------------------------

The following module allows for interaction with the ZIA DLP Notification Template API Endpoint.
This module creates a DLP Notification Tempalte resource, which can then be associated with Web DLP Rule.

.. code-block:: yaml

  - name: Create a new DLP Notification Template
    zia_dlp_notification_template:
      name: 'sample_DLPNotificationTemplate'
      subject: 'DLP Violation Alert'
      attach_content: true
      tls_enabled: true
      plain_text_message: |
        "The attached content triggered a Web DLP rule for your organization..."
      html_message: |
        "<html><body>The attached content triggered a Web DLP rule...</body></html>"

Forwarding Control Policy Rule
------------------------------

The following module allows for interaction with the ZIA Forwarding Control Policy API endpoint.
Forwarding control is used to forward selective Zscaler traffic to specific destinations based on your needs.
For example, if you want to forward specific web traffic to a third-party proxy service or if you want to forward
source IP anchored application traffic to a specific Zscaler Private Access (ZPA) App Connector or internal application
traffic through ZIA threat and data protection engines, use forwarding control by configuring appropriate rules.

.. code-block:: yaml

  - name: Create/Update/Delete Forwarding Control ZPA Forward Method
      zscaler.ziacloud.zia_forwarding_control_policy:
        provider: '{{ zia_cloud }}'
        name: 'sample_ForwardingControlPolicy'
        description: 'TT#1965232865'
        type: 'FORWARDING'
        forward_method: 'DIRECT'
        enabled: true
        order: 1
        zpa_gateway
          - id: 2590247
            name: 'ZPA_GW01'

IP Source Anchoring ZPA Gateway
-------------------------------

The following module allows for interaction with the ZIA/ZPA Gateway API endpoint.
This module creates a ZPA Gateway resource, which can then be associated with a Forwarding Control Policy.
Source IP Anchoring uses ZIA forwarding policies and Zscaler Private Access (ZPA) App Connectors
to selectively forward the application traffic to the appropriate destination servers


.. code-block:: yaml

  - name: Create/Update/Delete a ZPA Gateway with application segments
    zscaler.ziacloud.zia_ip_source_anchoring_zpa_gateway:
      provider: '{{ zia_cloud }}'
      name: 'ZPA_GW01'
      description: 'ZPA Gateway for internal apps'
      type: "ZPA"
      zpa_server_group:
        external_id: 216196257331370454
        name: 'sample_ZPAServerGroup_IP_Anchoring'
      zpa_app_segments:
        - external_id: 216196257331370455
          name: 'sample_ZPAAppSegment1'
        - external_id: 216196257331370465
          name: 'sample_ZPAAppSegment2'

Location Management with UFQDN VPN Credential
---------------------------------------------

The following module allows for interaction with the ZIA Location Management API Endpoint.
This module creates a Location management resource, which can then be associated with a Cloud Firewall, Web DLP and URL Filtering Rule.

.. code-block:: yaml

  - name: Create/Update/Delete VPN Credential
    zscaler.ziacloud.zia_traffic_forwarding_vpn_credentials:
      type: "UFQDN"
      fqdn: "usa_sjc37@acme.com"
      comments: "sample_UFQDN_VPNCredential"
      pre_shared_key: "newPassword123!"
    register: vpn_credential_ufqdn

  - name: Create/Update/Delete Location Management
    zscaler.ziacloud.zia_location_management:
      name: "USA_SJC_37"
      description: "sample_LocationManagement"
      country: "UNITED_STATES"
      tz: "UNITED_STATES_AMERICA_LOS_ANGELES"
      auth_required: true
      idle_time_in_minutes: 720
      display_time_unit: "HOUR"
      surrogate_ip: true
      xff_forward_enabled: true
      ofw_enabled: true
      ips_control: true
      ip_addresses: "1.1.1.1"
      vpn_credentials:
          - id: "{{ vpn_credential_ufqdn.data.id }}"
            type: "{{ vpn_credential_ufqdn.data.type }}"

Location Management with IP VPN Credential
---------------------------------------------

The following module allows for interaction with the ZIA Location Management API Endpoint.
This module creates a Location management resource, which can then be associated with a Cloud Firewall, Web DLP and URL Filtering Rule.

.. code-block:: yaml

  - name: Create/Update/Delete VPN Credentials Type IP.
    zscaler.ziacloud.zia_location_management:
      type: "IP"
      ip_address: "1.1.1.1"
      comments: "sample_IP_VPNCredential"
      pre_shared_key: "newPassword123!"
    register: vpn_credential_ip

  - name: Create/Update/Delete Location Management
    zscaler.ziacloud.zia_location_management:
      name: "sample_LocationManagement"
      description: "sample_LocationManagement"
      country: "UNITED_STATES"
      tz: "UNITED_STATES_AMERICA_LOS_ANGELES"
      auth_required: true
      idle_time_in_minutes: 720
      display_time_unit: "HOUR"
      surrogate_ip: true
      xff_forward_enabled: true
      ofw_enabled: true
      ips_control: true
      ip_addresses: "1.1.1.1"
      vpn_credentials:
          - id: "{{ vpn_credential_ip.data.id }}"
            type: "{{ vpn_credential_ip.data.type }}"
            ip_address: "{{ vpn_credential_ip.data.ip_address }}"

Rule Label
----------

The following module allows for interaction with the ZIA Rule Label API Endpoint.
This module creates a Rule Label resource, which can then be associated with:

1. Cloud Firewall Rule
2. URL Filtering Rule
3. Web DLP Rule

.. code-block:: yaml

  - name: Create/Update/Delete Rule Label.
    zscaler.ziacloud.zia_rule_labels:
      name: "sample_RuleLabel"
      description: "sample_RuleLabel"

Sandbox Advanced Settings
-------------------------

The following module allows for interaction with the ZIA Sandbox Advanced Settings API Endpoint.
This module updates the custom list of MD5 file hashes that are blocked by the Sandbox.
Notice, that the use of this module overwrites a previously generated blocklist.
If you need to completely erase the blocklist you must submit an empty list.

 ~> **Note**: Only the file types that are supported by Sandbox analysis can be blocked using MD5 hashes.

.. code-block:: yaml

  - name: Add MD5 Hashes to Custom List
    zscaler.ziacloud.zia_sandbox_advanced_settings_facts:
      file_hashes_to_be_blocked:
        - "936593e1ba2e1fefc78389ed40ab9d9a"
        - "c0202cf6aeab8437c638533d14563d35"
        - "1ca31319721740ecb79f4b9ee74cd9b0"

  - name: Read MD5 Hashes from file
    set_fact:
      md5_hashes: "{{ lookup('file', 'md5_hashes.txt').splitlines() }}"

  - name: Empty MD5 Hashes List
    zscaler.ziacloud.zia_sandbox_advanced_settings:
      state: absent
      file_hashes_to_be_blocked: "{{ md5_hashes }}"

Security Policy Settings
-------------------------

The following module allows for interaction with the ZIA Security Policy Settings API Endpoint to add or remove URLs from the Denylist

 ~> **Note**: The Security Policy Settings allow up to 25000 URLs.

.. code-block:: yaml

  - name: ADD URLs from the Blacklist
    zscaler.ziacloud.zia_security_policy_settings:
      urls:
        - test1.acme.com
        - test2.acme.com
        - test3.acme.com
        - test4.acme.com
      url_type: "blacklist"

  - name: REMOVE URLs from the Blacklist
    zscaler.ziacloud.zia_security_policy_settings:
      urls:
        - test1.acme.com
        - test2.acme.com
        - test3.acme.com
        - test4.acme.com
      url_type: "whitelist"