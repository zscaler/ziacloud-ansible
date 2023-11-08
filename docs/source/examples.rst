========
Examples
========

What is Zscaler Internet Access
===============================

The Zscaler Internet Access (ZIA) service enables organizations to provide access to internal applications and services while ensuring the security of their networks.
ZIA is an easier to deploy, more cost-effective, and more secure alternative to VPNs. Unlike VPNs, which require users to connect to your network to access your enterprise applications,
ZIA allows you to give users policy-based secure access only to the internal apps they need to get their work done. With ZIA, application access does not require network access.

App Connector Group
===================

The following module allows for interaction with the ZIA App Connector Group API endpoints.
This module creates an app connector group, which in turn must be associated with a provisioning key resource.

.. code-block:: yaml

    - name: Create First App Connector Group
      zscaler.ziacloud.zpa_app_connector_groups:
        name: "Example1"
        description: "Example1"
        enabled: true
        city_country: "California, US"
        country_code: "US"
        latitude: "37.3382082"
        longitude: "-121.8863286"
        location: "San Jose, CA, USA"
        upgrade_day: "SUNDAY"
        upgrade_time_in_secs: "66600"
        override_version_profile: true
        version_profile_id: "0"
        dns_query_type: "IPV4"

Service Edge Group
==================

The following module allows for interaction with the ZIA Service Edge Group API endpoints.
This module creates an service edge group, which in turn must be associated with a provisioning key resource.

.. code-block:: yaml

   - name: Create/Update/Delete Service Edge Group
      zscaler.ziacloud.zpa_service_edge_groups:
        name: "Example"
        description: "Example1"
        enabled: true
        city_country: "California, US"
        country_code: "US"
        latitude: "37.3382082"
        longitude: "-121.8863286"
        location: "San Jose, CA, USA"
        upgrade_day: "SUNDAY"
        upgrade_time_in_secs: "66600"
        override_version_profile: true
        version_profile_id: "0"

Provisioning Key
================

The following module allows for interaction with the ZIA Provisioning Key API endpoints.
This module creates a provisioning key resource, which is a text string that is generated when a new App Connector
or Private Service Edge is added.

.. code-block:: yaml

    - name: Create/Update/Delete App Connector Group Provisioning Key
      zscaler.ziacloud.zpa_provisioning_key:
        name: "App Connector Group Provisioning Key"
        association_type: "CONNECTOR_GRP"
        max_usage: "10"
        enrollment_cert_id: 6573
        zcomponent_id: 216196257331291903

    - name: Create/Update/Delete Service Edge Connector Group Provisioning Key
      zscaler.ziacloud.zpa_provisioning_key:
        name: "Service Edge Connector Group Provisioning Key"
        association_type: "CONNECTOR_GRP"
        max_usage: "10"
        enrollment_cert_id: 6573
        zcomponent_id: 216196257331291903


Application Segment
===================

The following module allows for interaction with the ZPA Application Segments endpoints.
The module creates an application segment resource, which is a grouping of defined applications.

.. code-block:: yaml

    - name: Create First Application Segment
      zscaler.ziacloud.zpa_application_segment:
        name: Example Application
        description: Example Application Test
        enabled: true
        health_reporting: ON_ACCESS
        bypass_type: NEVER
        is_cname_enabled: true
        tcp_port_range:
          - from: "8080"
            to: "8085"
        domain_names:
          - server1.example.com
          - server2.example.com
        segment_group_id: "{{ segment_group_id }}"
        server_groups:
          - id: "{{ server_group_id }}"

Browser Access Application Segment
==================================

The following module allows for interaction with the ZPA Application Segments endpoints.
The module creates a Browser Access Application Segment resource, which allows you to leverage
a web browser for user authentication and application access over ZPA, without requiring users
to install the Zscaler Client Connector (formerly Zscaler App or Z App) on their devices.

.. code-block:: yaml

    - name: Browser Access Application Segment
      zscaler.ziacloud.zpa_browser_access:
        name: Example
        description: Example
        enabled: true
        health_reporting: ON_ACCESS
        bypass_type: NEVER
        is_cname_enabled: true
        tcp_port_range:
          - from: "80"
            to: "80"
        domain_names:
          - crm1.example.com
          - crm2.example.com
        segment_group_id: "{{ segment_group_id }}"
        server_groups:
          - id: "{{ server_group_id }}"
        clientless_apps:
            name: "sales.acme.com"
            application_protocol: "HTTP"
            application_port: "80"
            certificate_id: "{{ certificate_id }}"
            trust_untrusted_cert: true
            enabled: true
            domain: "sales.acme.com"

Server Group
============

The following module allows for interaction with the ZPA Server Groups endpoints.
The module creates a Server Group resource, which can be created to manually define servers,
or it can be created with the option of `dynamic_discovery` enabled so that ZPA discovers the appropriate servers,
for each application as users request them.

.. code-block:: yaml

    - name: Create/Update/Delete a Server Group (Dynamic Discovery ON)
      zscaler.ziacloud.zpa_server_group:
        name: "Example"
        description: "Example"
        enabled: false
        dynamic_discovery: true
        app_connector_groups:
          - id: "216196257331291924"

    - name: Create/Update/Delete a Server Group (Dynamic Discovery OFF)
      zscaler.ziacloud.zpa_server_group:
        name: "Example"
        description: "Example"
        enabled: false
        dynamic_discovery: false
        app_connector_groups:
          - id: "216196257331291924"
        servers:
          - id: "216196257331291921"

Segment Group
=============

The following module allows for interaction with the ZPA Segment Groups endpoints.

.. code-block:: yaml

    - name: Create/Update/Delete a Segment Groups
      zscaler.ziacloud.zpa_segment_group:
        config_space: "DEFAULT"
        name: Example Segment Group
        description: Example Segment Group
        enabled: true
        policy_migrated: true
        tcp_keep_alive_enabled: "1"

Policy Access Rule
==================

.. code-block:: yaml

    - name: Create/update/delete a Policy Rule
      zscaler.ziacloud.zpa_policy_access_rule:
        name: "Example Policy Access Rule"
        description: "Example Policy Access Rule"
        action: "ALLOW"
        rule_order: 1
        operator: "AND"
        conditions:
          - negated: false
            operator: "OR"
            operands:
              - name: "Example Policy Access Rule"
                object_type: "APP"
                lhs: "id"
                rhs: "216196257331291979"

Policy Access Timeout Rule
==========================

.. code-block:: yaml

    - name: Create/update/delete a Policy Timeout Rule
      zscaler.ziacloud.zpa_policy_access_timeout_rule:
        name: "Example Policy Timeout Rule"
        description: "Example Policy Timeout Rule"
        action: "RE_AUTH"
        rule_order: 1
        operator: "AND"
        conditions:
          - negated: false
            operator: "OR"
            operands:
              - name: "Application_Segment"
                object_type: "APP"
                lhs: "id"
                rhs: "216196257331291979"

Policy Access Forwarding Rule
=============================

.. code-block:: yaml

    - name: Create/update/delete a Policy Forwarding Rule
      zscaler.ziacloud.zpa_policy_access_forwarding_rule:
        name: "Example Policy Forwarding Rule"
        description: "Example Policy Forwarding Rule"
        action: "BYPASS"
        rule_order: 1
        operator: "AND"
        conditions:
          - negated: false
            operator: "OR"
            operands:
              - name: "Application_Segment"
                object_type: "APP"
                lhs: "id"
                rhs: "216196257331291979"