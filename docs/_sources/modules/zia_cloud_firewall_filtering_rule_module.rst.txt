
.. Document meta

:orphan:

.. |antsibull-internal-nbsp| unicode:: 0xA0
    :trim:

.. meta::
  :antsibull-docs: 2.7.0

.. Anchors

.. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module:

.. Anchors: short name for ansible.builtin

.. Title

zscaler.ziacloud.zia_cloud_firewall_filtering_rule module -- Firewall Filtering policy rule.
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

.. Collection note

.. note::
    This module is part of the `zscaler.ziacloud collection <https://galaxy.ansible.com/ui/repo/published/zscaler/ziacloud/>`_ (version 1.0.0).

    It is not included in ``ansible-core``.
    To check whether it is installed, run :code:`ansible-galaxy collection list`.

    To install it, use: :code:`ansible-galaxy collection install zscaler.ziacloud`.
    You need further requirements to be able to use this module,
    see :ref:`Requirements <ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module_requirements>` for details.

    To use it in a playbook, specify: :code:`zscaler.ziacloud.zia_cloud_firewall_filtering_rule`.

.. version_added

.. rst-class:: ansible-version-added

New in zscaler.ziacloud 1.0.0

.. contents::
   :local:
   :depth: 1

.. Deprecated


Synopsis
--------

.. Description

- Adds a new Firewall Filtering policy rule.


.. Aliases


.. Requirements

.. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module_requirements:

Requirements
------------
The below requirements are needed on the host that executes this module.

- Zscaler SDK Python can be obtained from PyPI \ https://pypi.org/project/zscaler-sdk-python/\ 






.. Options

Parameters
----------

.. tabularcolumns:: \X{1}{3}\X{2}{3}

.. list-table::
  :width: 100%
  :widths: auto
  :header-rows: 1
  :class: longtable ansible-option-table

  * - Parameter
    - Comments

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-action"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-action:

      .. rst-class:: ansible-option-title

      **action**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-action" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`string`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      The action the Firewall Filtering policy rule takes when packets match the rule


      .. rst-class:: ansible-option-line

      :ansible-option-choices:`Choices:`

      - :ansible-option-choices-entry:`"ALLOW"`
      - :ansible-option-choices-entry:`"BLOCK\_DROP"`
      - :ansible-option-choices-entry:`"BLOCK\_RESET"`
      - :ansible-option-choices-entry:`"BLOCK\_ICMP"`
      - :ansible-option-choices-entry:`"EVAL\_NWAPP"`


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-app_service_groups"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-app_service_groups:

      .. rst-class:: ansible-option-title

      **app_service_groups**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-app_service_groups" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`list` / :ansible-option-elements:`elements=string`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      Application service groups on which this rule is applied


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-app_services"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-app_services:

      .. rst-class:: ansible-option-title

      **app_services**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-app_services" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`list` / :ansible-option-elements:`elements=string`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      Application services on which this rule is applied


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-departments"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-departments:

      .. rst-class:: ansible-option-title

      **departments**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-departments" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`list` / :ansible-option-elements:`elements=string`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      The departments to which the Firewall Filtering policy rule applies


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-description"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-description:

      .. rst-class:: ansible-option-title

      **description**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-description" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`string`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      Additional information about the rule


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-dest_addresses"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-dest_addresses:

      .. rst-class:: ansible-option-title

      **dest_addresses**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-dest_addresses" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`list` / :ansible-option-elements:`elements=string`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      List of destination IP addresses to which this rule will be applied.

      CIDR notation can be used for destination IP addresses.


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-dest_countries"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-dest_countries:

      .. rst-class:: ansible-option-title

      **dest_countries**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-dest_countries" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`list` / :ansible-option-elements:`elements=string`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      Destination countries for which the rule is applicable.

      If not set, the rule is not restricted to specific destination countries.


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-dest_ip_categories"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-dest_ip_categories:

      .. rst-class:: ansible-option-title

      **dest_ip_categories**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-dest_ip_categories" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`list` / :ansible-option-elements:`elements=string`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      IP address categories of destination for which the DNAT rule is applicable.

      If not set, the rule is not restricted to specific destination IP categories.


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-dest_ip_groups"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-dest_ip_groups:

      .. rst-class:: ansible-option-title

      **dest_ip_groups**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-dest_ip_groups" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`list` / :ansible-option-elements:`elements=string`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      User-defined destination IP address groups on which the rule is applied.

      If not set, the rule is not restricted to a specific destination IP address group.


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-enabled"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-enabled:

      .. rst-class:: ansible-option-title

      **enabled**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-enabled" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`string`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      Determines whether the Firewall Filtering policy rule is enabled or disabled


      .. rst-class:: ansible-option-line

      :ansible-option-choices:`Choices:`

      - :ansible-option-choices-entry:`"DISABLED"`
      - :ansible-option-choices-entry-default:`"ENABLED"` :ansible-option-choices-default-mark:`← (default)`


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-groups"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-groups:

      .. rst-class:: ansible-option-title

      **groups**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-groups" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`list` / :ansible-option-elements:`elements=string`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      The groups to which the Firewall Filtering policy rule applies


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-id"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-id:

      .. rst-class:: ansible-option-title

      **id**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-id" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`integer`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      Unique identifier for the Firewall Filtering policy rule


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-labels"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-labels:

      .. rst-class:: ansible-option-title

      **labels**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-labels" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`list` / :ansible-option-elements:`elements=string`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      Labels that are applicable to the rule.


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-location_groups"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-location_groups:

      .. rst-class:: ansible-option-title

      **location_groups**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-location_groups" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`list` / :ansible-option-elements:`elements=string`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      The location groups to which the Firewall Filtering policy rule applies


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-locations"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-locations:

      .. rst-class:: ansible-option-title

      **locations**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-locations" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`list` / :ansible-option-elements:`elements=string`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      The locations to which the Firewall Filtering policy rule applies


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-name"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-name:

      .. rst-class:: ansible-option-title

      **name**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-name" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`string` / :ansible-option-required:`required`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      Name of the Firewall Filtering policy rule


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-nw_application_groups"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-nw_application_groups:

      .. rst-class:: ansible-option-title

      **nw_application_groups**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-nw_application_groups" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`list` / :ansible-option-elements:`elements=string`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      User-defined network service application group on which the rule is applied.

      If not set, the rule is not restricted to a specific network service application group.


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-nw_applications"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-nw_applications:

      .. rst-class:: ansible-option-title

      **nw_applications**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-nw_applications" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`list` / :ansible-option-elements:`elements=string`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      User-defined network service applications on which the rule is applied.

      If not set, the rule is not restricted to a specific network service application.


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-nw_service_groups"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-nw_service_groups:

      .. rst-class:: ansible-option-title

      **nw_service_groups**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-nw_service_groups" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`list` / :ansible-option-elements:`elements=string`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      User-defined network service group on which the rule is applied.

      If not set, the rule is not restricted to a specific network service group.


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-nw_services"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-nw_services:

      .. rst-class:: ansible-option-title

      **nw_services**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-nw_services" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`list` / :ansible-option-elements:`elements=string`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      User-defined network services on which the rule is applied.

      If not set, the rule is not restricted to a specific network service.


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-order"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-order:

      .. rst-class:: ansible-option-title

      **order**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-order" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`integer` / :ansible-option-required:`required`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      Rule order number of the Firewall Filtering policy rule


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-provider"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-provider:

      .. rst-class:: ansible-option-title

      **provider**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-provider" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`dictionary` / :ansible-option-required:`required`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      A dict object containing connection details.


      .. raw:: html

        </div>
    
  * - .. raw:: html

        <div class="ansible-option-indent"></div><div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-provider/api_key"></div>

      .. raw:: latex

        \hspace{0.02\textwidth}\begin{minipage}[t]{0.3\textwidth}

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-provider/api_key:

      .. rst-class:: ansible-option-title

      **api_key**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-provider/api_key" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`string` / :ansible-option-required:`required`

      .. raw:: html

        </div>

      .. raw:: latex

        \end{minipage}

    - .. raw:: html

        <div class="ansible-option-indent-desc"></div><div class="ansible-option-cell">

      A string that contains the obfuscated API key


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-indent"></div><div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-provider/cloud"></div>

      .. raw:: latex

        \hspace{0.02\textwidth}\begin{minipage}[t]{0.3\textwidth}

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-provider/cloud:

      .. rst-class:: ansible-option-title

      **cloud**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-provider/cloud" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`string` / :ansible-option-required:`required`

      .. raw:: html

        </div>

      .. raw:: latex

        \end{minipage}

    - .. raw:: html

        <div class="ansible-option-indent-desc"></div><div class="ansible-option-cell">

      The Zscaler cloud name was provisioned for your organization


      .. rst-class:: ansible-option-line

      :ansible-option-choices:`Choices:`

      - :ansible-option-choices-entry:`"zscloud"`
      - :ansible-option-choices-entry:`"zscaler"`
      - :ansible-option-choices-entry:`"zscalerone"`
      - :ansible-option-choices-entry:`"zscalertwo"`
      - :ansible-option-choices-entry:`"zscalerthree"`
      - :ansible-option-choices-entry:`"zscalerbeta"`
      - :ansible-option-choices-entry:`"zscalergov"`
      - :ansible-option-choices-entry:`"zscalerten"`


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-indent"></div><div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-provider/password"></div>

      .. raw:: latex

        \hspace{0.02\textwidth}\begin{minipage}[t]{0.3\textwidth}

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-provider/password:

      .. rst-class:: ansible-option-title

      **password**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-provider/password" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`string` / :ansible-option-required:`required`

      .. raw:: html

        </div>

      .. raw:: latex

        \end{minipage}

    - .. raw:: html

        <div class="ansible-option-indent-desc"></div><div class="ansible-option-cell">

      A string that contains the password for the API admin


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-indent"></div><div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-provider/username"></div>

      .. raw:: latex

        \hspace{0.02\textwidth}\begin{minipage}[t]{0.3\textwidth}

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-provider/username:

      .. rst-class:: ansible-option-title

      **username**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-provider/username" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`string` / :ansible-option-required:`required`

      .. raw:: html

        </div>

      .. raw:: latex

        \end{minipage}

    - .. raw:: html

        <div class="ansible-option-indent-desc"></div><div class="ansible-option-cell">

      A string that contains the email ID of the API admin


      .. raw:: html

        </div>


  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-rank"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-rank:

      .. rst-class:: ansible-option-title

      **rank**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-rank" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`integer`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      Admin rank of the Firewall Filtering policy rule


      .. rst-class:: ansible-option-line

      :ansible-option-default-bold:`Default:` :ansible-option-default:`7`

      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-src_ip_groups"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-src_ip_groups:

      .. rst-class:: ansible-option-title

      **src_ip_groups**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-src_ip_groups" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`list` / :ansible-option-elements:`elements=string`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      User-defined source IP address groups for which the rule is applicable.

      If not set, the rule is not restricted to a specific source IP address group.


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-src_ips"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-src_ips:

      .. rst-class:: ansible-option-title

      **src_ips**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-src_ips" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`list` / :ansible-option-elements:`elements=string`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      User-defined source IP addresses for which the rule is applicable.

      If not set, the rule is not restricted to a specific source IP address.


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-state"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-state:

      .. rst-class:: ansible-option-title

      **state**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-state" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`string`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      The state.


      .. rst-class:: ansible-option-line

      :ansible-option-choices:`Choices:`

      - :ansible-option-choices-entry-default:`"present"` :ansible-option-choices-default-mark:`← (default)`
      - :ansible-option-choices-entry:`"absent"`


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-time_windows"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-time_windows:

      .. rst-class:: ansible-option-title

      **time_windows**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-time_windows" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`list` / :ansible-option-elements:`elements=string`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      The time interval in which the Firewall Filtering policy rule applies


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-users"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-users:

      .. rst-class:: ansible-option-title

      **users**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-users" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`list` / :ansible-option-elements:`elements=string`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      The users to which the Firewall Filtering policy rule applies


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-workload_groups"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_filtering_rule_module__parameter-workload_groups:

      .. rst-class:: ansible-option-title

      **workload_groups**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-workload_groups" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`list` / :ansible-option-elements:`elements=integer`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      The list of preconfigured workload groups to which the policy must be applied.


      .. raw:: html

        </div>


.. Attributes


.. Notes


.. Seealso


.. Examples

Examples
--------

.. code-block:: yaml+jinja

    
    - name: Create/update  firewall filtering rule
      zscaler.ziacloud.zia_cloud_firewall_filtering_rule:
        provider: '{{ provider }}'
        state: present
        name: "Ansible_Example_Rule"
        description: "TT#1965232865"
        action: "ALLOW"
        enabled: true
        order: 1
        enable_full_logging: true
        exclude_src_countries: true
        source_countries:
          - BR
          - CA
          - US
        dest_countries:
          - BR
          - CA
          - US
        device_trust_levels:
          - "UNKNOWN_DEVICETRUSTLEVEL"
          - "LOW_TRUST"
          - "MEDIUM_TRUST"
          - "HIGH_TRUST"




.. Facts


.. Return values


..  Status (Presently only deprecated)


.. Authors

Authors
~~~~~~~

- William Guilherme (@willguibr)



.. Extra links

Collection links
~~~~~~~~~~~~~~~~

.. ansible-links::

  - title: "Issue Tracker"
    url: "https://github.com/zscaler/ziacloud-ansible/issues"
    external: true
  - title: "Repository (Sources)"
    url: "https://github.com/zscaler/ziacloud-ansible"
    external: true


.. Parsing errors

