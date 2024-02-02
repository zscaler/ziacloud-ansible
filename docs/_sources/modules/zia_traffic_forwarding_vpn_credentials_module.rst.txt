
.. Document meta

:orphan:

.. |antsibull-internal-nbsp| unicode:: 0xA0
    :trim:

.. meta::
  :antsibull-docs: 2.7.0

.. Anchors

.. _ansible_collections.zscaler.ziacloud.zia_traffic_forwarding_vpn_credentials_module:

.. Anchors: short name for ansible.builtin

.. Title

zscaler.ziacloud.zia_traffic_forwarding_vpn_credentials module -- Adds VPN credentials that can be associated to locations.
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

.. Collection note

.. note::
    This module is part of the `zscaler.ziacloud collection <https://galaxy.ansible.com/ui/repo/published/zscaler/ziacloud/>`_ (version 1.0.0).

    It is not included in ``ansible-core``.
    To check whether it is installed, run :code:`ansible-galaxy collection list`.

    To install it, use: :code:`ansible-galaxy collection install zscaler.ziacloud`.
    You need further requirements to be able to use this module,
    see :ref:`Requirements <ansible_collections.zscaler.ziacloud.zia_traffic_forwarding_vpn_credentials_module_requirements>` for details.

    To use it in a playbook, specify: :code:`zscaler.ziacloud.zia_traffic_forwarding_vpn_credentials`.

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

- Adds VPN credentials that can be associated to locations.


.. Aliases


.. Requirements

.. _ansible_collections.zscaler.ziacloud.zia_traffic_forwarding_vpn_credentials_module_requirements:

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
        <div class="ansibleOptionAnchor" id="parameter-comments"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_traffic_forwarding_vpn_credentials_module__parameter-comments:

      .. rst-class:: ansible-option-title

      **comments**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-comments" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`string`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      Additional information about this VPN credential.


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-fqdn"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_traffic_forwarding_vpn_credentials_module__parameter-fqdn:

      .. rst-class:: ansible-option-title

      **fqdn**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-fqdn" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`string`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      Fully Qualified Domain Name. Applicable only to UFQDN or XAUTH (or HOSTED\_MOBILE\_USERS) auth type.


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-id"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_traffic_forwarding_vpn_credentials_module__parameter-id:

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

      VPN credential id


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-pre_shared_key"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_traffic_forwarding_vpn_credentials_module__parameter-pre_shared_key:

      .. rst-class:: ansible-option-title

      **pre_shared_key**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-pre_shared_key" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`boolean`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      Pre-shared key. This is a required field for UFQDN and IP auth type.


      .. rst-class:: ansible-option-line

      :ansible-option-choices:`Choices:`

      - :ansible-option-choices-entry:`false`
      - :ansible-option-choices-entry:`true`


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-provider"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_traffic_forwarding_vpn_credentials_module__parameter-provider:

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

      .. _ansible_collections.zscaler.ziacloud.zia_traffic_forwarding_vpn_credentials_module__parameter-provider/api_key:

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

      .. _ansible_collections.zscaler.ziacloud.zia_traffic_forwarding_vpn_credentials_module__parameter-provider/cloud:

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

      .. _ansible_collections.zscaler.ziacloud.zia_traffic_forwarding_vpn_credentials_module__parameter-provider/password:

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

      .. _ansible_collections.zscaler.ziacloud.zia_traffic_forwarding_vpn_credentials_module__parameter-provider/username:

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
        <div class="ansibleOptionAnchor" id="parameter-state"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_traffic_forwarding_vpn_credentials_module__parameter-state:

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

      Whether the app connector group should be present or absent.


      .. rst-class:: ansible-option-line

      :ansible-option-choices:`Choices:`

      - :ansible-option-choices-entry-default:`"present"` :ansible-option-choices-default-mark:`← (default)`
      - :ansible-option-choices-entry:`"absent"`


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-type"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_traffic_forwarding_vpn_credentials_module__parameter-type:

      .. rst-class:: ansible-option-title

      **type**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-type" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`string`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      VPN authentication type (i.e., how the VPN credential is sent to the server).

      It is not modifiable after VpnCredential is created.


      .. rst-class:: ansible-option-line

      :ansible-option-choices:`Choices:`

      - :ansible-option-choices-entry:`"IP"`
      - :ansible-option-choices-entry-default:`"UFQDN"` :ansible-option-choices-default-mark:`← (default)`


      .. raw:: html

        </div>


.. Attributes


.. Notes


.. Seealso


.. Examples

Examples
--------

.. code-block:: yaml+jinja

    

    - name: Create/Update/Delete VPN Credentials Type IP.
      zscaler.ziacloud.zia_traffic_forwarding_vpn_credentials:
        provider: '{{ provider }}'
        type: "IP"
        ip_address: "1.1.1.1"
        comments: "Created via Ansible"
        pre_shared_key: "newPassword123!"

    - name: Create/Update/Delete VPN Credentials Type UFQDN.
      zscaler.ziacloud.zia_traffic_forwarding_vpn_credentials:
        provider: '{{ provider }}'
        type: "UFQDN"
        ip_address: "sjc-1-37@acme.com"
        comments: "Created via Ansible"
        pre_shared_key: "newPassword123!"




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

