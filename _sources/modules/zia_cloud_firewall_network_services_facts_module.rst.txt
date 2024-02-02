
.. Document meta

:orphan:

.. |antsibull-internal-nbsp| unicode:: 0xA0
    :trim:

.. meta::
  :antsibull-docs: 2.7.0

.. Anchors

.. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_network_services_facts_module:

.. Anchors: short name for ansible.builtin

.. Title

zscaler.ziacloud.zia_cloud_firewall_network_services_facts module -- Gets a list of all network services.
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

.. Collection note

.. note::
    This module is part of the `zscaler.ziacloud collection <https://galaxy.ansible.com/ui/repo/published/zscaler/ziacloud/>`_ (version 1.0.0).

    It is not included in ``ansible-core``.
    To check whether it is installed, run :code:`ansible-galaxy collection list`.

    To install it, use: :code:`ansible-galaxy collection install zscaler.ziacloud`.
    You need further requirements to be able to use this module,
    see :ref:`Requirements <ansible_collections.zscaler.ziacloud.zia_cloud_firewall_network_services_facts_module_requirements>` for details.

    To use it in a playbook, specify: :code:`zscaler.ziacloud.zia_cloud_firewall_network_services_facts`.

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

- Gets a list of all network services.


.. Aliases


.. Requirements

.. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_network_services_facts_module_requirements:

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
        <div class="ansibleOptionAnchor" id="parameter-id"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_network_services_facts_module__parameter-id:

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

      The unique identifier for the network services


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-name"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_network_services_facts_module__parameter-name:

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

      The network services name


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-provider"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_network_services_facts_module__parameter-provider:

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

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_network_services_facts_module__parameter-provider/api_key:

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

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_network_services_facts_module__parameter-provider/cloud:

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

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_network_services_facts_module__parameter-provider/password:

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

      .. _ansible_collections.zscaler.ziacloud.zia_cloud_firewall_network_services_facts_module__parameter-provider/username:

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



.. Attributes


.. Notes


.. Seealso


.. Examples

Examples
--------

.. code-block:: yaml+jinja

    
    - name: Gather Information Details of all Network Services
      zscaler.ziacloud.zia_cloud_firewall_network_services_facts:
        provider: '{{ provider }}'

    - name: Gather Information Details of a Network Services by Name
      zscaler.ziacloud.zia_cloud_firewall_network_services_facts:
        provider: '{{ provider }}'
        name: "ICMP_ANY"




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

