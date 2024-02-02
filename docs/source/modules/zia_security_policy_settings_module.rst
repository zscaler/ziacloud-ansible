
.. Document meta

:orphan:

.. |antsibull-internal-nbsp| unicode:: 0xA0
    :trim:

.. meta::
  :antsibull-docs: 2.7.0

.. Anchors

.. _ansible_collections.zscaler.ziacloud.zia_security_policy_settings_module:

.. Anchors: short name for ansible.builtin

.. Title

zscaler.ziacloud.zia_security_policy_settings module -- Adds a URL to or removes a URL from the Denylist
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

.. Collection note

.. note::
    This module is part of the `zscaler.ziacloud collection <https://galaxy.ansible.com/ui/repo/published/zscaler/ziacloud/>`_ (version 1.0.0).

    It is not included in ``ansible-core``.
    To check whether it is installed, run :code:`ansible-galaxy collection list`.

    To install it, use: :code:`ansible-galaxy collection install zscaler.ziacloud`.
    You need further requirements to be able to use this module,
    see :ref:`Requirements <ansible_collections.zscaler.ziacloud.zia_security_policy_settings_module_requirements>` for details.

    To use it in a playbook, specify: :code:`zscaler.ziacloud.zia_security_policy_settings`.

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

- Adds a URL to or removes a URL from the Denylist.


.. Aliases


.. Requirements

.. _ansible_collections.zscaler.ziacloud.zia_security_policy_settings_module_requirements:

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
        <div class="ansibleOptionAnchor" id="parameter-provider"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_security_policy_settings_module__parameter-provider:

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

      .. _ansible_collections.zscaler.ziacloud.zia_security_policy_settings_module__parameter-provider/api_key:

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

      .. _ansible_collections.zscaler.ziacloud.zia_security_policy_settings_module__parameter-provider/cloud:

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

      .. _ansible_collections.zscaler.ziacloud.zia_security_policy_settings_module__parameter-provider/password:

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

      .. _ansible_collections.zscaler.ziacloud.zia_security_policy_settings_module__parameter-provider/username:

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

      .. _ansible_collections.zscaler.ziacloud.zia_security_policy_settings_module__parameter-state:

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
        <div class="ansibleOptionAnchor" id="parameter-url_type"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_security_policy_settings_module__parameter-url_type:

      .. rst-class:: ansible-option-title

      **url_type**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-url_type" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`string`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      The type of URL to be whitelisted or blacklisted.


      .. rst-class:: ansible-option-line

      :ansible-option-choices:`Choices:`

      - :ansible-option-choices-entry:`"whitelist"`
      - :ansible-option-choices-entry:`"blacklist"`


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-urls"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_security_policy_settings_module__parameter-urls:

      .. rst-class:: ansible-option-title

      **urls**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-urls" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`list` / :ansible-option-elements:`elements=string`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      URLs on the denylist for your organization. Allow up to 25000 URLs.


      .. raw:: html

        </div>


.. Attributes


.. Notes


.. Seealso


.. Examples

Examples
--------

.. code-block:: yaml+jinja

    

    - name: ADD and REMOVE URLs from Blacklist or Whitelist
      zscaler.ziacloud.zia_security_policy_settings:
        provider: '{{ provider }}'
        urls:
          - test1.acme.com
          - test2.acme.com
          - test3.acme.com
          - test4.acme.com
        url_type: "blacklist"




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

