
.. Document meta

:orphan:

.. |antsibull-internal-nbsp| unicode:: 0xA0
    :trim:

.. meta::
  :antsibull-docs: 2.7.0

.. Anchors

.. _ansible_collections.zscaler.ziacloud.zia_dlp_engine_module:

.. Anchors: short name for ansible.builtin

.. Title

zscaler.ziacloud.zia_dlp_engine module -- Adds a new custom DLP engine.
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

.. Collection note

.. note::
    This module is part of the `zscaler.ziacloud collection <https://galaxy.ansible.com/ui/repo/published/zscaler/ziacloud/>`_ (version 1.0.0).

    It is not included in ``ansible-core``.
    To check whether it is installed, run :code:`ansible-galaxy collection list`.

    To install it, use: :code:`ansible-galaxy collection install zscaler.ziacloud`.
    You need further requirements to be able to use this module,
    see :ref:`Requirements <ansible_collections.zscaler.ziacloud.zia_dlp_engine_module_requirements>` for details.

    To use it in a playbook, specify: :code:`zscaler.ziacloud.zia_dlp_engine`.

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

- Adds a new custom DLP engine.


.. Aliases


.. Requirements

.. _ansible_collections.zscaler.ziacloud.zia_dlp_engine_module_requirements:

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
        <div class="ansibleOptionAnchor" id="parameter-custom_dlp_engine"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_dlp_engine_module__parameter-custom_dlp_engine:

      .. rst-class:: ansible-option-title

      **custom_dlp_engine**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-custom_dlp_engine" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`boolean` / :ansible-option-required:`required`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      The DLP engine description.


      .. rst-class:: ansible-option-line

      :ansible-option-choices:`Choices:`

      - :ansible-option-choices-entry:`false`
      - :ansible-option-choices-entry:`true`


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-description"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_dlp_engine_module__parameter-description:

      .. rst-class:: ansible-option-title

      **description**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-description" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`string` / :ansible-option-required:`required`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      The DLP engine description.


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-engine_expression"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_dlp_engine_module__parameter-engine_expression:

      .. rst-class:: ansible-option-title

      **engine_expression**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-engine_expression" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`string` / :ansible-option-required:`required`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      The logical expression that defines a DLP engine by combining DLP dictionaries using logical operators.

      Namely All (AND), Any (OR), Exclude (NOT), and Sum (the total number of content matches).

      ((D63.S \> 1)).

      ((D38.S \> 1) AND (D63.S \> 1)).

      ((D38.S \> 1) OR (D63.S \> 1)).

      (SUM(D63.S, D38.S) \> 3).

      In the preceding examples, 63 represents the ID of the Credit Cards dictionary ID.

      61 is the Financial Statements ID, and 38 is the ABA Bank Routing Numbers dictionary ID.

      Each dictionary ID is wrapped around by a prefix (D) and a suffix (.S).


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-id"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_dlp_engine_module__parameter-id:

      .. rst-class:: ansible-option-title

      **id**

      .. raw:: html

        <a class="ansibleOptionLink" href="#parameter-id" title="Permalink to this option"></a>

      .. ansible-option-type-line::

        :ansible-option-type:`string`

      .. raw:: html

        </div>

    - .. raw:: html

        <div class="ansible-option-cell">

      The unique identifier for the DLP engine.


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-name"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_dlp_engine_module__parameter-name:

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

      The DLP engine name as configured by the admin.

      This attribute is required in POST and PUT requests for custom DLP engines.


      .. raw:: html

        </div>

  * - .. raw:: html

        <div class="ansible-option-cell">
        <div class="ansibleOptionAnchor" id="parameter-provider"></div>

      .. _ansible_collections.zscaler.ziacloud.zia_dlp_engine_module__parameter-provider:

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

      .. _ansible_collections.zscaler.ziacloud.zia_dlp_engine_module__parameter-provider/api_key:

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

      .. _ansible_collections.zscaler.ziacloud.zia_dlp_engine_module__parameter-provider/cloud:

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

      .. _ansible_collections.zscaler.ziacloud.zia_dlp_engine_module__parameter-provider/password:

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

      .. _ansible_collections.zscaler.ziacloud.zia_dlp_engine_module__parameter-provider/username:

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

      .. _ansible_collections.zscaler.ziacloud.zia_dlp_engine_module__parameter-state:

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


.. Attributes


.. Notes


.. Seealso


.. Examples

Examples
--------

.. code-block:: yaml+jinja

    
    - name: Create/Update/Delete custom dlp engine.
      zscaler.ziacloud.zia_dlp_engine:
        provider: '{{ provider }}'
        name: "Example"
        description: "Example"
        engine_expression: "((D63.S > 1))"
        custom_dlp_engine: true




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

