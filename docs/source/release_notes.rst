.. ...........................................................................
.. © Copyright Zscaler Inc, 2024                                             .
.. ...........................................................................

======================
Releases
======================

Zscaler Internet Access (ZIA) Ansible Collection Changelog
----------------------------------------------------------

1.3.0 (September, 6 2024)
-------------------------

Notes
^^^^^

- Python Versions: **v3.9, v3.10, v3.11**

New Feature
^^^^^^^^^^^

- (`#46 <https://github.com/zscaler/ziacloud-ansible/issues/46>`_) Added new resource `zia_cloud_app_control_rule` and `zia_cloud_app_control_rule_info` for Cloud Application Control rule management.


1.2.0 (July, 22 2024)
----------------------

Notes
^^^^^

- Python Versions: **v3.9, v3.10, v3.11**

BREAKING CHANGES
^^^^^^^^^^^^^^^^

- (`#270 <https://github.com/zscaler/ziacloud-ansible/issues/270>`_) All resources previously named with `_facts` have been moved to `_info` to comply with Red Hat Ansible best practices as described in the following (`Ansible Developer Documentation <https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_general.html#creating-an-info-or-a-facts-module>`_)

NEW FEATURES
^^^^^^^^^^^^
- (`#270 <https://github.com/zscaler/ziacloud-ansible/issues/270>`_) All resources now support `check_mode` for simulation purposes and for validating configuration management playbooks.

1.1.0 (June, 25 2024)
----------------------

Notes
^^^^^

- Python Versions: **v3.9, v3.10, v3.11**

Enhancements
^^^^^^^^^^^^

- Added Forwarding Control Rule Resource (`#37 <https://github.com/zscaler/ziacloud-ansible/issues/37>`_)

1.0.17 (May, 04 2024)
----------------------

Notes
^^^^^

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
^^^^^^^^^

- Updated requirements.txt and documentation (`#34 <https://github.com/zscaler/ziacloud-ansible/issues/34>`_)

1.0.16 (May, 04 2024)
----------------------

Notes
^^^^^

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
^^^^^^^^^

- Fixed IP Destination and IP Source Group Drift (`#33 <https://github.com/zscaler/ziacloud-ansible/issues/33>`_)

1.0.15 (May, 04 2024)
----------------------

Notes
^^^^^

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
^^^^^^^^^

- Fixed zia authentication method schema (`#31 <https://github.com/zscaler/ziacloud-ansible/issues/31>`_)

1.0.14 (April, 24 2024)
------------------------

Notes
^^^^^

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
^^^^^^^^^

- Added collection version to user-agent header (`#30 <https://github.com/zscaler/ziacloud-ansible/issues/30>`_)

1.0.13 (April, 23 2024)
------------------------

Notes
^^^^^

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
^^^^^^^^^

- Fixed release process for automation hub (`#27 <https://github.com/zscaler/ziacloud-ansible/issues/27>`_)

1.0.12 (April, 23 2024)
------------------------

Notes
^^^^^

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
^^^^^^^^^

- Removed Beta comment from README and fixed galaxy link on index (`#e47696c <https://github.com/zscaler/ziacloud-ansible/commit/e47696cc8c4ea26e492547a76687dce8dcc71b2a>`_)

1.0.11 (April, 23 2024)
------------------------

Notes
^^^^^

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
^^^^^^^^^

- Removed Beta from README page (`#658b30b <https://github.com/zscaler/ziacloud-ansible/commit/658b30baa1d1f6204de53c91aeb99f394788f79d>`_)


1.0.10 (April, 23 2024)
------------------------

Notes
^^^^^

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
^^^^^^^^^

- Fixed linter workflow and documentation (`#45f0f98 <https://github.com/zscaler/ziacloud-ansible/commit/45f0f98fe6e6eebfb83dab7775c847d845ede585>`_)

1.0.9 (April, 23 2024)
----------------------

Notes
^^^^^

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
^^^^^^^^^

- Fixed makefile doc generation section (`#26024a5 <https://github.com/zscaler/ziacloud-ansible/commit/26024a5073e9b2338b1f656d4ceef54f0f2e131a>`_)

1.0.8 (April, 23 2024)
----------------------

Notes
^^^^^

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
^^^^^^^^^

- Fixed makefile doc generation section (`#165756c <https://github.com/zscaler/ziacloud-ansible/commit/165756cdab765b556c0a82e4fb01f0612b96bc41>`_)

1.0.7 (April, 23 2024)
----------------------

Notes
^^^^^

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
^^^^^^^^^

- Removed poetry from release.yml doc generation (`#e0feb95 <https://github.com/zscaler/ziacloud-ansible/commit/e0feb95affb02877cb2c8471dae9137f56d20ccf>`_)

1.0.6 (April, 23 2024)
----------------------

Notes
^^^^^

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
^^^^^^^^^

- Fixed index.rst document (`#dfef5dc <https://github.com/zscaler/ziacloud-ansible/commit/dfef5dc53b63c3aa7f04bfa9809fdbcc3c06472d>`_)

1.0.5 (April, 23 2024)
----------------------

Notes
^^^^^

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
^^^^^^^^^

- Fixed index.rst document (`#ddf8eee <https://github.com/zscaler/ziacloud-ansible/commit/ddf8eee851c2e24af6383d39e6535d8e714e51c1>`_)


1.0.4 (April, 23 2024)
----------------------

Notes
^^^^^

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
^^^^^^^^^

- Temporarily disabled Automation Hub Workflow (`#77ccd0d <https://github.com/zscaler/ziacloud-ansible/commit/77ccd0d306de88422f0718bdfa88c888c41e3042>`_)


1.0.3 (April, 23 2024)
----------------------

Notes
^^^^^

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
^^^^^^^^^

- Temporarily disabled Automation Hub Workflow (`#e1a4b24 <https://github.com/zscaler/ziacloud-ansible/commit/e1a4b24bb0a0d669073ce79cda7d197ea73c69f7>`_)


1.0.2 (April, 23 2024)
----------------------

Notes
^^^^^

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
^^^^^^^^^

- Temporarily disabled Automation Hub Workflow (`#78b77bd <https://github.com/zscaler/ziacloud-ansible/commit/78b77bdb1c576306d2c130784a6956e28d8224d6>`_)

1.0.1 (April, 23 2024)
----------------------

Notes
^^^^^

- Python Versions: **v3.9, v3.10, v3.11**

Bug Fixes
^^^^^^^^^

- Temporarily disabled Automation Hub Workflow (`#66a363f <https://github.com/zscaler/ziacloud-ansible/commit/66a363fc3541ab8998f8bd2d0ab5acd2934f0665>`_)

1.0.0 (April, 22 2024)
----------------------

Notes
^^^^^

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
