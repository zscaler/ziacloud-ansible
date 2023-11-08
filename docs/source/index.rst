==========================================
Zscaler Internet Access Ansible Collection
==========================================

Version: 1.0.0

The Zscaler Private Access Ansible collection is a collection of modules that
automate configuration and operational tasks on Zscaler Private Access Cloud. The
underlying protocol uses API calls that are wrapped within the Ansible
framework.

This is a **community supported project**; hence, this project or the software module is not affiliated or supported by Zscaler engineering teams in any way.

Installation
============

Ansible 2.9 is **required** for using collections.

Install the collection using `ansible-galaxy`:

.. code-block:: bash

    ansible-galaxy collection install zscaler.ziacloud

Then in your playbooks you can specify that you want to use the
`ziacloud` collection like so:

.. code-block:: yaml

    collections:
        - zscaler.ziacloud

* Ansible Galaxy: https://galaxy.ansible.com/willguibr/ziacloud
* GitHub repo:  https://github.com/willguibr/ziacloud-ansible


.. toctree::
   :maxdepth: 2
   :caption: Contents:

   examples
   modules
   history
   authors
   license


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
