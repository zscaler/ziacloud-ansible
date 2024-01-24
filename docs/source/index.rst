==========================================
Zscaler Internet Access Ansible Collection
==========================================

Version: 1.0.0

The Zscaler Private Access Ansible collection is a collection of modules that
automate configuration and operational tasks on Zscaler Private Access Cloud. The
underlying protocol uses API calls that are wrapped within the Ansible
framework.


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

* Ansible Galaxy: https://galaxy.ansible.com/zscaler/ziacloud
* Red Hat Catalog: https://catalog.redhat.com/software/collection/zscaler/ziacloud
* GitHub repo:  https://github.com/zscaler/ziacloud-ansible


.. toctree::
   :maxdepth: 2
   :caption: Contents:

   examples
   modules
   history
   authors
   license


Collection Dependencies
=======================

* zscaler-sdk-python

If you believe you have installed these dependencies but Ansible is not finding them, it is likely a
problem with where your local shell is searching for installed dependencies and where Ansible is
searching for them.

Configuring `ANSIBLE_PYTHON_INTERPRETER` is probably the solution to this issue:

https://docs.ansible.com/ansible/latest/reference_appendices/python_3_support.html#using-python-3-on-the-managed-machines-with-commands-and-playbooks


Support
=======
As of version 1.0.0, this Collection of Ansible Modules for Zscaler Internet Access is
[certified on Ansible Automation Hub](https://console.redhat.com/ansible/automation-hub/repo/published/zscaler/ziacloud)
and officially supported for Ansible subscribers. Ansible subscribers can engage
for support through their usual route towards Red Hat.

For those who are not Ansible subscribers, this Collection of Ansible Modules is
also [published on Ansible Galaxy](https://galaxy.ansible.com/ui/repo/published/zscaler/ziacloud)
to be freely used under an as-is, best effort, support
policy. These scripts should be seen as community supported and Zscaler
Technology Alliances Team will contribute our expertise as and when possible.
We do not provide technical support or help in using or troubleshooting the components
of the project through our normal support options such as Zscaler support teams,
or ASC (Authorized Support Centers) partners and backline
support options. The underlying product used (Zscaler Private Access API) but the
scripts or templates are still supported, but the support is only for the
product functionality and not for help in deploying or using the template or
script itself.

Unless explicitly tagged, all projects or work posted in our
[GitHub repository](https://github.com/zscaler) or sites other
than our official [Downloads page](https://help.zscaler.com/login-tickets)
are provided under the best effort policy.

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
