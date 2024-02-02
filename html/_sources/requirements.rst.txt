.. ...........................................................................
.. © Copyright Zscaler Inc, 2024                                             .
.. ...........................................................................

==========================
Requirements
==========================

The **Zscaler Internet Access Collection** has the following requirements in order to be successfully used:

* **zscaler-sdk-python**

If you believe you have installed these dependencies but Ansible is not finding them, it is likely a
problem with where your local shell is searching for installed dependencies and where Ansible is
searching for them.

Configuring **ANSIBLE_PYTHON_INTERPRETER** is probably the solution to this issue:

.. _collection dependencies:
    https://docs.ansible.com/ansible/latest/reference_appendices/python_3_support.html#using-python-3-on-the-managed-machines-with-commands-and-playbooks
