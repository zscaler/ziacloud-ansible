.. ...........................................................................
.. © Copyright Zscaler Inc, 2024                                             .
.. ...........................................................................

==========================
Requirements
==========================

The **Zscaler Internet Access Collection** has the following requirements in order to be successfully used.

Python dependencies
----------------------

The minimum python version for this collection is python `3.9`.

The Python module dependencies are not automatically handled by `ansible-galaxy`. To manually install these dependencies, you have the following options:

1. Utilize the `requirements.txt` file located `here <https://github.com/zscaler/ziacloud-ansible/blob/master/requirements.txt>`_ to install all required packages:

    ```bash
    pip install -r requirements.txt
    ```

2. Alternatively, install the `Zscaler SDK Python <https://pypi.org/project/zscaler-sdk-python/>`_ package directly:

    ```bash
    pip install zscaler-sdk-python
    ```

If you believe you have installed these dependencies but Ansible is not finding them, it is likely a
problem with where your local shell is searching for installed dependencies and where Ansible is
searching for them.

Configuring **ANSIBLE_PYTHON_INTERPRETER** is probably the solution to this issue:

.. _collection dependencies:
    https://docs.ansible.com/ansible/latest/reference_appendices/python_3_support.html#using-python-3-on-the-managed-machines-with-commands-and-playbooks
