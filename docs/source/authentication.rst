.. ...........................................................................
.. © Copyright Zscaler Inc, 2024                                             .
.. ...........................................................................

==========================
Authentication
==========================

This guide covers the authentication methods available for the ZIA Ansible Collection modules.

The ZIA Ansible Collection supports the following environments:

* zscaler
* zscalerone
* zscalertwo
* zscalerthree
* zscloud
* zscalerbeta
* zscalergov
* zscalerten
* zspreview

1. **Environment Variables**

   You can authenticate using only environment variables. Set the following variables before running your playbook:

   .. code-block:: bash

      export ZIA_USERNAME="username"
      export ZIA_PASSWORD="password"
      export ZIA_API_KEY="api_key"
      export ZIA_CLOUD="zscalerone"

2. **Credential File**

   Alternatively, you can authenticate using a credentials file. This file should be passed to the playbook with the `-e` option.
   For example, to execute the `zia_rule_labels.yml` playbook using `creds.yml`:

   .. code-block:: bash

      ansible-playbook zia_rule_labels.yml -e @creds.yml

   The `creds.yml` file should have the following structure:

   .. code-block:: yaml

      username: "username"
      password: "password"
      api_key: "api_key"
      cloud: "zscalerone"

   In your playbook, you must then have the following configuration:

   .. code-block:: yaml

      - name: Create Rule Label
        hosts: localhost
        connection: local

        vars:
          zia_cloud:
            username: "{{ username | default(omit) }}"
            password: "{{ password | default(omit) }}"
            api_key: "{{ api_key | default(omit) }}"
            cloud: "{{ cloud | default(omit) }}"

        tasks:
          - name: Create Rule Label
            zscaler.ziacloud.zia_rule_labels:
              provider: "{{ zia_cloud }}"
              name: Example
              description: Example
            register: result

3. **Provider Block (Empty Dictionary)**

   You can also use an empty `provider` block, which will then fall back to the environment variables:

   .. code-block:: yaml

      - name: Create Rule Label
        hosts: localhost
        connection: local

        tasks:
          - name: Create Rule Label
            zscaler.ziacloud.zia_rule_labels:
              provider: {}
              name: Example
              description: Example
            register: result

4. **Direct Parameters in Playbook Task**

   The authentication parameters can also be set directly within the playbook task:

   .. code-block:: yaml

      - name: Create Rule Label
        hosts: localhost
        connection: local

        tasks:
          - name: Create Rule Label
            zscaler.ziacloud.zia_rule_labels:
              username: "username"
              password: "password"
              api_key: "api_key"
              cloud: "cloud"
              name: Example
              description: Example
            register: result

.. Warning::

   Zscaler does not recommend using hard-coded credentials in your playbooks. This can lead to credential leakage, especially if your configuration files are being committed to a version control system (e.g., GitHub).

