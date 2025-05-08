.. ...........................................................................
.. © Copyright Zscaler Inc, 2024                                             .
.. ...........................................................................

==========================
Authentication
==========================

This guide covers the authentication methods available for the ZIA Ansible Collection modules.

=============================
Zscaler OneAPI New Framework
=============================

The ZIA Ansible Collection now offers support for (`OneAPI <https://help.zscaler.com/oneapi/understanding-oneapi>`_) OAuth2 authentication through (`Zidentity <https://help.zscaler.com/zidentity/what-zidentity>`_)

* NOTE: As of version v2.0.0, this Ansible Collection offers backwards compatibility to the Zscaler legacy API framework. This is the recommended authentication method for organizations whose tenants are still not migrated to (`Zidentity <https://help.zscaler.com/zidentity/what-zidentity>`_)

* NOTE: Notice that OneAPI and Zidentity is not currently supported for the following clouds: `zscalergov` and `zscalerten`. Refer to the Legacy API Framework for more information on how authenticate to these environments

* NOTE: The authentication parameter `cloud` or `ZSCALER_CLOUD` are optional, and only required when authenticating to a non-production environment i.e `beta`

Client Secret Authentication
-----------------------------

1. **Environment Variables**

   .. code-block:: bash

      export ZSCALER_CLIENT_ID="client_id"
      export ZSCALER_CLIENT_SECRET="client_secret"
      export ZSCALER_VANITY_DOMAIN="vanity_domain"
      export ZSCALER_CLOUD='beta'

2. **Credential File**

   Alternatively, you can authenticate using a credentials file. This file should be passed to the playbook with the `-e` option.
   For example, to execute the `zia_rule_labels.yml` playbook using `creds.yml`:

   .. code-block:: bash

      ansible-playbook zia_rule_labels.yml -e @creds.yml

   The `creds.yml` file should have the following structure:

   .. code-block:: yaml

      client_id: "client_id"
      client_secret: "client_secret"
      vanity_domain: "vanity_domain"
      cloud: "beta"

   In your playbook, you must then have the following configuration:

   .. code-block:: yaml

      - name: Create Rule Label
        hosts: localhost
        connection: local

        vars:
          zia_cloud:
            client_id: "{{ client_id | default(omit) }}"
            client_secret: "{{ client_secret | default(omit) }}"
            vanity_domain: "{{ vanity_domain | default(omit) }}"
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
              client_id: "client_id"
              client_secret: "client_secret"
              vanity_domain: "vanity_domain"
              cloud: "cloud"
              name: Example
              description: Example
            register: result

Private Key Authentication
-----------------------------

1. **Environment Variables**

   .. code-block:: bash

      export ZSCALER_CLIENT_ID="client_id"
      export ZSCALER_PRIVATE_KEY="private_key.pem"
      export ZSCALER_VANITY_DOMAIN="vanity_domain"
      export ZSCALER_CLOUD='beta'

2. **Credential File**

   Alternatively, you can authenticate using a credentials file. This file should be passed to the playbook with the `-e` option.
   For example, to execute the `zia_rule_labels.yml` playbook using `creds.yml`:

   .. code-block:: bash

      ansible-playbook zia_rule_labels.yml -e @creds.yml

   The `creds.yml` file should have the following structure:

   .. code-block:: yaml

      client_id: "client_id"
      private_key: "private_key.pem"
      vanity_domain: "vanity_domain"
      cloud: "beta"

   In your playbook, you must then have the following configuration:

   .. code-block:: yaml

      - name: Create Rule Label
        hosts: localhost
        connection: local

        vars:
          zia_cloud:
            client_id: "{{ client_id | default(omit) }}"
            private_key: "{{ lookup('file', 'private_key.pem') | default(omit) }}"
            vanity_domain: "{{ vanity_domain | default(omit) }}"
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
              client_id: "client_id"
              private_key: "private_key.pem"
              vanity_domain: "vanity_domain"
              cloud: "cloud"
              name: Example
              description: Example
            register: result

=============================
Legacy API Authentication
=============================

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
      export ZSCALER_USE_LEGACY_CLIENT=true

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
      use_legacy_client: true

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
            use_legacy_client: "{{ use_legacy_client | default(omit) }}"

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
              use_legacy_client: true
              name: Example
              description: Example
            register: result

.. Warning::

   Zscaler does not recommend using hard-coded credentials in your playbooks. This can lead to credential leakage, especially if your configuration files are being committed to a version control system (e.g., GitHub).

