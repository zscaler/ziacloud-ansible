.. ...........................................................................
.. © Copyright Zscaler Inc, 2024                                             .
.. ...........................................................................

==========================
Authentication
==========================

This guide covers the authentication methods available for the ZIA Ansible Collection modules.

Choosing Your Authentication Method
-----------------------------------

The collection supports two mutually exclusive modes:

* **OneAPI (default)** – Use when your tenant is migrated to (`Zidentity <https://help.zscaler.com/zidentity/what-zidentity>`_). Requires ``client_id`` plus either ``client_secret`` or ``private_key``, and ``vanity_domain``. The ``cloud`` parameter is optional (omit for production; use ``beta`` for beta).

* **Legacy** – Use when your tenant is **not** on Zidentity, or for ``zscalergov`` and ``zscalerten`` clouds (OneAPI is not supported there). Requires ``use_legacy_client: true`` plus ``username``, ``password``, ``api_key``, and ``cloud``. The ``cloud`` parameter is required; use one of: zscaler, zscloud, zscalerbeta, zspreview, zscalerone, zscalertwo, zscalerthree, zscalergov, zscalerten.

=============================
Zscaler OneAPI New Framework
=============================

The ZIA Ansible Collection offers (`OneAPI <https://help.zscaler.com/oneapi/understanding-oneapi>`_) OAuth2 authentication through (`Zidentity <https://help.zscaler.com/zidentity/what-zidentity>`_).

* NOTE: OneAPI is not supported for ``zscalergov`` and ``zscalerten``. Use the Legacy API Framework for those clouds. See `Legacy API Authentication`_ below.

* NOTE: For OneAPI: The ``cloud`` parameter or ``ZSCALER_CLOUD`` env var is optional. Omit for production. Set to ``beta`` only when authenticating to the beta environment. Legacy cloud names (zscalerone, zscalertwo, etc.) must not be used with OneAPI—they would break the API URL.

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

Use Legacy authentication when your tenant is not on Zidentity, or for ``zscalergov`` and ``zscalerten`` clouds. You must set ``use_legacy_client: true`` (or ``ZSCALER_USE_LEGACY_CLIENT=true``) and provide ``username``, ``password``, ``api_key``, and ``cloud``. The ``cloud`` parameter is required.

The ZIA Ansible Collection supports the following cloud environments for Legacy:

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

