.. ...........................................................................
.. © Copyright Zscaler Inc, 2024                                             .
.. ...........................................................................

==========================
Activation Overview
==========================

Who Controls When Changes Are Activated?
----------------------------------------

**Activation timing is controlled by the ZIA platform, not by the Ansible collection.** When Ansible (or any API client) creates or updates configuration, ZIA saves those changes into a pending state. Those changes do not take effect for traffic until they are *activated*. The collection cannot override this native platform behavior.

Activation can happen in three ways:

1. **Explicit activation** — You activate after your playbook run using the ``zia_activation_status`` module or via the ZIA Admin UI.
2. **Auto-activation by ZIA** — The platform may activate pending changes automatically after a period of inactivity (e.g. ~15–30 minutes, configurable in Advanced Settings) or when an admin logs out. This applies to all API-based changes, including Ansible.
3. **In-playbook activation** — Add the ``zia_activation_status`` module as a final task in your playbook so activation runs after your configuration tasks complete.

If you do not explicitly activate and do not use an in-playbook activation task, your changes may still go live when ZIA auto-activates. That is expected ZIA behavior. To avoid surprises, use the ``zia_activation_status`` module in your playbook or push changes in a controlled fashion when you intend them to take effect.

For the official Zscaler explanation of saving and activating changes (including in the Admin UI), see `Saving and Activating Changes (Admin Console) <https://help.zscaler.com/unified/saving-and-activating-changes-admin-console>`_.

Activation Options with the Ansible Collection
----------------------------------------------

The collection supports the following ways to activate changes:

| Method | Description |
|--------|-------------|
| **``zia_activation_status`` module** | Add the module as the last task (or a dedicated play) in your playbook. It activates pending changes after your configuration tasks succeed. See :doc:`examples` for usage. |
| **ZIA Admin UI** | After running your playbook, log into the ZIA Admin Console and activate changes manually when ready. |

.. note::
   The ZIA platform has its own auto-activation behavior, independent of the Ansible collection. Pending changes may be activated automatically when: (1) the session has been inactive for a configurable period (e.g. 30 minutes, see Advanced Settings), or (2) an admin logs out. This applies to all API-based changes, including Ansible. If you do not want changes to go live until you decide, use the ``zia_activation_status`` module and run it only when you are ready, or push changes only when you intend them to take effect.

Example: Activate After Configuration
-------------------------------------

.. code-block:: yaml

   - name: Apply ZIA configuration and activate
     hosts: localhost
     gather_facts: false

     tasks:
       - name: Create or update firewall rule
         zscaler.ziacloud.zia_cloud_firewall_rule:
           provider: "{{ zia_cloud }}"
           name: "Example Rule"
           # ... other parameters ...

       - name: Activate ZIA configuration
         zscaler.ziacloud.zia_activation_status:
           provider: "{{ zia_cloud }}"
           status: ACTIVE

FAQ: "A change was pushed without us activating it"
---------------------------------------------------

If you see configuration take effect even though you did not run an explicit activation step, that is normal ZIA behavior. The platform can activate pending changes automatically (inactivity timeout or logout). The Ansible collection does not control when ZIA activates; it only writes configuration. To avoid unintended activation:

- Use the **``zia_activation_status``** module in your playbook and run it only when you are ready for changes to go live, or
- Rely on **ZIA Admin UI** to activate manually when you choose.

The collection cannot override ZIA's native behavior. For the platform's own description of save vs. activate behavior, see `Zscaler Help: Saving and Activating Changes <https://help.zscaler.com/unified/saving-and-activating-changes-admin-console>`_.