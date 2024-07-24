.. _common_return_values:

Common Return Values
--------------------
This section details the common return values that are applicable across multiple modules in the Zscaler Internet Access Ansible Collection. These values are standardized to provide a consistent output structure for ease of automation and integration.

.. list-table::
   :header-rows: 1

   * - Key
     - Description
     - Returned
     - Type
     - Sample
   * - changed
     - Indicates if any changes were made.
     - always
     - bool
     - true
   * - failed
     - Indicates if the operation failed.
     - on failure
     - bool
     - false
