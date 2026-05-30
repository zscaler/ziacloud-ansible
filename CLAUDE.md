# CLAUDE.md

Guidance for AI coding agents (Claude, Cursor, etc.) working in the
`zscaler.ziacloud` Ansible Collection. Read this before adding or modifying
modules, and follow the existing conventions exactly.

## What this repository is

- An Ansible Collection (`zscaler.ziacloud`) that manages **Zscaler Internet
  Access (ZIA)** resources.
- It is a thin automation layer on top of the dedicated **Zscaler Python SDK**
  (`zscaler-sdk-python`, published on PyPI). The SDK source lives locally at
  `http://github.com/zscaler/zscaler-sdk-python`. All API calls go through the
  SDK; modules never call the REST API directly.
- Collection version is kept in sync in two places: `galaxy.yml` and
  `plugins/module_utils/version.py`.

## Repository layout

| Path | Purpose |
|------|---------|
| `plugins/modules/zia_<resource>.py` | Mutating (CRUD / settings) modules |
| `plugins/modules/zia_<resource>_info.py` | Read-only info modules |
| `plugins/module_utils/zia_client.py` | `ZIAClientHelper` auth wrapper + `zia_argument_spec()` |
| `plugins/module_utils/utils.py` | Shared helpers (`deleteNone`, `normalize_list`, `collect_all_items`, validators) |
| `plugins/module_utils/version.py` | Collection version string |
| `plugins/doc_fragments/fragments.py` | Shared `DOCUMENTATION` fragments (`provider`, `documentation`, `state`, ...) |
| `tests/unit/plugins/modules/test_zia_<resource>.py` | pytest unit tests (1:1 with each module) |
| `tests/unit/plugins/modules/common/utils.py` | Test helpers: `set_module_args`, `ModuleTestCase`, `AnsibleExitJson/FailJson`, `DEFAULT_PROVIDER` |
| `tests/sanity/ignore-2.1X.txt` | `ansible-test sanity` ignore entries (one per Ansible version) |
| `tests/integration/targets/zia_<resource>/` | Optional live integration tests |

## Naming conventions (MUST follow)

- Module file name: `zia_<resource>.py` (CRUD) and `zia_<resource>_info.py` (info).
- FQCN: `zscaler.ziacloud.zia_<resource>`.
- Unit test file: `tests/unit/plugins/modules/test_zia_<resource>.py`.
- Each new module **MUST** have a matching unit test file and sanity ignore
  entries in **all** `tests/sanity/ignore-2.1X.txt` files.

## Module anatomy (copy this skeleton)

1. `#!/usr/bin/python` + `# -*- coding: utf-8 -*-` + the MIT license header
   (copy verbatim from an existing module).
2. `from __future__ import absolute_import, division, print_function` and
   `__metaclass__ = type`.
3. `DOCUMENTATION`, `EXAMPLES`, `RETURN` as `r"""..."""` raw strings.
   - `author: - William Guilherme (@willguibr)`
   - `version_added: "<next version>"`
   - `extends_documentation_fragment:` with
     `zscaler.ziacloud.fragments.provider`,
     `zscaler.ziacloud.fragments.documentation`, and (CRUD only)
     `zscaler.ziacloud.fragments.state`.
4. Imports: `from traceback import format_exc`, `to_native`, `AnsibleModule`,
   and `ZIAClientHelper`.
5. A `core(module)` function with the business logic.
6. A `main()` function that builds
   `argument_spec = ZIAClientHelper.zia_argument_spec()`, `.update(...)`s the
   resource-specific params, constructs `AnsibleModule(... supports_check_mode=True)`,
   and wraps `core(module)` in `try/except` that calls
   `module.fail_json(msg=to_native(e), exception=format_exc())`.

## SDK usage rules

- Create the client once per run: `client = ZIAClientHelper(module)`.
- `ZIAClientHelper.__getattr__` delegates to `self._client.zia.<service>`, so a
  module calls `client.<service>.<method>(...)` (e.g.
  `client.rule_labels.list_labels()`, `client.secure_browsing.get_browser_control_settings()`).
- **Every** SDK method (except a few file exports) returns a 3-tuple:
  `result, _unused, error = client.<service>.<method>(...)`.
  - Always check `error` first and `module.fail_json(...)` with a clear message.
  - `result` is an SDK model object exposing `.as_dict()`; convert before
    returning to Ansible.
- When the SDK migrates a resource to a new service module, update the service
  accessor name only (e.g. `client.browser_control_settings` ->
  `client.secure_browsing`). The method names usually stay the same.

## Idempotency, check mode, and return values

- Info modules: always `module.exit_json(changed=False, ...)`,
  `supports_check_mode=True`, and use `mutually_exclusive=[["name", "id"]]`
  when they accept both.
- CRUD modules:
  - Look up the existing resource by `id` (preferred) else by `name`.
  - Build a normalized desired vs. existing dict (drop computed/read-only fields
    such as `last_modified_*`, `created_by`, counters). Use `module.warn(...)`
    on each detected difference.
  - Honor `module.check_mode`: exit early with the correct `changed` value and
    perform **no** API writes.
  - `state=present`: create when absent, update when different, no-op when equal.
  - `state=absent`: delete when present, no-op when absent.
  - Singleton/settings resources cannot be deleted: `state=absent` is a no-op
    that returns the current settings with `changed=False`.

## Validation & cross-field requirements

- Use `required_if`, `mutually_exclusive`, `required_together` on the
  `AnsibleModule` when fields are interdependent (e.g. enabling a feature
  requires a profile). Prefer declarative `required_if` over manual checks.
- Use the validators in `plugins/module_utils/utils.py` (country codes,
  IP ranges, locales) instead of re-implementing them.

## Client-side filtering for flat-list info modules

Some ZIA endpoints return a flat list with no server-side query parameters
(e.g. supported browser versions). For these:

- Prefer simple, explicit filter parameters (e.g. `browser_type`, `versions`)
  combined with logical AND, applied client-side after the SDK call.
- For advanced filtering/projection, expose an optional `query` parameter and
  evaluate it with `filter_by_jmespath(data, expression)` from
  `plugins/module_utils/utils.py` (guarded `jmespath` import; raises
  `ValueError` on a bad expression). Apply `query` last, to the already
  filtered list, and `module.fail_json` on `ImportError`/`ValueError`. This
  mirrors the JMESPath client-side filtering the SDK itself documents.
- See `zia_browser_control_supported_versions_info.py` for the reference
  implementation.

## Testing (imperative — never skip)

For every module you add or change:

1. **Unit tests** in `tests/unit/plugins/modules/test_zia_<resource>.py`.
   - Subclass `ModuleTestCase`, patch
     `ansible_collections.zscaler.ziacloud.plugins.modules.zia_<resource>.ZIAClientHelper`
     in a `mock_client` fixture, and set
     `mock_class.zia_argument_spec.return_value` to a copy of the real spec
     updated with the module params.
   - Mock SDK methods to return `(MockBox({...}), None, None)` or
     `(None, None, "error")`. `MockBox` exposes `.as_dict()`.
   - Inject args via `set_module_args(provider=DEFAULT_PROVIDER, ...)` and assert
     with `pytest.raises(AnsibleExitJson)` / `AnsibleFailJson`.
   - Cover: create, update, delete, no-op/idempotent, check mode, and error
     paths.
   - Run: `poetry run pytest tests/unit/plugins/modules/test_zia_<resource>.py -q`.
2. **Sanity**: add the module to **every** `tests/sanity/ignore-2.1X.txt` with
   `plugins/modules/zia_<resource>.py validate-modules:missing-gplv3-license`
   (this collection is MIT-licensed). Run `make new-sanity`.
3. **Lint/format**: `make format` (black) and `make check-format` must pass.
   The full unit suite runs via `poetry run pytest tests/unit/`.

## Commands

```bash
make format          # black .
make check-format    # black --check --diff .
make new-sanity      # ansible-test sanity (Ansible >= 2.11)
poetry run pytest tests/unit/   # full unit suite
make docs            # build collection docs
```

## Do / Don't

- DO mirror an existing, similar module rather than inventing new structure.
- DO keep `galaxy.yml` and `version.py` versions in sync.
- DON'T call the REST API directly or add new HTTP clients — go through the SDK.
- DON'T add narrating code comments; comments explain non-obvious intent only.
- DON'T add a CRUD/info module without its unit test and sanity ignore entries.
