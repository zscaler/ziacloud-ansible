## [1.2.0](https://github.com/zscaler/ziacloud-ansible/compare/v1.1.0...v1.2.0) (2024-07-24)


### Features

* Added support to Ansible check_mode ([#40](https://github.com/zscaler/ziacloud-ansible/issues/40)) ([14373dd](https://github.com/zscaler/ziacloud-ansible/commit/14373dd809ef73ebd7914371c6950bd92ee0488a))

# Zscaler Internet Access (ZIA) Ansible Collection Changelog

## v1.2.0 (July, 22 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### BREAKING CHANGES

- [PR #270](https://github.com/zscaler/zscaler-sdk-go/pull/270) All resources previously named with `_facts` have been moved to `_info` to comply with Red Hat Ansible best practices as described in the following [Ansible Developer Documentation](https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_general.html#creating-an-info-or-a-facts-module)

### New Feature

- [PR #270](https://github.com/zscaler/zscaler-sdk-go/pull/270) All resources now support `check_mode` for simulation purposes and for validating configuration management playbooks

## v1.1.0 (June, 25 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Features

- Release v1.1.0 ([98727b7](https://github.com/zscaler/ziacloud-ansible/commit/98727b79f6fd0250e83996bf297db18fcf626cdd))
- **new:** Added Forwarding Control Rule Resource ([#37](https://github.com/zscaler/ziacloud-ansible/issues/37)) ([a0abe94](https://github.com/zscaler/ziacloud-ansible/commit/a0abe943d5cd4a5d76742f13c7e176df9929c4f8))

## v1.0.18 (May, 25 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Features

- Release v1.1.0 ([98727b7](https://github.com/zscaler/ziacloud-ansible/commit/98727b79f6fd0250e83996bf297db18fcf626cdd))
- **new:** Added Forwarding Control Rule Resource ([#37](https://github.com/zscaler/ziacloud-ansible/issues/37)) ([a0abe94](https://github.com/zscaler/ziacloud-ansible/commit/a0abe943d5cd4a5d76742f13c7e176df9929c4f8))

## v1.0.17 (May, 23 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Updated requirements.txt and documentation ([#34](https://github.com/zscaler/ziacloud-ansible/issues/34)) ([337f505](https://github.com/zscaler/ziacloud-ansible/commit/337f5055ed0e667c5143c031e50f38d2c40caff0))

## v1.0.16 (May, 04 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Fixed IP Destination and IP Source Group Drift ([#33](https://github.com/zscaler/ziacloud-ansible/issues/33)) ([2e9531b](https://github.com/zscaler/ziacloud-ansible/commit/2e9531b7a6584c4ab091e5f833e1f6c383ea5a81))

## v1.0.15 (May, 04 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Fixed zia authentication method schema ([#31](https://github.com/zscaler/ziacloud-ansible/issues/31)) ([271ce29](https://github.com/zscaler/ziacloud-ansible/commit/271ce29c308f6cfb101048f5197aff20fb0fdce1))

## v1.0.14 (April, 24 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Added collection version to user-agent header ([#30](https://github.com/zscaler/ziacloud-ansible/issues/30)) ([1fa5f3f](https://github.com/zscaler/ziacloud-ansible/commit/1fa5f3f9c44ecb05846a3263a4afe591a49bf2bb))

## v1.0.13 (April, 23 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Fixed release process for automation hub ([#27](https://github.com/zscaler/ziacloud-ansible/issues/27)) ([a067c69](https://github.com/zscaler/ziacloud-ansible/commit/a067c69e723bcd37c28437115cf734bc9c5e32ce))

## v1.0.12 (April, 23 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Removed Beta comment from README and fixed galaxy link on index ([e47696c](https://github.com/zscaler/ziacloud-ansible/commit/e47696cc8c4ea26e492547a76687dce8dcc71b2a))

## v1.0.11 (April, 23 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Removed Beta from README page ([658b30b](https://github.com/zscaler/ziacloud-ansible/commit/658b30baa1d1f6204de53c91aeb99f394788f79d))

## v1.0.10 (April, 23 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Fixed linter workflow and documentation ([45f0f98](https://github.com/zscaler/ziacloud-ansible/commit/45f0f98fe6e6eebfb83dab7775c847d845ede585))
- Fixed linter workflow and documentation ([093c9ad](https://github.com/zscaler/ziacloud-ansible/commit/093c9add9409b85d17c971346b61f8cd507604ae))

## v1.0.9 (April, 23 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Fixed makefile doc generation section ([26024a5](https://github.com/zscaler/ziacloud-ansible/commit/26024a5073e9b2338b1f656d4ceef54f0f2e131a))

## v1.0.8 (April, 23 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Fixed makefile doc generation section ([165756c](https://github.com/zscaler/ziacloud-ansible/commit/165756cdab765b556c0a82e4fb01f0612b96bc41))

## v1.0.7 (April, 23 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Removed poetry from release.yml doc generation ([e0feb95](https://github.com/zscaler/ziacloud-ansible/commit/e0feb95affb02877cb2c8471dae9137f56d20ccf))

## v1.0.6 (April, 23 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Fixed index.rst document ([dfef5dc](https://github.com/zscaler/ziacloud-ansible/commit/dfef5dc53b63c3aa7f04bfa9809fdbcc3c06472d))

## v1.0.5 (April, 23 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Fixed index.rst document ([ddf8eee](https://github.com/zscaler/ziacloud-ansible/commit/ddf8eee851c2e24af6383d39e6535d8e714e51c1))

## v1.0.4 (April, 23 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Temporarily disabled Automation Hub Workflow ([77ccd0d](https://github.com/zscaler/ziacloud-ansible/commit/77ccd0d306de88422f0718bdfa88c888c41e3042))

## v1.0.3 (April, 23 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Temporarily disabled Automation Hub Workflow ([e1a4b24](https://github.com/zscaler/ziacloud-ansible/commit/e1a4b24bb0a0d669073ce79cda7d197ea73c69f7))

## v1.0.2 (April, 23 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Temporarily disabled Automation Hub Workflow ([78b77bd](https://github.com/zscaler/ziacloud-ansible/commit/78b77bdb1c576306d2c130784a6956e28d8224d6))

## v1.0.1 (April, 23 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

### Bug Fixes

- Temporarily disabled Automation Hub Workflow ([66a363f](https://github.com/zscaler/ziacloud-ansible/commit/66a363fc3541ab8998f8bd2d0ab5acd2934f0665))

## v1.0.0 (April, 22 2024)

### Notes

- Python Versions: **v3.9, v3.10, v3.11**

## Initial Release v1.0.0

[Release Notes](https://github.com/zscaler/ziacloud-ansible/releases/tag/1.0.0)

- 🎉Initial Release🎉
