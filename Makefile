# Taken from: https://github.com/sensu/sensu-go-ansible/blob/master/Makefile
COLOR_OK=\\x1b[0;32m
COLOR_NONE=\x1b[0m
COLOR_ERROR=\x1b[31;01m
COLOR_WARNING=\x1b[33;01m
COLOR_ZSCALER=\x1B[34;01m

VERSION=$(shell grep -E -o '(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?' ./plugins/module_utils/version.py)

help:
	@echo "$(COLOR_ZSCALER)"
	@echo "  ______              _           "
	@echo " |___  /             | |          "
	@echo "    / / ___  ___ __ _| | ___ _ __ "
	@echo "   / / / __|/ __/ _\` | |/ _ \ '__|"
	@echo "  / /__\__ \ (_| (_| | |  __/ |   "
	@echo " /_____|___/\___\__,_|_|\___|_|   "
	@echo "                                  "
	@echo "                                  "
	@echo "$(COLOR_NONE)"
	@echo "$(COLOR_OK)ZIA Ansible Collection$(COLOR_NONE) version $(COLOR_WARNING)$(VERSION)$(COLOR_NONE)"
	@echo ""
	@echo "$(COLOR_WARNING)Usage:$(COLOR_NONE)"
	@echo "$(COLOR_OK)  make [command]$(COLOR_NONE)"
	@echo ""
	@echo "$(COLOR_WARNING)Available commands:$(COLOR_NONE)"
	@echo "$(COLOR_OK)  help$(COLOR_NONE)           Show this help message"
	@echo "$(COLOR_WARNING)clean$(COLOR_NONE)"
	@echo "$(COLOR_OK)  clean                      	Remove all auto-generated files$(COLOR_NONE)"
	@echo "$(COLOR_WARNING)development$(COLOR_NONE)"
	@echo "$(COLOR_OK)  check-format               	Check code format/style with black$(COLOR_NONE)"
	@echo "$(COLOR_OK)  format                     	Reformat code with black$(COLOR_NONE)"
	@echo "$(COLOR_OK)  docs                       	Build collection documentation$(COLOR_NONE)"
	@echo "$(COLOR_OK)  reqs                       	Recreate the requirements.txt file$(COLOR_NONE)"
	@echo "$(COLOR_WARNING)test$(COLOR_NONE)"
	@echo "$(COLOR_OK)  test:integration:zia          Execute the full integration test suite$(COLOR_NONE)"
	@echo "$(COLOR_OK)  old-sanity          		Sanity tests for Ansible v2.9 and Ansible v2.10$(COLOR_NONE)"
	@echo "$(COLOR_OK)  new-sanity          	        Sanity tests for Ansible v2.11 and above$(COLOR_NONE)"

# Make sure we have ansible_collections/zscaler/ziacloud_enhanced
# as a prefix. This is ugly as heck, but it works. I suggest all future
# developer to treat next few lines as an opportunity to learn a thing or two
# about GNU make ;)
collection := $(notdir $(realpath $(CURDIR)      ))
namespace  := $(notdir $(realpath $(CURDIR)/..   ))
toplevel   := $(notdir $(realpath $(CURDIR)/../..))

err_msg := Place collection at <WHATEVER>/ansible_collections/zscaler/ziacloud
ifneq (ziacloud,$(collection))
  $(error $(err_msg))
else ifneq (zscaler,$(namespace))
  $(error $(err_msg))
else ifneq (ansible_collections,$(toplevel))
  $(error $(err_msg))
endif

python_version := $(shell \
  python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))' \
)

.PHONY: docs
docs:		## Build collection documentation
	rm -rf antsibull
	mkdir antsibull
	poetry add sphinx_ansible_theme
	poetry run antsibull-docs collection --use-current --dest-dir antsibull --no-indexes zscaler.ziacloud
	mkdir -p docs/source/modules
	mv antsibull/collections/zscaler/ziacloud/* docs/source/modules
	rm -rf antsibull
	rm -f docs/source/modules/index.rst
	cd docs && sphinx-build source html

.PHONY: clean
clean:		## Remove all auto-generated files
	rm -rf tests/output
	rm -rf *.tar.gz

.PHONY: format
format:		## Format with black
	black .

.PHONY: check-format
check-format:	## Check with black
	black --check --diff .

test\:integration\:zia:
	@echo "$(COLOR_ZSCALER)Running zia integration tests...$(COLOR_NONE)"
	ansible-playbook tests/integration/run_all_tests.yml


.PHONY: old-sanity
old-sanity:		## Sanity tests for Ansible v2.9 and Ansible v2.10
	ansible-test sanity -v --skip-test pylint --skip-test rstcheck --python $(python_version)

.PHONY: new-sanity
new-sanity:		## Sanity tests for Ansible v2.11 and above
	ansible-test sanity -v --skip-test pylint --python $(python_version)

.PHONY: reqs
reqs:       ## Recreate the requirements.txt file
	poetry export -f requirements.txt --output requirements.txt

install:
	cp -R /Users/wguilherme/ansible_collections/zscaler/zpacloud /Users/wguilherme/.pyenv/versions/3.11.0/lib/python3.11/site-packages/ansible_collections/zscaler
	rm -f zscaler*
	pip3 install -r requirements.txt
	ansible-galaxy collection build . --force
	ansible-galaxy collection install zscaler* --force
	rm -f zscaler*

.PHONY: clean-pyc clean-build docs clean local-setup
