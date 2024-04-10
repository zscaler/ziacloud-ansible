#!/usr/bin/env bash

ansible-galaxy collection build
ansible-galaxy collection publish zscaler-ziacloud-* --server release_galaxy
ansible-galaxy collection publish zscaler-ziacloud-* --server automation_hub