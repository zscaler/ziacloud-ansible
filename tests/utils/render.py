#!/usr/bin/env python

from __future__ import absolute_import, division, print_function

__metaclass__ = type


import os

# Get environment variables
username = os.getenv("ZIA_USERNAME")
password = os.getenv("ZIA_PASSWORD")
api_key = os.getenv("ZIA_API_KEY")
base_url = os.getenv("ZIA_BASE_URL")

content = """
---
username: %s
password: %s
api_key: %s
base_url: %s

""" % (
    username,
    password,
    api_key,
    base_url,
)

f = open("./tests/integration/integration_config.yml", "w")
f.write(content)
f.close()
