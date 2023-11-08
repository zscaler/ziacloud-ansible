#!/usr/bin/env python

# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# Copyright (c) 2023 Zscaler Business Development, <zscaler-partner-labs@z-bd.com>
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import re
import time

from ansible.module_utils.basic import env_fallback


def obfuscate_api_key(seed):
    now = int(time.time() * 1000)
    n = str(now)[-6:]
    r = str(int(n) >> 1).zfill(6)
    key = "".join(seed[int(str(n)[i])] for i in range(len(str(n))))
    for j in range(len(str(r))):
        key += seed[int(str(r)[j]) + 2]

    return {"timestamp": now, "key": key}


def delete_none(f):
    """
    This decorator should be used on functions that return an object to delete empty fields
    """

    def wrapper(*args):
        _dict = f(*args)
        if _dict is not None:
            return deleteNone(_dict)
        return _dict

    return wrapper


def deleteNone(_dict):
    """Delete None values recursively from all of the dictionaries, tuples, lists, sets"""
    if isinstance(_dict, dict):
        for key, value in list(_dict.items()):
            if isinstance(value, (list, dict, tuple, set)):
                _dict[key] = deleteNone(value)
            elif value is None or key is None:
                del _dict[key]
    elif isinstance(_dict, (list, set, tuple)):
        _dict = type(_dict)(deleteNone(item) for item in _dict if item is not None)
    return _dict


def camelcaseToSnakeCase(obj):
    new_obj = dict()
    for key, value in obj.items():
        if value is not None:
            new_obj[re.sub(r"(?<!^)(?=[A-Z])", "_", key).lower()] = value
    return new_obj


def snakecaseToCamelcase(obj):
    new_obj = dict()
    for key, value in obj.items():
        if value is not None:
            newKey = "".join(x.capitalize() or "_" for x in key.split("_"))
            newKey = newKey[:1].lower() + newKey[1:]
            new_obj[newKey] = value
    return new_obj


def zia_argument_spec():
    return dict(
        username=dict(
            no_log=True,
            fallback=(
                env_fallback,
                ["ZIA_USERNAME"],
            ),
        ),
        password=dict(
            no_log=True,
            fallback=(
                env_fallback,
                ["ZIA_PASSWORD"],
            ),
        ),
        api_key=dict(
            no_log=True,
            fallback=(
                env_fallback,
                ["ZIA_API_KEY"],
            ),
        ),
        base_url=dict(
            no_log=True,
            fallback=(
                env_fallback,
                ["ZIA_BASE_URL"],
            ),
        ),
        sandbox_token=dict(
            no_log=True,
            fallback=(
                env_fallback,
                ["ZIA_SANDBOX_TOKEN"],
            ),
        ),
    )


__version__ = "1.4.1"
