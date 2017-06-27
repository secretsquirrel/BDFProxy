#!/usr/bin/env python

# Authors:
# P. Thierry

import os
import os.path

from distutils.core import setup

setup(
    name="bdfproxy",
    author="Josh Pitts",
    description="Backdoring binaries as they are downloaded",
    license="BSD-3-clause",
    url="https://github.com/secretsquirrel/bdfproxy",
    scripts=[ "bdf_proxy.py" ],
    data_files=[
        ('/etc/bdfproxy', ['bdfproxy.cfg']),
    ],
)
