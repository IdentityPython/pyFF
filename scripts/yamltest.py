#!/usr/bin/env python
import sys

import yaml

with open(sys.argv[1]) as fd:
    print(yaml.safe_load(fd))
