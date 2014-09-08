#!/usr/bin/env python
import yaml
import sys

with open(sys.argv[1]) as fd:
    print yaml.safe_load(fd)
