#!/usr/bin/env python
import yaml,sys

with open(sys.argv[1]) as fd:
   print yaml.safe_load(fd)
