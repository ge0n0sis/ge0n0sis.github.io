#!/usr/bin/env python
# -*- coding: utf-8 -*- #
from __future__ import unicode_literals

# This file is only used if you use `make publish` or
# explicitly specify it as your config file.

import os
import sys
sys.path.append(os.curdir)
from pelicanconf import *  # nopep8

SITEURL = 'https://ge0n0sis.github.io'
RELATIVE_URLS = False

FEED_ALL_ATOM = 'feeds/all.atom.xml'
CATEGORY_FEED_ATOM = 'feeds/%s.atom.xml'

DELETE_OUTPUT_DIRECTORY = True

# Social widget
SOCIAL.extend([
    ('RSS', 'https://ge0n0sis.github.io/' + FEED_ALL_ATOM),
])

# Following items are often useful when publishing

DISQUS_SITENAME  = 'ge0n0sis.disqus.com'
GOOGLE_ANALYTICS = 'UA-71641668-1'
