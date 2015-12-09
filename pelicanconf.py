#!/usr/bin/env python
# -*- coding: utf-8 -*- #
from __future__ import unicode_literals

AUTHOR = 'ge0n0sis'
SITENAME = 'ge0n0sis.github.io'
SITEURL = ''

PATH = 'content'

TIMEZONE = 'Europe/Paris'

DEFAULT_LANG = 'en'

# Plugins
PLUGIN_PATHS = ['plugins']
PLUGINS = ['pelican-toc']

# Static content
STATIC_PATHS = ['static']

# Theme
THEME = 'themes/pelican-twitchy'
PYGMENTS_STYLE = 'github'

# Feed generation is usually not desired when developing
FEED_ALL_ATOM = None
CATEGORY_FEED_ATOM = None
TRANSLATION_FEED_ATOM = None
AUTHOR_FEED_ATOM = None
AUTHOR_FEED_RSS = None

# Article generation
ARTICLE_URL = 'posts/{date:%Y}/{date:%m}/{slug}/'
ARTICLE_SAVE_AS = 'posts/{date:%Y}/{date:%m}/{slug}/index.html'

# Social widget
SOCIAL = [
    ('Github', 'https://github.com/ge0n0sis'),
    ('Twitter', 'https://twitter.com/ge0n0sis'),
]

DEFAULT_PAGINATION = 10

# Uncomment following line if you want document-relative URLs when developing
# RELATIVE_URLS = True
