#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-

from __future__ import print_function, unicode_literals

import base64
import hashlib
import hmac
import json
import os, os.path
import sys
import re
import time
from pprint import pprint, pformat

from Crypto.Cipher.AES import AESCipher
from github import Github

order = 'desc'
order_by = 'stat'
show_summary = True
skip_forked = True
skip_repos = []
verbose = False

login = sys.argv[1]
password = sys.argv[2] if len(sys.argv) > 2 else None
CACHE_TIME = 3600
CACHE_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cache')
KEY = 'JKHghyY^&*iujhgft65R%^$ertfghbHJ'

def _aes_pad(data):
    data = str(data)
    l = len(data)
    if l % 16 == 0:
        return data
    data += chr(0) * (16 - l % 16)
    return data

_aes = AESCipher(_aes_pad(KEY))

def aes_encrypt(msg, key=None):
    msg = _aes_pad(msg)

    global _aes
    if key is not None:
        _aes_local = AESCipher(key)
        ret = _aes_local.encrypt(msg)
    else:
        ret = _aes.encrypt(msg)

    ret = base64.b64encode(ret)
    return ret

def aes_decrypt(msg, key=None):
    msg = base64.b64decode(msg)

    global _aes
    if key is not None:
        _aes_local = AESCipher(key)
        ret = _aes_local.decrypt(msg)
    else:
        ret = _aes.decrypt(msg)

    return ret.rstrip(chr(0))

cache_file = hmac.new(str(KEY), login, hashlib.sha1).hexdigest() + '.json'
cache_file = os.path.join(CACHE_ROOT, cache_file)
cache = None
if os.path.isfile(cache_file):
    try:
        with open(cache_file, 'r') as fh:
            cache = json.load(fh)
    except ValueError:
        cache = None

if cache:
    if cache['ts'] > time.time() - CACHE_TIME:
        stats = cache
    else:
        if not login:
            login = aes_decrypt(cache['login'])
        if not password:
            password = aes_decrypt(cache['password'])
        cache = None

if cache:
    stats = cache
else:
    gh = Github(login, password, user_agent='github-profile-stats/0.1')
    stats = {}
    for repo in gh.get_user(login).get_repos():
        if skip_forked and repo.fork:
            continue

        if repo.name in skip_repos:
            continue

        langs = repo.get_languages()
        for lang, bytes_ in langs.items():
            try:
                stats[lang.lower()] += bytes_
            except KeyError:
                stats[lang.lower()] = bytes_

    stats = {'stats': stats}
    stats['ts'] = time.time()
    stats['login'] = aes_encrypt(login)
    stats['password'] = aes_encrypt(password)
    print(stats)
    with open(cache_file, 'w') as fh:
        json.dump(stats, fh)

# stats = {u'stats': {u'shell': 67, u'python': 195425, u'javascript': 3219, u'viml': 143671, u'perl': 125968, u'php': 1848501}, u'ts': time.time()}
bytes_sum = sum(stats['stats'].values())
one_perc = float(bytes_sum / 100)

items = []
most = {'lang': '', 'bytes': 0}
for lang, bytes_ in stats['stats'].items():
    if bytes_ > most['bytes']:
        most['lang'] = lang
        most['bytes'] = bytes_

    items.append({ 'lang': lang, 'bytes': bytes_, 'stat': (float(bytes_) / float(one_perc)) })

items.sort(key = lambda item: item[order_by], reverse=order == 'desc')
for item in items:
    print('%(lang)s: %(stat)0.1f%%' % item, end='')
    if verbose:
        print(' (%db of %db)' % (item['bytes'], bytes_sum), end='')
    print()

if show_summary:
    print()
    print('You are a %s guy!' % most['lang'].upper())
