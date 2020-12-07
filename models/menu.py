# -*- coding: utf-8 -*-
# this file is released under public domain and you can use without limitations

# ----------------------------------------------------------------------------------------------------------------------
# this is the main application menu add/remove items as required
# ----------------------------------------------------------------------------------------------------------------------
response.menu = [
    (T('Home'), False, URL('default', 'index'), []),
    (T('HTTP Analysis'), False, '#', [
        (T('Web APP'), False, URL('proxy', 'webApp')),
        (T('HTTP Proxy'), False, URL('proxy', 'httpProxy')),
        (T('HTTP Analysis'), False, URL('proxy', 'httpAnalysis')),
        (T('Static Analysis'), False, URL('proxy', 'staticAnalysis')),
    ]),
    (T('License'), False, URL('default', 'license'), []),
]

