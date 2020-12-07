"""
This inline script allows conditional TLS Interception based
on a user-defined strategy.

Example:

    > mitmdump -s tls_passthrough.py

    1. curl --proxy http://localhost:8080 https://example.com --insecure
    // works - we'll also see the contents in mitmproxy

    2. curl --proxy http://localhost:8080 https://example.com --insecure
    // still works - we'll also see the contents in mitmproxy

    3. curl --proxy http://localhost:8080 https://example.com
    // fails with a certificate error, which we will also see in mitmproxy

    4. curl --proxy http://localhost:8080 https://example.com
    // works again, but mitmproxy does not intercept and we do *not* see the contents

Authors: Maximilian Hils, Matthew Tuusberg
"""
import collections
import random
from enum import Enum

import mitmproxy
from mitmproxy import ctx
from mitmproxy.exceptions import TlsProtocolException
from mitmproxy.proxy.protocol import TlsLayer, RawTCPLayer
import os
import sys

#We get the app name by an argument
#sys.argv[7] --> --ssl-insecure
print (len(sys.argv))
if len(sys.argv) == 7:
    appName = sys.argv[6]
    print (appName)
    print (str(sys.argv))
#else:
elif len(sys.argv) == 6:
    appName = sys.argv[5]
    print (appName)
    print (str(sys.argv))
pass

class InterceptionResult(Enum):
    success = True
    failure = False
    skipped = None


class _TlsStrategy:
    """
    Abstract base class for interception strategies.
    """

    def __init__(self):
        # A server_address -> interception results mapping
        self.history = collections.defaultdict(lambda: collections.deque(maxlen=200))

    def should_intercept(self, server_address):
        """
        Returns:
            True, if we should attempt to intercept the connection.
            False, if we want to employ pass-through instead.
        """
        raise NotImplementedError()

    def record_success(self, server_address):
        self.history[server_address].append(InterceptionResult.success)

    def record_failure(self, server_address):
        self.history[server_address].append(InterceptionResult.failure)

    def record_skipped(self, server_address):
        self.history[server_address].append(InterceptionResult.skipped)


class ConservativeStrategy(_TlsStrategy):
    """
    Conservative Interception Strategy - only intercept if there haven't been any failed attempts
    in the history.
    """

    def should_intercept(self, server_address):
        if InterceptionResult.failure in self.history[server_address]:
            return False
        return True


class ProbabilisticStrategy(_TlsStrategy):
    """
    Fixed probability that we intercept a given connection.
    """

    def __init__(self, p):
        self.p = p
        super(ProbabilisticStrategy, self).__init__()

    def should_intercept(self, server_address):
        return random.uniform(0, 1) < self.p


class TlsFeedback(TlsLayer):
    """
    Monkey-patch _establish_tls_with_client to get feedback if TLS could be established
    successfully on the client connection (which may fail due to cert pinning).
    """

    def _establish_tls_with_client(self):
        server_address = self.server_conn.address

        try:
            super(TlsFeedback, self)._establish_tls_with_client()
        except TlsProtocolException as e:
            tls_strategy.record_failure(server_address)
            raise e
        else:
            tls_strategy.record_success(server_address)


# inline script hooks below.

tls_strategy = None


def load(l):
    l.add_option(
        "tlsstrat", int, 0, "TLS passthrough strategy (0-100)",
    )


def configure(updated):
    global tls_strategy
    if ctx.options.tlsstrat > 0:
        tls_strategy = ProbabilisticStrategy(float(ctx.options.tlsstrat) / 100.0)
    else:
        tls_strategy = ConservativeStrategy()


def next_layer(next_layer):
    """
    This hook does the actual magic - if the next layer is planned to be a TLS layer,
    we check if we want to enter pass-through mode instead.
    """
    if isinstance(next_layer, TlsLayer) and next_layer._client_tls:
        server_address = next_layer.server_conn.address

        if tls_strategy.should_intercept(server_address):
            # We try to intercept.
            # Monkey-Patch the layer to get feedback from the TLSLayer if interception worked.
            next_layer.__class__ = TlsFeedback
        else:
            # We don't intercept - reply with a pass-through layer and add a "skipped" entry.
            mitmproxy.ctx.log("TLS passthrough for %s" % repr(next_layer.server_conn.address), "info")
            next_layer_replacement = RawTCPLayer(next_layer.ctx, ignore=True)
            next_layer.reply.send(next_layer_replacement)
            tls_strategy.record_skipped(server_address)

def response(flow):
    #------------------------------------------------
    #Mitmproxy to store HTTP session data
    #Data is stored in a html file and dict()
    #-------------------------------------------------
    rFlow = {}
    rContent = ''
    #-------------------------------------
    #Request dict()
    #idRequest dict match with html file 
    #-------------------------------------
    urlText = hash(flow.request.url)
    if urlText < 0:
        urlText += sys.maxsize
    rFlow['idRequest'] = urlText
    rFlow['rqMethod'] = flow.request.method
    rFlow['rqPath'] = flow.request.path
    rFlow['rqHttpVersion'] = flow.request.http_version
    rFlow['rqUrl'] = flow.request.url
    rFlow['rqCookies'] = flow.request.cookies.fields
    rFlow['rqHeaders'] = flow.request.headers
    rFlow['rqQuery'] = flow.request.query
    rFlow['rqBody'] = flow.request.content
    #-----------------------------
    #Responses dict()
    #-----------------------------
    rFlow['rsStatusCode'] = flow.response.status_code
    rFlow['rsStatusText'] = flow.response.reason
    rFlow['rsHttpVersion'] = flow.response.http_version
    rFlow['rsCookies'] = flow.response.cookies
    rFlow['rsHeaders'] = flow.response.headers
    #rFlow['rsContent'] = flow.response.content
    #rContent = str(flow.response.content).encode("utf8")
    #rContent = bytes(str(flow.response.content), 'utf8')
    rContent = flow.response.content
    if str(rFlow['rsHeaders']).find('image')<0:
        flowFile(rFlow, rContent)

def flowFile(rFlow, rContent):
    #-------------------------------------------
    #rFlow contains HTTP parameters, headers,...
    #rContent contains response BODY
    #-------------------------------------------
    f = os.path.join(os.getcwd(),'applications/' + str(appName) + '/modules/flowContent/')
    flowDetails = open( f + 'flowDetails.txt','a')
    flowDetails.write(str(rFlow))
    flowDetails.write('\n')
    flowDetails.close()
    c = open(f + str(rFlow['idRequest']), 'w')
    c.write(str(rContent))
    c.close()
