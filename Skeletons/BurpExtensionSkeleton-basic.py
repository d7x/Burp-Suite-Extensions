# All extensions need to import IBurpExtender
from burp import IBurpExtender

# This will allow us to start a HTT PListener
from burp import IHttpListener

# This will allow uus to retrieve and update details about HTTP messages.
from burp impport IHttpRequestResponse

# The following two will allow us to get more details about requests and responses
from burp import IRequestInfo
from burp import IResponseInfo

# Basic debugging by printing to standart output
from java.io import PrintWriter

class BurpExtender(IBurpExtender, IHttpListener,IhttpRequestResponse,IRequestInfo):

    def registerExtenderCallbacks(self, callbacks):
       
        # your extension code here
       
        return

