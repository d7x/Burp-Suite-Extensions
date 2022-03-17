''' This is the example from the Burp Suite Essentials book by Akash Mahajan '''

# All extensions need to import IBurpExtender
from burp import IBurpExtender

# This will allow us to start a HTT PListener
from burp import IHttpListener

# This will allow uus to retrieve and update details about HTTP messages.
from burp import IHttpRequestResponse

# The following two will allow us to get more details about requests and responses
from burp import IRequestInfo
from burp import IResponseInfo

# Basic debugging by printing to standart output
from java.io import PrintWriter

class BurpExtender(IBurpExtender, IHttpListener, IHttpRequestResponse,IRequestInfo):

    def registerExtenderCallbacks(self, callbacks):
        # This function is required to setu pcallbacks and get access to helper functions.
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # This is where you name your extension. 
        # This name will show under Extensions | Burp Extensions when loaded.
        callbacks.setExtensionName("My first Burp extension")

        self._stdout = PrintWriter(callbacks.getStdout(), True)

        callbacks.registerHttpListener(self)

        # This will get printed once the extension is loaded without any errors
        self._stdout.println("Hello, Burp Extension World!")

        return

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # This function is where all the work hapens for us. 

        # We want to ensure that we are working with a request to begin with. 
        if messageIsRequest:
            requestInfo = self._helpers.analyzeRequest(messageInfo)

            # We are interested in finding out when a HTTP POST request is made. 
            if requestInfo.getMethod() == "POST":
                # Once we have determined that an HTTP POST request was made, we want to enumerate the headers. 
                headers = requestInfo.getHeaders()

                # Use the next line for debugging, if required. 
                #self._stdout.println("Printing Request")

                # We are trying to ffind the header Content-Type and then search for a form that has upload capabilities
                for header in headers:
                    if header.startswith("Content-Type:") and "multipart/form-data" in header:
                        # This comment will be useful for us later when we look for all kinds of requests.
                        messageInfo.setComment("File Upload detected and this comment was created by an extension.")

                        # Print all the headers
                        self._stdout.println(header)
                    else:
                        # Since we didn't get a request, we will look at responses. 
                        responseInfo = self._helpers.analyzeRespponse(self._helpers.bytesToString(messageInfo.getResponse()))

                        # Many times, we figure out next steps based on the status code of the respopnse. 
                        self._stdout.println(responseInfo.getStatusCode())

        # your extension code here
           
        return

