import os
import sys
#appName = 'httpProxy'
appName = request.application

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
    rContent = flow.response.content
    if str(rFlow['rsHeaders']).find('image')<0:
        flowFile(rFlow, rContent)

def flowFile(rFlow, rContent):
    #-------------------------------------------
    #rFlow contains HTTP parameters, headers,...
    #rContent contains response BODY
    #-------------------------------------------
    f = os.path.join(os.getcwd(),'applications/' + str(appName) + '/modules/flowContent/')
    flowDetails = open(str(f)+'flowDetails.txt','a')
    flowDetails.write(str(rFlow))
    flowDetails.write('\n')
    flowDetails.close()
    c = open(str(f)+ str(rFlow['idRequest']), 'w')
    c.write(str(rContent))
    c.close()
