# -*- coding: utf-8 -*-
import os
import shutil
import subprocess
import signal
import base64
from datetime import datetime, date, time

demo = True

@auth.requires_login()
def webApp():
    #-------------------------------------------------------------------------------------
    if demo == False:
        if (auth.has_membership(role='admin') or auth.has_membership(role='riskManager')):
            pass
        else:
            redirect(URL('default','index'))
    #-------------------------------------------------------------------------------------
    form = SQLFORM.grid(db.webApp, searchable=True, create=True, editable=True, deletable=True, user_signature=True, paginate=10, maxtextlength=500)
    return dict(form=form)

@auth.requires_login()
def httpProxy():
    #-------------------------------------------------------------------------------------
    if demo == False:
        if (auth.has_membership(role='admin') or auth.has_membership(role='riskManager')):
            pass
        else:
            redirect(URL('default','index'))
    #-------------------------------------------------------------------------------------
    db.httpProxy.pidExec.writable = False
    db.httpProxy.proxyRun.writable = False
    fields = (db.httpProxy.webAppId, db.httpProxy.process, db.httpProxy.pidExec, db.httpProxy.portHttp, db.httpProxy.httpSsl, db.httpProxy.sslInsecure, db.httpProxy.proxyRun, db.httpProxy.keyWord)
    #links = [lambda row: A(T('START PROXY'),_class='button btn btn-success',_href=URL("proxy","httpProxyExec", args=[row.id, row.httpSsl, row.webAppId, row.portHttp, row.sslInsecure, row.proxyRun])), lambda row: A(T('STOP PROXY'),_class='button btn btn-danger',_href=URL("proxy","httpProxyStop", args=[row.id, row.pidExec])), lambda row: A(T('RESULTS'),_class='button btn btn-info',_href=URL("proxy","getResult", args=[row.id])), lambda row: A(T('STATIC ANALYSIS'),_class='button btn btn-warning',_href=URL("proxy","codeReview", args=[row.id, base64.b64encode(row.keyWord), row.webAppId] ))]

    #funciones: httpProxyExec, httpProxyStop, getResult, codeReview
    links = [lambda row: A(T('START PROXY'),_class='button btn btn-success',_href=URL("proxy","httpProxyExec", args=[row.id, row.httpSsl, row.webAppId, row.portHttp, row.sslInsecure, row.proxyRun])), lambda row: A(T('STOP PROXY'),_class='button btn btn-danger',_href=URL("proxy","httpProxyStop", args=[row.id, row.pidExec])), lambda row: A(T('RESULTS'),_class='button btn btn-info',_href=URL("proxy","getResult", args=[row.id])), lambda row: A(T('STATIC ANALYSIS'),_class='button btn btn-warning',_href=URL("proxy","codeReview", args=[row.id, base64.b64encode(row.keyWord) ] ))]

    form = SQLFORM.grid(db.httpProxy, fields=fields, links=links, searchable=True, create=True, editable=True, deletable=True, user_signature=True, paginate=10, maxtextlength=500)
    return dict(form=form)

@auth.requires_login()
def httpAnalysis():
    #-------------------------------------------------------------------------------------
    if demo == False:
        if (auth.has_membership(role='admin') or auth.has_membership(role='riskManager')):
            pass
        else:
            redirect(URL('default','index'))
    #-------------------------------------------------------------------------------------
    db.httpAnalysis.httpProxyId.writable = False
    db.httpAnalysis.idRequest.writable = False
    db.httpAnalysis.rqMethod.writable = False
    db.httpAnalysis.rqPath.writable = False
    db.httpAnalysis.rqHttpVersion.writable = False
    db.httpAnalysis.rqUrl.writable = False
    db.httpAnalysis.rqCookies.writable = False
    db.httpAnalysis.rqHeaders.writable = False
    db.httpAnalysis.rqQuery.writable = False
    db.httpAnalysis.rqBody.writable = False
    db.httpAnalysis.rsStatusCode.writable = False
    db.httpAnalysis.rsStatusText.writable = False
    db.httpAnalysis.rsHttpVersion.writable = False
    db.httpAnalysis.rsCookies.writable = False
    db.httpAnalysis.rsHeaders.writable = False
    db.httpAnalysis.rsContent.writable = False
    db.httpAnalysis.httpAnalysisDate.writable = False

    fields = (db.httpAnalysis.id, db.httpAnalysis.httpProxyId, db.httpAnalysis.rqUrl, db.httpAnalysis.rsContent, db.httpAnalysis.httpAnalysisDate, db.httpAnalysis.flagRequest)
    form = SQLFORM.grid(db.httpAnalysis, fields=fields, searchable=True, create=False, editable=True, deletable=True, user_signature=False, paginate=10, maxtextlength=100)
    return dict(form=form)

@auth.requires_login()
def staticAnalysis():
    #-------------------------------------------------------------------------------------
    if demo == False:
        if (auth.has_membership(role='admin') or auth.has_membership(role='riskManager')):
            pass
        else:
            redirect(URL('default','index'))
    #-------------------------------------------------------------------------------------
    db.staticAnalysis.httpProxyId.writable = False
    db.staticAnalysis.staticAnalysisKeyWords.writable = False
    db.staticAnalysis.staticAnalysisDate.writable = False
    db.staticAnalysis.staticAnalysisUrl.writable = False
    db.staticAnalysis.staticAnalysisLine.writable = False

    form = SQLFORM.grid(db.staticAnalysis, searchable=True, create=False, editable=True, deletable=True, user_signature=False, paginate=10, maxtextlength=50)
    return dict(form=form)

@auth.requires_login()
def httpProxyStop():
    #-------------------------------------------------------------------------------------
    if demo == False:
        if (auth.has_membership(role='admin') or auth.has_membership(role='riskManager')):
            pass
        else:
            redirect(URL('default','index'))
    #-------------------------------------------------------------------------------------
    try:
        #subprocess.Popen.kill(request.args[1])
        #os.killpg(os.getpgid(int(request.args[1])), signal.SIGTERM)
        #c="kill -TERM -- -"+str(request.args[1])
        #os.system(kill -TERM -- -28796)
        db.httpProxy.update_or_insert((db.httpProxy.id==request.args[0]), proxyRun='F')
        os.killpg(int(request.args[1]), signal.SIGTERM)
        redirect(URL('proxy','httpProxy', vars=dict(msg='PROXY STOPPED PID: ' + str(request.args[1]), alert="danger")))
    except:
        redirect(URL('proxy','httpProxy', vars=dict(msg='PROXY STOPPED PID: ' + str(request.args[1]), alert="danger")))
        #redirect(URL('proxy','httpProxy', vars=dict(msg='Error', alert="danger")))
        pass

@auth.requires_login()
def httpProxyExec():
    #-------------------------------------------------------------------------------------
    if demo == False:
        if (auth.has_membership(role='admin') or auth.has_membership(role='riskManager')):
            pass
        else:
            redirect(URL('default','index'))
    #-------------------------------------------------------------------------------------
    #if request.args[5] == 'True':
    #    redirect(URL('proxy','httpProxy', vars=dict(msg='Proxy server already listening at http://*: ' + str(request.args[3]), alert="warning")))

    #flowcontent stores html/js content
    webAppPath = str(request.folder)+"/modules/flowContent/"
    try:
        shutil.rmtree(webAppPath)
    except:
        pass
    try:
        os.mkdir(webAppPath)
        #flowDetails.txt stores proxy results
        a = open(webAppPath+"flowDetails.txt",'w')
        a.close()
    except:
        pass
    #mitmproxyExec.py executes mitmproxy http
    script = os.path.join(request.folder, 'modules', 'mitmproxyExec.py')

    #----------------------------------
    #To execute mitmproxy with options
    #args=[row.id, row.httpSsl, row.webAppId, row.portHttp, row.sslInsecure, row.proxyRun])
    #----------------------------------
    if request.args[1] == 'False': #SSL
        op1 = 0
    if request.args[1] == 'True':  #SSL
        op1 = 1
    if request.args[4] == 'True':  #sslInsecure
        op1 = 2
    #----------------------------------------------------
    #-S app tells web2py to run "myscript.py" as "app", 
    #-M tells web2py to execute models
    #-A a b c passes optional command line arguments
    #----------------------------------------------------
    #op1 [ssl-insecure, ssl]
    #request.args[3] --> TCP port
    #----------------------------------------------------
    mitmproxyExec = "python %s/web2py.py -S %s -M -R %s -A %s %s %s"%(os.getcwd(), request.application, script, request.application, request.args[3], op1)
    proxyPs = subprocess.Popen(mitmproxyExec, shell=True,  preexec_fn=os.setsid)
    #db.httpProxy.update_or_insert((db.httpProxy.id==request.args[0]), pidExec=proxyPs.pid )
    db.httpProxy.update_or_insert((db.httpProxy.id==request.args[0]), pidExec=os.getpgid(proxyPs.pid), proxyRun='T')
    redirect(URL('proxy','httpProxy', vars=dict(msg='PROXY SERVER LISTENING AT PORT: ' + str(request.args[3]), alert="success")))

@auth.requires_login()
def getResult():
    #-------------------------------------------------------------------------------------
    if demo == False:
        if (auth.has_membership(role='admin') or auth.has_membership(role='riskManager')):
            pass
        else:
            redirect(URL('default','index'))
    #-------------------------------------------------------------------------------------
    #-------------------------------------------------------------------------------
    #To handle none parameters or that cannot treated as a dict objetc
    #-------------------------------------------------------------------------------
    httpFlow = open(str(request.folder)+"/modules/flowContent/flowDetails.txt", 'r')
    fileData = httpFlow.read()
    httpFlow.close()
    newData = fileData.replace('MultiDictView[]', 'None')
    httpFlow = open(str(request.folder)+"/modules/flowContent/flowDetails.txt", 'w')
    httpFlow.write(newData)
    httpFlow.close()

    httpFlow = open(str(request.folder)+"/modules/flowContent/flowDetails.txt", 'r')
    fileData = httpFlow.read()
    httpFlow.close()
    newData = fileData.replace('Headers[(', '[(')
    httpFlow = open(str(request.folder)+"/modules/flowContent/flowDetails.txt", 'w')
    httpFlow.write(newData)
    httpFlow.close()

    httpFlow = open(str(request.folder)+"/modules/flowContent/flowDetails.txt", 'r')
    fileData = httpFlow.read()
    httpFlow.close()
    newData = fileData.replace('MultiDictView[(', '[(')
    httpFlow = open(str(request.folder)+"/modules/flowContent/flowDetails.txt", 'w')
    httpFlow.write(newData)
    httpFlow.close()

    httpFlow = open(str(request.folder)+"/modules/flowContent/flowDetails.txt", 'r')
    fileData = httpFlow.read()
    httpFlow.close()
    newData = fileData.replace('CookieAttrs[(', '[(')
    httpFlow = open(str(request.folder)+"/modules/flowContent/flowDetails.txt", 'w')
    httpFlow.write(newData)
    httpFlow.close()
    #-------------------------------------------------------------------------------

    httpFlow = open(str(request.folder)+"/modules/flowContent/flowDetails.txt", 'r')
    for f in httpFlow.readlines():
        f = dict(eval(f))
        try:
            db.httpAnalysis.update_or_insert(((db.httpAnalysis.httpProxyId==request.args[0]) & (db.httpAnalysis.idRequest==f['idRequest'])), httpProxyId=request.args[0], idRequest=f['idRequest'], rqMethod=f['rqMethod'], rqPath=f['rqPath'], rqHttpVersion=f['rqHttpVersion'], rqUrl=f['rqUrl'], rqCookies=f['rqCookies'], rqHeaders=f['rqHeaders'], rqQuery=f['rqQuery'], rqBody=f['rqBody'], rsStatusCode=f['rsStatusCode'], rsStatusText=f['rsStatusText'], rsHttpVersion=f['rsHttpVersion'], rsCookies=f['rsCookies'], rsHeaders=f['rsHeaders'], httpAnalysisDate=datetime.now())        
        except:
            pass
        #To upload file
        try:
            stream = open(str(request.folder)+"/modules/flowContent/"+str(f['idRequest']), 'rb')
            db.httpAnalysis.update_or_insert(((db.httpAnalysis.httpProxyId==request.args[0]) & (db.httpAnalysis.idRequest==f['idRequest'])), rsContent=stream )
            stream.close()
        except:
            pass

    redirect(URL('proxy','httpAnalysis'))

@auth.requires_login()
def codeReview():
    codeFile = db(db.httpAnalysis.httpProxyId==request.args[0]).select(db.httpAnalysis.rsContent, db.httpAnalysis.rqUrl, db.httpAnalysis.httpProxyId)
    for i in codeFile:
        f = str(request.folder)+"/uploads/"+i.rsContent
        openFile = open(f, 'rb')
        for line in openFile:
            for k in str(str(base64.b64decode(request.args[1])).replace(' ','')).split(','):
                if (line.lower()).find(str(k).lower()) != -1:
                    l = line[(line.lower()).find(str(k).lower()) - 20 : (line.lower()).find(str(k).lower()) + 20]
                    #db.staticAnalysis.update_or_insert(( (db.staticAnalysis.webAppId==request.args[2]) & (db.staticAnalysis.staticAnalysisKeyWords==k) & (db.staticAnalysis.staticAnalysisUrl==i.rqUrl)), webAppId=request.args[2], staticAnalysisKeyWords=k, staticAnalysisUrl=i.rqUrl, staticAnalysisLine=l, staticAnalysisDate=datetime.now() )
                    db.staticAnalysis.update_or_insert(( (db.staticAnalysis.httpProxyId==request.args[0]) & (db.staticAnalysis.staticAnalysisKeyWords==k) & (db.staticAnalysis.staticAnalysisUrl==i.rqUrl)), httpProxyId=request.args[0], staticAnalysisKeyWords=k, staticAnalysisUrl=i.rqUrl, staticAnalysisLine=l, staticAnalysisDate=datetime.now() )
    redirect(URL('proxy','staticAnalysis'))
