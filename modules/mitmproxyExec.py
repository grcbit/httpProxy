import os
import sys

#--ssl-insecure, -k    Do not verify upstream server SSL/TLS certificates.
#sys.argv[1] --> appName
#sys.argv[2] --> TCP Port
#sys.argv[3] --> op1 [ssl, ssl-insecure]

if sys.argv[3] == '0':
    #mitmproxyExec = str(request.folder)+"/modules/./mitmdump -s " + str(request.folder)+"/controllers/httpFlow.py &"
    mitmproxyExec = str(request.folder)+"/modules/./mitmdump -s " + str(request.folder) + "/modules/tls_passthrough.py -p " + str(sys.argv[2]) + " " + str(sys.argv[1]) + " &"
elif sys.argv[3] == '1':
    mitmproxyExec = str(request.folder)+"/modules/./mitmdump -s " + str(request.folder) + "/modules/tls_passthrough.py -p " + str(sys.argv[2]) + " " + str(sys.argv[1]) + " &"
elif sys.argv[3] == '2':
    mitmproxyExec = str(request.folder)+"/modules/./mitmdump -k -s " + str(request.folder) + "/modules/tls_passthrough.py -p " + str(sys.argv[2]) + " " + str(sys.argv[1]) + " &"

os.system(mitmproxyExec)
