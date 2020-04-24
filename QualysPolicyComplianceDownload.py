'''
Qualys Policy Compliance API Script
Author Siggi Bjarnason Copyright 2017

Description:
This script will pull all details about our Qualys Policy Compliance Scan the Qualys API and write the results to a file.


Following packages need to be installed as administrator
pip install requests
pip install xmltodict
pip install pymysql

'''
# Import libraries
import sys
import requests
import os
import xmltodict
import pymysql
import json
import platform
import time
import urllib.parse as urlparse
# End imports

# strConf_File = "QSPOLICY.ini"
ISO = time.strftime("-%Y-%m-%d-%H-%M-%S")
strScriptName = os.path.basename(sys.argv[0])
iLoc = sys.argv[0].rfind(".")
strConf_File = sys.argv[0][:iLoc] + ".ini"
strScriptHost = platform.node().upper()
strBaseDir = os.path.dirname(sys.argv[0])
if strBaseDir != "":
  if strBaseDir[-1:] != "/":
    strBaseDir += "/"
strLogDir  = strBaseDir + "Logs"

if not os.path.exists (strLogDir) :
  os.makedirs(strLogDir)
  print ("\nPath '{0}' for log files didn't exists, so I create it!\n".format(strLogDir))

iLoc = strScriptName.rfind(".")
strLogFile = strLogDir + "/" + strScriptName[:iLoc] + ISO + ".log"
strRealPath = os.path.realpath(sys.argv[0])
strVersion = "{0}.{1}.{2}".format(sys.version_info[0],sys.version_info[1],sys.version_info[2])
localtime = time.localtime(time.time())
gmt_time = time.gmtime()
iGMTOffset = (time.mktime(localtime) - time.mktime(gmt_time))/3600
now = time.asctime()
print ("This is a Qualys Policy Compliance API script. This is running under Python Version {0}".format(strVersion))
print ("Running from: {}".format(strRealPath))

print ("The time now is {}".format(now))
print ("Logs saved to {}".format(strLogFile))
objLogOut = open(strLogFile,"w",1)


def SendNotification (strMsg):
  if not bNotifyEnabled:
    return "notifications not enabled"
  dictNotify = {}
  dictNotify["token"] = strNotifyToken
  dictNotify["channel"] = strNotifyChannel
  dictNotify["text"]=strMsg[:9999]
  strNotifyParams = urlparse.urlencode(dictNotify)
  strURL = strNotifyURL + "?" + strNotifyParams
  bStatus = False
  WebRequest = ""
  try:
    WebRequest = requests.get(strURL)
  except Exception as err:
    LogEntry ("Issue with sending notifications. {}".format(err))
  if isinstance(WebRequest,requests.models.Response)==False:
    LogEntry ("response is unknown type")
  else:
    try:
      dictResponse = json.loads(WebRequest.text)
    except Exception as err:
      LogEntry ("Issue with json results while sending notifications. {}".format(err))
      LogEntry (WebRequest.text,True)
    if isinstance(dictResponse,dict):
      if "ok" in dictResponse:
        bStatus = dictResponse["ok"]
    if not bStatus or WebRequest.status_code != 200:
      LogEntry ("Slack Problem: Status Code:{} API Response OK={}".format(WebRequest.status_code,dictResponse["ok"]))
      LogEntry (WebRequest.text)

def CleanExit(strCause):
  SendNotification("{} is exiting abnormally on {} {}".format(strScriptName,strScriptHost, strCause))
  objLogOut.close()
  sys.exit(9)

def LogEntry(strMsg,bAbort=False):
  strTimeStamp = time.strftime("%m-%d-%Y %H:%M:%S")
  objLogOut.write("{0} : {1}\n".format(strTimeStamp,strMsg))
  print (strMsg)
  if bAbort:
    SendNotification("{} on {}: {}".format (strScriptName,strScriptHost,strMsg[:99]))
    CleanExit("")

def processConf():
  global strBaseURL
  global strHeadReq
  global strUserName
  global strPWD
  global strServer
  global strDBUser
  global strDBPWD
  global strInitialDB
  global strNotifyURL
  global strNotifyToken
  global strNotifyChannel
  global bNotifyEnabled
  global strOutFile

  strBaseURL=None
  strUserName=None
  strPWD=None
  strNotifyURL=None
  strNotifyToken=None
  strNotifyChannel=None
  bNotifyEnabled = False

  if os.path.isfile(strConf_File):
    LogEntry ("Configuration File exists")
  else:
    LogEntry ("Can't find configuration file {}, make sure it is the same directory as this script".format(strConf_File),True)

  strLine = "  "
  LogEntry ("Reading in configuration")
  objINIFile = open(strConf_File,"r")
  strLines = objINIFile.readlines()
  objINIFile.close()

  for strLine in strLines:
    strLine = strLine.strip()
    iCommentLoc = strLine.find("#")
    if iCommentLoc > -1:
      strLine = strLine[:iCommentLoc].strip()
    else:
      strLine = strLine.strip()
    if "=" in strLine:
      strConfParts = strLine.split("=")
      strVarName = strConfParts[0].strip()
      strValue = strConfParts[1].strip()
      strConfParts = strLine.split("=")
      if strVarName == "OutfileName":
        strOutFile = strValue
      if strVarName == "APIBaseURL":
        strBaseURL = strValue
      if strVarName == "APIRequestHeader":
        strHeadReq = strValue
      if strVarName == "QUserID":
        strUserName = strValue
      if strVarName == "QUserPWD":
        strPWD = strValue
      if strVarName == "Server":
        strServer = strValue
      if strVarName == "dbUser":
        strDBUser = strValue
      if strVarName == "dbPWD":
        strDBPWD = strValue
      if strVarName == "InitialDB":
        strInitialDB = strValue
      if strVarName == "NotificationURL":
        strNotifyURL = strValue
      if strVarName == "NotifyChannel":
        strNotifyChannel = strValue
      if strVarName == "NotifyToken":
        strNotifyToken = strValue
      if strVarName == "NotifyEnabled":
        bNotifyEnabled = strValue.lower()=="yes" or strValue.lower()=="true"
        LogEntry("notifications: {}".format(bNotifyEnabled))
  if strNotifyToken is None or strNotifyChannel is None or strNotifyURL is None:
    bNotifyEnabled = False
    LogEntry("Missing configuration items for Slack notifications, turned slack notifications off")

  if strBaseURL[-1:] != "/":
    strBaseURL += "/"

  LogEntry ("Done processing configuration, moving on")

def MakePLAPICall (strURL, dictHeader, strUserName,strPWD, strMethod, dictPayload={}, bRaw=False):
  global strType

  strErrCode = ""
  strErrText = ""
  dictResponse = {}

  LogEntry ("Doing a {} to URL: \n {}\n".format(strMethod,strURL))

  try:
    if strMethod.lower() == "get":
      WebRequest = requests.get(strURL,timeout=iTimeOut, headers=dictHeader, auth=(strUserName, strPWD))
      LogEntry ("get executed")
    if strMethod.lower() == "post":
      if dictPayload != {}:
        WebRequest = requests.post(strURL, data=dictPayload, headers=dictHeader, auth=(strUserName, strPWD))
        LogEntry ("payload post executed")
      else:
        WebRequest = requests.post(strURL, headers=dictHeader, auth=(strUserName, strPWD))
        LogEntry ("no payload post executed")
  # except requests.exceptions.ReadTimeout as err:
  except Exception as err:
    LogEntry ("Issue with API call. {}".format(err))
    strErrCode = "APIFail"
    strErrText = err
    return {"result":{"error_message":"API call failed"}}

  if isinstance(WebRequest,requests.models.Response)==False:
    LogEntry ("response is unknown type")
    return {"result":{"error_message":"API call failed"}}
  # end if
  # if WebRequest.status_code != 200:
  #   LogEntry ("call resulted in status code {}".format(WebRequest.status_code))

  if bRaw:
    return WebRequest.text

  if WebRequest.text[:5] == "<?xml":
    strType = "xml"
  elif WebRequest.text[:1] == "[" or WebRequest.text[:1] == "{" :
    strType = "json"
  else:
    strType = "unknown"
  if strType.lower() == "xml":
    try:
      dictResponse = xmltodict.parse(WebRequest.text)
      LogEntry ("xml loaded into dictionary")
    except xml.parsers.expat.ExpatError as err:
      LogEntry ("Expat Error: {}\n{}".format(err,WebRequest.text))
      strErrCode = "Expat Error"
      strErrText = "Expat Error: {}\n{}".format(err,WebRequest.text)
  elif strType == "json" :
    dictResponse = json.loads(WebRequest.text)
    # LogEntry ("json loaded into dictionary")
  else:
    dictResponse = {}

  if isinstance(dictResponse,dict):
    if "SIMPLE_RETURN" in dictResponse:
      try:
        if "CODE" in dictResponse["SIMPLE_RETURN"]["RESPONSE"]:
          strErrCode = dictResponse["SIMPLE_RETURN"]["RESPONSE"]["CODE"]
          strErrText = dictResponse["SIMPLE_RETURN"]["RESPONSE"]["TEXT"]
      except KeyError as e:
        LogEntry ("KeyError: {}".format(e))
        LogEntry (WebRequest.text)
        strErrCode = "Unknown"
        strErrText = "Unexpected error"
    if "result" in dictResponse:
      if "error_message" in dictResponse["result"]:
        strErrText = dictResponse["result"]["error_message"]
        strErrCode = WebRequest.status_code
  elif isinstance(dictResponse,list):
    LogEntry ("Response is a list of {} elements".format(len(dictResponse)))
    LogEntry ("First element is of type {}".format(type(dictResponse[0])))
  else:
    LogEntry ("Response not a dictionary or a list. it's {}".format(type(dictResponse)),True)

  if strErrText != "" or WebRequest.status_code !=200:
    if strErrCode == "":
      return "HTTP error {} {}".format(WebRequest.status_code,strErrText)
    else:
      if strErrCode == 521 or strErrCode == "APIFail":
        return dictResponse
      else:
        return "HTTP error {} code {} {}".format(WebRequest.status_code,strErrCode,strErrText)
  else:
    return dictResponse

dictPayload = {}
iTimeOut = 120
lstPolicyID=[]
processConf()
strHeader={'X-Requested-With': strHeadReq}
strAPI = "api/2.0/fo/compliance/policy/?"
strAction = "action=list"
# strAction = "action=list&output_mode=full&name=SCNTTN16"
strURL = strBaseURL + strAPI + strAction
APIResponse = MakePLAPICall(strURL,strHeader,strUserName,strPWD,"get")
if isinstance(APIResponse,str):
  LogEntry(APIResponse)
elif isinstance(APIResponse,dict):
  if "result" in APIResponse:
    if "error_message" in APIResponse["result"]:
      LogEntry(APIResponse["result"]["error_message"],True)
    else:
      LogEntry("Unexpected APIResponse: {}".format(APIResponse))
  if "POLICY_LIST_OUTPUT" in APIResponse:
    if "RESPONSE" in APIResponse["POLICY_LIST_OUTPUT"]:
      if "POLICY_LIST" in APIResponse["POLICY_LIST_OUTPUT"]["RESPONSE"]:
        if isinstance(APIResponse["POLICY_LIST_OUTPUT"]["RESPONSE"]["POLICY_LIST"]["POLICY"],list):
          iNumRows = len(APIResponse["POLICY_LIST_OUTPUT"]["RESPONSE"]["POLICY_LIST"]["POLICY"])
          LogEntry ("Number of policys: {}".format(iNumRows))
          for dictTemp in APIResponse["POLICY_LIST_OUTPUT"]["RESPONSE"]["POLICY_LIST"]["POLICY"]:
            print (" {} : {}".format(dictTemp["ID"],dictTemp["TITLE"]))
            lstPolicyID.append(dictTemp["ID"])
        else:
          iNumRows = 1
          LogEntry ("Number of policys: {}".format(iNumRows))
          dictTemp = APIResponse["POLICY_LIST_OUTPUT"]["RESPONSE"]["POLICY_LIST"]["POLICY"]
          print (" {} : {}".format(dictTemp["ID"],dictTemp["TITLE"]))
          lstPolicyID.append(dictTemp["ID"])
      else:
        LogEntry ("There is no policy list. Here is the APIResponse:{}".format(APIResponse))
    else:
      LogEntry ("There is no response object. Here is the APIResponse:{}".format(APIResponse))
  else:
    LogEntry ("There is no policy list output. Here is the APIResponse:{}".format(APIResponse))
else:
  LogEntry ("API Response neither a dictionary nor a string. Here is what I got: {}".format(APIResponse))

print ("Policy IDs: {}".format(lstPolicyID))

dictPayload["policy_ids"] = ",".join(lstPolicyID)
dictPayload["action"] = "list"
dictPayload["details"] = "All"
print ("Payload: {}".format(dictPayload))
strAPI = "/api/2.0/fo/compliance/posture/info/"
strURL = strBaseURL + strAPI
APIResponse = MakePLAPICall(strURL,strHeader,strUserName,strPWD,"post",dictPayload,True)
print(APIResponse)
objOutFile = open(strOutFile,"w",1)
objOutFile.write(APIResponse)
objOutFile.close()


SendNotification ("{} completed on {}!".format(strScriptName,strScriptHost))
LogEntry ("All Done!")
objLogOut.close()