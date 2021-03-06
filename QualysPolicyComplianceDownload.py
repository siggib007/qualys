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
import xml.parsers.expat
import pymysql
import json
import platform
import time
import urllib.parse as urlparse
# End imports

#avoid insecure warning
requests.urllib3.disable_warnings()

#Define few things
iChunkSize = 5000
iTimeOut = 120
iMinQuiet = 2 # Minimum time in seconds between API calls
iTotalSleep = 0
tLastCall = 0

def isInt (CheckValue):
  # function to safely check if a value can be interpreded as an int
  if isinstance(CheckValue,int):
    return True
  elif isinstance(CheckValue,str):
    if CheckValue.isnumeric():
      return True
    else:
      return False
  else:
    return False

def SendNotification (strMsg):
  if not bNotifyEnabled:
    return "notifications not enabled"
  dictNotify = {}
  dictNotify["token"] = dictConfig["NotifyToken"]
  dictNotify["channel"] = dictConfig["NotifyChannel"]
  dictNotify["text"]=strMsg[:199]
  strNotifyParams = urlparse.urlencode(dictNotify)
  strURL = dictConfig["NotificationURL"] + "?" + strNotifyParams
  bStatus = False
  try:
    WebRequest = requests.get(strURL,timeout=iTimeOut)
  except Exception as err:
    LogEntry ("Issue with sending notifications. {}".format(err))
  if isinstance(WebRequest,requests.models.Response)==False:
    LogEntry ("response is unknown type")
  else:
    dictResponse = json.loads(WebRequest.text)
    if isinstance(dictResponse,dict):
      if "ok" in dictResponse:
        bStatus = dictResponse["ok"]
        LogEntry ("Successfully sent slack notification\n{} ".format(strMsg))
    if not bStatus or WebRequest.status_code != 200:
      LogEntry ("Problme: Status Code:[] API Response OK={}")
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

def MakeAPICall (strURL, dictHeader, strMethod, strUserName, strPWD, dictPayload=""):

  global tLastCall
  global iTotalSleep
  global strResponse

  fTemp = time.time()
  fDelta = fTemp - tLastCall
  # LogEntry ("It's been {} seconds since last API call".format(fDelta))
  if fDelta > iMinQuiet:
    tLastCall = time.time()
  else:
    iDelta = int(fDelta)
    iAddWait = iMinQuiet - iDelta
    LogEntry ("It has been less than {} seconds since last API call, "
      "waiting {} seconds".format(iMinQuiet,iAddWait))
    iTotalSleep += iAddWait
    time.sleep(iAddWait)
  iErrCode = ""
  iErrText = ""

  # LogEntry ("Doing a {} to URL: \n {}\n".format(strMethod,strURL))
  try:
    if strMethod.lower() == "get":
      WebRequest = requests.get(strURL, headers=dictHeader, verify=False, auth=(strUserName, strPWD))
      # LogEntry ("get executed")
    if strMethod.lower() == "post":
      if dictPayload != "":
        WebRequest = requests.post(strURL, json= dictPayload, headers=dictHeader, verify=False,  auth=(strUserName, strPWD))
      else:
        WebRequest = requests.post(strURL, headers=dictHeader, verify=False, auth=(strUserName, strPWD))
      # LogEntry ("post executed")
  except Exception as err:
    LogEntry ("Issue with API call. {}".format(err))
    CleanExit ("due to issue with API, please check the logs")

  if isinstance(WebRequest,requests.models.Response)==False:
    LogEntry ("response is unknown type")
    iErrCode = "ResponseErr"
    iErrText = "response is unknown type"

  # LogEntry ("call resulted in status code {}".format(WebRequest.status_code))
  if WebRequest.status_code != 200:
    # LogEntry (WebRequest.text)
    iErrCode = WebRequest.status_code
    iErrText = WebRequest.text

  strType = "xml"
  strResponse = WebRequest.text
  if strResponse[:2] == "[{":
    strType = "json"
  if strResponse[:5] == "<?xml":
    strType = "xml"
  if strType.lower() == "xml":
    try:
      dictResponse = xmltodict.parse(strResponse)
      LogEntry ("xml loaded into dictionary")
    except xml.parsers.expat.ExpatError as err:
      LogEntry ("Expat Error: {}\n{}".format(err,strResponse))
      iErrCode = "Expat Error"
      iErrText = "Expat Error: {}\n{}".format(err,strResponse)
  elif strType == "json" :
    dictResponse = json.loads(strResponse)
    LogEntry ("json loaded into dictionary")
  else:
    dictResponse = {}

  if isinstance(dictResponse,dict):
    if "SIMPLE_RETURN" in dictResponse:
      try:
        if "CODE" in dictResponse["SIMPLE_RETURN"]["RESPONSE"]:
          iErrCode = dictResponse["SIMPLE_RETURN"]["RESPONSE"]["CODE"]
          iErrText = dictResponse["SIMPLE_RETURN"]["RESPONSE"]["TEXT"]
      except KeyError as e:
        LogEntry ("KeyError: {}".format(e))
        LogEntry (strResponse)
        iErrCode = "Unknown"
        iErrText = "Unexpected error"
  elif isinstance(dictResponse,list):
    LogEntry ("Response is a list of {} elements".format(len(dictResponse)))
    LogEntry ("First element is of type {}".format(type(dictResponse[0])))
  else:
    LogEntry ("Response not a dictionary or a list. it's {}".format(type(dictResponse)))
    sys.exit(8)

  if iErrCode != "" or WebRequest.status_code !=200:
    return "There was a problem with your request. HTTP error {} code {} {}".format(WebRequest.status_code,iErrCode,iErrText)
  else:
    return dictResponse

def processConf(strConf_File):

  LogEntry ("Looking for configuration file: {}".format(strConf_File))
  if os.path.isfile(strConf_File):
    LogEntry ("Configuration File exists")
  else:
    LogEntry ("Can't find configuration file {}, make sure it is the same directory "
      "as this script and named the same with ini extension".format(strConf_File))
    LogEntry("{} on {}: Exiting.".format (strScriptName,strScriptHost))
    objLogOut.close()
    sys.exit(9)

  strLine = "  "
  dictConfig = {}
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
      dictConfig[strVarName] = strValue
      if strVarName == "include":
        LogEntry ("Found include directive: {}".format(strValue))
        strValue = strValue.replace("\\","/")
        if strValue[:1] == "/" or strValue[1:3] == ":/":
          LogEntry("include directive is absolute path, using as is")
        else:
          strValue = strBaseDir + strValue
          LogEntry("include directive is relative path,"
            " appended base directory. {}".format(strValue))
        if os.path.isfile(strValue):
          LogEntry ("file is valid")
          objINIFile = open(strValue,"r")
          strLines += objINIFile.readlines()
          objINIFile.close()
        else:
          LogEntry ("invalid file in include directive")

  LogEntry ("Done processing configuration, moving on")
  return dictConfig

def main():
  global strFileout
  global objLogOut
  global strScriptName
  global strScriptHost
  global tLastCall
  global iTotalSleep
  global strBaseDir
  global strBaseURL
  global dictConfig
  global bNotifyEnabled
  global iMinQuiet
  global iTimeOut

  dictPayload = {}
  dictHeader = {}
  dictParams = {}
  lstPolicyID=[]
  
  iTimeOut = 120
  ISO = time.strftime("-%Y-%m-%d-%H-%M-%S")
  strScriptName = os.path.basename(sys.argv[0])
  iLoc = sys.argv[0].rfind(".")
  strConf_File = sys.argv[0][:iLoc] + ".ini"
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

  now = time.asctime()
  print ("This is a Qualys Policy Compliance API script. This is running under Python Version {0}".format(strVersion))
  print ("Running from: {}".format(strRealPath))

  print ("The time now is {}".format(now))
  print ("Logs saved to {}".format(strLogFile))
  objLogOut = open(strLogFile,"w",1)

  dictConfig = processConf(strConf_File)
  strScriptHost = platform.node().upper()
  if strScriptHost in dictConfig:
    strScriptHost = dictConfig[strScriptHost]
    
  LogEntry ("Starting {} on {}".format(strScriptName,strScriptHost))

  if "QUserID" in dictConfig:
    strUserName = dictConfig["QUserID"]

  if "QUserPWD" in dictConfig:
    strPWD = dictConfig["QUserPWD"]


  if "APIRequestHeader" in dictConfig:
    dictHeader["X-Requested-With"] = dictConfig["APIRequestHeader"]

  if "NotifyToken" in dictConfig and "NotifyChannel" in dictConfig and "NotificationURL" in dictConfig:
    bNotifyEnabled = True
  else:
    bNotifyEnabled = False
    LogEntry("Missing configuration items for Slack notifications, "
      "turning slack notifications off")

  if "APIBaseURL" in dictConfig:
    strBaseURL = dictConfig["APIBaseURL"]
  else:
    CleanExit("No Base API provided")
  if strBaseURL[-1:] != "/":
    strBaseURL += "/"

  if "NotifyEnabled" in dictConfig:
    if dictConfig["NotifyEnabled"].lower() == "yes" \
      or dictConfig["NotifyEnabled"].lower() == "true":
      bNotifyEnabled = True
    else:
      bNotifyEnabled = False

  if "OutfileName" in dictConfig:
    strFileout = dictConfig["OutfileName"]

  if "TimeOut" in dictConfig:
    if isInt(dictConfig["TimeOut"]):
      iTimeOut = int(dictConfig["TimeOut"])
    else:
      LogEntry("Invalid timeout, setting to defaults of {}".format(iTimeOut))
  
  if "MinQuiet" in dictConfig:
    if isInt(dictConfig["MinQuiet"]):
      iMinQuiet = int(dictConfig["MinQuiet"])
    else:
      LogEntry("Invalid MinQuiet, setting to defaults of {}".format(iMinQuiet))

  strMethod = "get"
  strAPI = "api/2.0/fo/compliance/policy/?"
  strAction = "action=list"
  strURL = strBaseURL + strAPI + strAction
  LogEntry ("Making a query for a Policy List using {} {}".format(strMethod.upper(),strURL))
  APIResponse = MakeAPICall(strURL, dictHeader, strMethod, strUserName, strPWD, dictPayload)
  if isinstance(APIResponse,str):
    LogEntry(APIResponse,True)
  elif isinstance(APIResponse,dict):
    if "result" in APIResponse:
      if "error_message" in APIResponse["result"]:
        LogEntry(APIResponse["result"]["error_message"],True)
      else:
        LogEntry("Unexpected APIResponse: {}".format(APIResponse),True)
    if "POLICY_LIST_OUTPUT" in APIResponse:
      if "RESPONSE" in APIResponse["POLICY_LIST_OUTPUT"]:
        if "POLICY_LIST" in APIResponse["POLICY_LIST_OUTPUT"]["RESPONSE"]:
          if isinstance(APIResponse["POLICY_LIST_OUTPUT"]["RESPONSE"]["POLICY_LIST"]["POLICY"],list):
            iNumRows = len(APIResponse["POLICY_LIST_OUTPUT"]["RESPONSE"]["POLICY_LIST"]["POLICY"])
            LogEntry ("Number of policys: {}".format(iNumRows))
            for dictTemp in APIResponse["POLICY_LIST_OUTPUT"]["RESPONSE"]["POLICY_LIST"]["POLICY"]:
              LogEntry (" {} : {}".format(dictTemp["ID"],dictTemp["TITLE"]))
              lstPolicyID.append(dictTemp["ID"])
          else:
            iNumRows = 1
            LogEntry ("Number of policys: {}".format(iNumRows))
            dictTemp = APIResponse["POLICY_LIST_OUTPUT"]["RESPONSE"]["POLICY_LIST"]["POLICY"]
            LogEntry (" {} : {}".format(dictTemp["ID"],dictTemp["TITLE"]))
            lstPolicyID.append(dictTemp["ID"])
        else:
          LogEntry ("There is no policy list. Here is the APIResponse:{}".format(APIResponse),True)
      else:
        LogEntry ("There is no response object. Here is the APIResponse:{}".format(APIResponse),True)
    else:
      LogEntry ("There is no policy list output. Here is the APIResponse:{}".format(APIResponse),True)
  else:
    LogEntry ("API Response neither a dictionary nor a string. Here is what I got: {}".format(APIResponse),True)

  LogEntry ("Policy IDs: {}".format(lstPolicyID))

  iStep = 0
  lstPolicyChunks = []
  while iStep < len(lstPolicyID):
    lstPolicyChunks.append(",".join(lstPolicyID[iStep:iStep+10]))
    iStep += 10
  
  iCount = 1
  for strPolicyList in lstPolicyChunks:
    iLoc = strFileout.rfind(".")
    strFileChunkName = "{}-{}{}".format(strFileout[:iLoc],iCount,strFileout[iLoc:])
    objOutFile = open(strFileChunkName,"w",1)
    dictParams["policy_ids"] = strPolicyList
    dictParams["action"] = "list"
    dictParams["details"] = "All"
    LogEntry ("Payload: {}".format(dictParams))
    strAPI = "/api/2.0/fo/compliance/posture/info/"
    strListScans = urlparse.urlencode(dictParams)
    strURL = strBaseURL + strAPI + "?" + strListScans
    strMethod="get"
    LogEntry ("Streaming API for Posture Details using {} {}".format(strMethod.upper(),strURL))
    try:
      WebRequest = requests.get(strURL, headers=dictHeader, verify=False, stream=True, auth=(strUserName, strPWD))
      LogEntry ("get executed")
    except Exception as err:
      LogEntry ("Issue with API call. {}".format(err),True)

    if isinstance(WebRequest,requests.models.Response)==False:
      LogEntry ("response is unknown type",True)

    LogEntry ("call resulted in status code {}".format(WebRequest.status_code))
    LogEntry ("Starting to stream the results to {}".format(strFileChunkName))
    iLineNum = 1
    try:
      for strLine in WebRequest.iter_lines():
        if strLine:
          strLine = strLine.decode("ascii","ignore")
          print ("Downloaded {} lines.".format(iLineNum),end="\r")
          iLineNum += 1
          objOutFile.write ("{}\n".format(strLine))
    except Exception as err:
      LogEntry ("Unexpected issue: {}".format(err),True)  
    objOutFile.close()
    iCount += 1

  SendNotification ("{} completed on {}!".format(strScriptName,strScriptHost))
  LogEntry ("All Done!")
  objLogOut.close()

if __name__ == '__main__':
    main()

