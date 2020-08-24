'''
Script to pull all Host information from Qualys
Author Siggi Bjarnason Copyright 2020

Following packages need to be installed as administrator
pip install requests
pip install xmltodict

'''
# Import libraries
import sys
import requests
import os
import time
import xmltodict
import urllib.parse as urlparse
import xml.parsers.expat
import json
import platform
# End imports


ISO = time.strftime("-%Y-%m-%d-%H-%M-%S")
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

strScriptName = os.path.basename(sys.argv[0])
iLoc = strScriptName.rfind(".")
strLogFile = strLogDir + "/" + strScriptName[:iLoc] + ISO + ".log"
strRealPath = os.path.realpath(sys.argv[0])
strVersion = "{0}.{1}.{2}".format(sys.version_info[0],sys.version_info[1],sys.version_info[2])
localtime = time.localtime(time.time())
gmt_time = time.gmtime()
iGMTOffset = (time.mktime(localtime) - time.mktime(gmt_time))/3600

strScriptHost = platform.node().upper()
if strScriptHost == "DEV-APS-RHEL-STD-A":
  strScriptHost = "VMSAWS01"

print ("This is a script to gather all asset host information from Qualys via API. This is running under Python Version {}".format(strVersion))
print ("Running from: {}".format(strRealPath))
now = time.asctime()
print ("The time now is {}".format(now))
print ("Logs saved to {}".format(strLogFile))
objLogOut = open(strLogFile,"w",1)

dboErr = None
dbo = None
iTotalCount = 0
iEntryID = 0
iCountHostChange = 0
iCountTagChange = 0
strDBType = "undef"
strDBUser = ""
strDBPWD = ""
strdbNow = time.strftime("%Y-%m-%d %H:%M:%S")

def CleanExit(strCause):
  objLogOut.close()
  objOutFile.close()
  sys.exit(9)

def LogEntry(strMsg,bAbort=False):
  strTimeStamp = time.strftime("%m-%d-%Y %H:%M:%S")
  objLogOut.write("{0} : {1}\n".format(strTimeStamp,strMsg))
  print (strMsg)
  if bAbort:
    CleanExit("")

def processConf():
  global strBaseURL
  global strHeader
  global strUserName
  global strPWD
  global strServer
  global strDBUser
  global strDBPWD
  global strInitialDB
  global iMinQuietTime
  global strLoadType
  global dtFullLoad
  global strNotifyURL
  global strNotifyToken
  global strNotifyChannel
  global strDBType
  global strFileout
  global iBatchSize

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
      if strVarName == "APIBaseURL":
        strBaseURL = strValue
      if strVarName == "APIRequestHeader":
        strHeader={'X-Requested-With': strValue}
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
      if strVarName == "MinQuietTime":
        iMinQuietTime = int(strValue)
      if strVarName == "LoadType":
        strLoadType = strValue
      if strVarName == "FullFromDate":
        dtFullLoad = strValue
      if strVarName == "NotificationURL":
        strNotifyURL = strValue
      if strVarName == "NotifyChannel":
        strNotifyChannel = strValue
      if strVarName == "NotifyToken":
        strNotifyToken = strValue
      if strVarName == "DBType":
        strDBType  = strValue
      if strVarName == "OutfileName":
        strFileout  = strValue
      if strVarName == "BatchSize":
        iBatchSize = int(strValue)

  if strBaseURL[-1:] != "/":
    strBaseURL += "/"

  LogEntry ("Done processing configuration, moving on")

def MakeAPICall (strURL, strHeader, strUserName,strPWD, strMethod):
  global rawAPIResponse

  iErrCode = ""
  iErrText = ""
  dictResponse = {}

  LogEntry ("Doing a {} to URL: \n {}\n".format(strMethod,strURL))
  try:
    if strMethod.lower() == "get":
      WebRequest = requests.get(strURL, headers=strHeader, auth=(strUserName, strPWD))
      LogEntry ("get executed")
    if strMethod.lower() == "post":
      WebRequest = requests.post(strURL, headers=strHeader, auth=(strUserName, strPWD))
      LogEntry ("post executed")
  except Exception as err:
    LogEntry ("Issue with API call. {}".format(err))
    CleanExit("due to issue with API, please check the logs")

  if isinstance(WebRequest,requests.models.Response)==False:
    LogEntry ("response is unknown type")
    iErrCode = "ResponseErr"
    iErrText = "response is unknown type"

  LogEntry ("call resulted in status code {}".format(WebRequest.status_code))
  if WebRequest.status_code == 200:
    rawAPIResponse = WebRequest.text
  else:
    rawAPIResponse = ""

  try:
    dictResponse = xmltodict.parse(WebRequest.text)
  except xml.parsers.expat.ExpatError as err:
    # LogEntry("Expat Error: {}\n{}".format(err,WebRequest.text))
    iErrCode = "Expat Error"
    iErrText = "Expat Error: {}\n{}".format(err,WebRequest.text)
  except Exception as err:
    LogEntry("Unkown xmltodict exception: {}".format(err))
    CleanExit(", Unkown xmltodict exception, please check the logs")

  if isinstance(dictResponse,dict):
    if "SIMPLE_RETURN" in dictResponse:
      try:
        if "CODE" in dictResponse["SIMPLE_RETURN"]["RESPONSE"]:
          iErrCode = dictResponse["SIMPLE_RETURN"]["RESPONSE"]["CODE"]
          iErrText = dictResponse["SIMPLE_RETURN"]["RESPONSE"]["TEXT"]
      except KeyError as e:
        LogEntry ("KeyError: {}".format(e))
        LogEntry (WebRequest.text)
        iErrCode = "Unknown"
        iErrText = "Unexpected error"
  else:
    LogEntry ("Response not a dictionary",True)

  if iErrCode != "" or WebRequest.status_code !=200:
    return "There was a problem with your request. HTTP error {} code {} {}".format(WebRequest.status_code,iErrCode,iErrText)
  else:
    return dictResponse

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

processConf()

LogEntry("Starting Processing. Script {} running under Python version {}".format(strRealPath,strVersion))

strdbNow = time.strftime("%Y-%m-%d %H:%M:%S")

strAPIFunction = "/api/2.0/fo/asset/host/"
if strAPIFunction[0] == "/":
  strAPIFunction = strAPIFunction[1:]

if strAPIFunction[-1:] != "/":
  strAPIFunction += "/"

LogEntry ("API Function: {}".format(strAPIFunction))

strMethod = "get"
dictParams = {}
dictParams["action"] = "list"
dictParams["truncation_limit"] = iBatchSize
# dictParams["ids"] = "119710152,171444421,129630824,119729204,119729206"

strListScans = urlparse.urlencode(dictParams)
bMoreData = True
iTotalCount = 0
iTotalTagCount = 0
iCount = 1

strURL = strBaseURL + strAPIFunction +"?" + strListScans

APIResponse = MakeAPICall(strURL,strHeader,strUserName,strPWD,strMethod)

while bMoreData:
  if rawAPIResponse != "":
    iLoc = strFileout.rfind(".")
    strFileChunkName = "{}-{}{}".format(strFileout[:iLoc],iCount,strFileout[iLoc:])
    LogEntry("Writing results to {}".format(strFileChunkName))
    objOutFile = open(strFileChunkName,"w",1)
    objOutFile.write(rawAPIResponse)
    objOutFile.close()
    iCount += 1
  if isinstance (APIResponse,str):
    LogEntry (APIResponse)
    bMoreData = False
  if isinstance(APIResponse,dict):
    if "HOST_LIST" in APIResponse["HOST_LIST_OUTPUT"]["RESPONSE"]:
      if "HOST" in APIResponse["HOST_LIST_OUTPUT"]["RESPONSE"]["HOST_LIST"]:
        if isinstance(APIResponse["HOST_LIST_OUTPUT"]["RESPONSE"]["HOST_LIST"]["HOST"],list):
          iResultCount = len(APIResponse["HOST_LIST_OUTPUT"]["RESPONSE"]["HOST_LIST"]["HOST"])
          iTotalCount += iResultCount
          LogEntry ("{} hosts in results".format(iResultCount))
          # for dictHosts in APIResponse["HOST_LIST_OUTPUT"]["RESPONSE"]["HOST_LIST"]["HOST"]:
          #   UpdateDB (dictHosts)
          #   iTotalCount += 1
        else:
          iTotalCount += 1
          LogEntry ("Only one host in results")
          # UpdateDB (APIResponse["HOST_LIST_OUTPUT"]["RESPONSE"]["HOST_LIST"]["HOST"])
        LogEntry("total processed so far {}".format(iTotalCount))
      else:
        LogEntry("there is hosts list but no hosts, weird!!!!")
    else:
      LogEntry ("There are no results")
    if "WARNING" in APIResponse["HOST_LIST_OUTPUT"]["RESPONSE"]:
      strURL = APIResponse["HOST_LIST_OUTPUT"]["RESPONSE"]["WARNING"]["URL"]
      LogEntry ("Next URL: {}".format(strURL))
      APIResponse = MakeAPICall(strURL,strHeader,strUserName,strPWD,strMethod)
    else:
      bMoreData = False
    

objLogOut.close()
