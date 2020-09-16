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

print ("This is a script to gather all asset host information from Qualys via API. This is running under Python Version {}".format(strVersion))
print ("Running from: {}".format(strRealPath))
now = time.asctime()
print ("The time now is {}".format(now))
print ("Logs saved to {}".format(strLogFile))
objLogOut = open(strLogFile,"w",1)

iTotalCount = 0

def CleanExit(strCause):
  try:
    objLogOut.close()
    objOutFile.close()
  except:
    pass
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
  global strFileout
  global iBatchSize
  global strAPIFunction

  strBaseURL = ""
  strHeader = ""
  strUserName = ""
  strPWD = ""
  strFileout = ""
  iBatchSize = 1000

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
      if strVarName == "APIEndPoint":
        strAPIFunction = strValue
      if strVarName == "APIRequestHeader":
        strHeader={'X-Requested-With': strValue}
      if strVarName == "QUserID":
        strUserName = strValue
      if strVarName == "QUserPWD":
        strPWD = strValue
      if strVarName == "OutfileName":
        strFileout  = strValue
      if strVarName == "BatchSize":
        iBatchSize = int(strValue)

  if strBaseURL[-1:] != "/":
    strBaseURL += "/"
  if strAPIFunction[0] == "/":
    strAPIFunction = strAPIFunction[1:]
  if strAPIFunction[-1:] != "/":
    strAPIFunction += "/"

  LogEntry ("Done processing configuration, moving on")

def MakeAPICall (strURL, strHeader, strUserName,strPWD, strMethod):
  global rawAPIResponse

  iErrCode = ""
  iErrText = ""
  dictResponse = {}

  LogEntry ("Doing a {} to URL: {}".format(strMethod,strURL))
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

processConf()

LogEntry("Starting Processing. Script {} running under Python version {}".format(strRealPath,strVersion))

strFileout = strFileout.replace("\\","/")
if not os.path.exists(os.path.dirname(strFileout)):
  LogEntry ("Path '{0}' for output files didn't exists, so I'm creating it!".format(strFileout))
  os.makedirs(os.path.dirname(strFileout))

LogEntry ("API Function: {}".format(strAPIFunction))

strMethod = "get"
dictParams = {}
dictParams["action"] = "list"
dictParams["truncation_limit"] = iBatchSize

strListScans = urlparse.urlencode(dictParams)
bMoreData = True
iTotalCount = 0
iCount = 1

iExtLoc = strFileout.rfind(".")
iFileLoc = strFileout.rfind("/")
strPath = strFileout[:iFileLoc]
lstDir = os.listdir(strPath)
for strFile in lstDir:
  if strFile.startswith(strFileout[iFileLoc+1:iExtLoc]):
    os.remove(os.path.join(strPath,strFile))

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
          LogEntry("{} hosts in results".format(iResultCount))
        else:
          iTotalCount += 1
          LogEntry ("Only one host in results")
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

LogEntry("Complete, processed {} hosts".format(iTotalCount))
objLogOut.close()
