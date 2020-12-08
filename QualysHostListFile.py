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
    objCSVOut.close()
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
  global strHostIDs

  strBaseURL = ""
  strHeader = ""
  strUserName = ""
  strPWD = ""
  strFileout = ""
  iBatchSize = 1000
  strHostIDs = ""

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
      if strVarName == "OutfileName":
        strFileout  = strValue
      if strVarName == "HostIDs":
        strHostIDs  = strValue
      if strVarName == "BatchSize":
        iBatchSize = int(strValue)

  if strBaseURL[-1:] != "/":
    strBaseURL += "/"

  LogEntry ("Done processing configuration, moving on")

def MakeAPICall (strURL, strHeader, strUserName,strPWD, strMethod):
  global rawAPIResponse
  global dictResponse
  global strErrCode

  strErrCode = ""
  strErrText = ""
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
    strErrCode = "ResponseErr"
    strErrText = "response is unknown type"

  LogEntry ("call resulted in status code {}".format(WebRequest.status_code))
  if WebRequest.status_code == 200:
    rawAPIResponse = WebRequest.text
  else:
    rawAPIResponse = ""
    LogEntry(WebRequest.text)

  try:
    dictResponse = xmltodict.parse(WebRequest.text)
  except xml.parsers.expat.ExpatError as err:
    # LogEntry("Expat Error: {}\n{}".format(err,WebRequest.text))
    strErrCode = "Expat Error"
    strErrText = "Expat Error: {}\n{}".format(err,WebRequest.text)
  except Exception as err:
    LogEntry("Unkown xmltodict exception: {}".format(err))
    CleanExit(", Unkown xmltodict exception, please check the logs")

  if isinstance(dictResponse,dict):
    if "SIMPLE_RETURN" in dictResponse:
      try:
        if "CODE" in dictResponse["SIMPLE_RETURN"]["RESPONSE"]:
          strErrCode = dictResponse["SIMPLE_RETURN"]["RESPONSE"]["CODE"]
        if "TEXT" in dictResponse["SIMPLE_RETURN"]["RESPONSE"]:
          strErrText = dictResponse["SIMPLE_RETURN"]["RESPONSE"]["TEXT"]

      except KeyError as e:
        LogEntry ("KeyError: {}".format(e))
        LogEntry (WebRequest.text)
        strErrCode = "Unknown"
        strErrText = "Unexpected error"
  else:
    LogEntry ("Response not a dictionary",True)

  if strErrCode != "" or WebRequest.status_code !=200:
    return "There was a problem with your request. HTTP error {} code {} {}".format(WebRequest.status_code,strErrCode,strErrText)
  else:
    return dictResponse

def Write2CSV (dictResults):
  if "DNS" in dictResults:
    strDNS = dictResults["DNS"]
  else:
    strDNS = "No DSN"
  if "NETBIOS" in dictResults:
    strNetBIOS = dictResults["NETBIOS"]
  else:
    strNetBIOS = "No NetBIOS"
  if "IP" in dictResults:
    strIPaddr = dictResults["IP"]
  else:
    strIPaddr = "No IP"
  if "ID" in dictResults:
    strHostID = dictResults["ID"]
  else:
    strHostID = "No ID"
  if "OS" in dictResults:
    strOS = dictResults["OS"]
  else:
    strOS = "No OS"
  strOS = strOS.replace(","," ")
  objCSVOut.write("{},{},{},{},{}\n".format(strHostID,strDNS,strNetBIOS,strIPaddr,strOS))

processConf()

LogEntry("Starting Processing. Script {} running under Python version {}".format(strRealPath,strVersion))

strAPIFunction = "/api/2.0/fo/asset/host/"
if strAPIFunction[0] == "/":
  strAPIFunction = strAPIFunction[1:]

if strAPIFunction[-1:] != "/":
  strAPIFunction += "/"

strFileout = strFileout.replace("\\","/")
if not os.path.exists(os.path.dirname(strFileout)):
  LogEntry ("Path '{0}' for output files didn't exists, so I'm creating it!".format(strFileout))
  os.makedirs(os.path.dirname(strFileout))

LogEntry ("API Function: {}".format(strAPIFunction))

strMethod = "get"
dictParams = {}
dictParams["action"] = "list"
dictParams["truncation_limit"] = iBatchSize
if strHostIDs != "" :
  dictParams["ids"] = strHostIDs

strListScans = urlparse.urlencode(dictParams)
bMoreData = True
bSuccess = True
objCSVOut = None
iTotalCount = 0
iCount = 1

iExtLoc = strFileout.rfind(".")
iFileLoc = strFileout.rfind("/")
strPath = strFileout[:iFileLoc]
lstDir = os.listdir(strPath)

strCSVName = strFileout[:iExtLoc] + ".csv"

strURL = strBaseURL + strAPIFunction +"?" + strListScans

APIResponse = MakeAPICall(strURL,strHeader,strUserName,strPWD,strMethod)

while strErrCode == "1965":
  LogEntry ("Got Error 409 Code 1965, looking for retry interval")
  if "ITEM_LIST" in dictResponse["SIMPLE_RETURN"]["RESPONSE"]:
    iRetrySec = dictResponse["SIMPLE_RETURN"]["RESPONSE"]["ITEM_LIST"]["ITEM"]["VALUE"]
    LogEntry("retrying in {} sec".format(iRetrySec))
    time.sleep(iRetrySec)
    APIResponse = MakeAPICall(strURL,strHeader,strUserName,strPWD,strMethod)

if isinstance (APIResponse,str):
  LogEntry (APIResponse)
  bMoreData = False
  bSuccess = False
else:
  for strFile in lstDir:
    if strFile.startswith(strFileout[iFileLoc+1:iExtLoc]):
      os.remove(os.path.join(strPath,strFile))
  objCSVOut = open(strCSVName,"w",1)
  objCSVOut.write("AssetID,DNS,NetBIOS,IP,OS\n")

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
    bSuccess = False
  if isinstance(APIResponse,dict):
    LogEntry("CSV Output will be written to {}".format(strCSVName))
    if "HOST_LIST" in APIResponse["HOST_LIST_OUTPUT"]["RESPONSE"]:
      if "HOST" in APIResponse["HOST_LIST_OUTPUT"]["RESPONSE"]["HOST_LIST"]:
        if isinstance(APIResponse["HOST_LIST_OUTPUT"]["RESPONSE"]["HOST_LIST"]["HOST"],list):
          iResultCount = len(APIResponse["HOST_LIST_OUTPUT"]["RESPONSE"]["HOST_LIST"]["HOST"])
          iTotalCount += iResultCount
          LogEntry("{} hosts in results".format(iResultCount))
          for dictHosts in APIResponse["HOST_LIST_OUTPUT"]["RESPONSE"]["HOST_LIST"]["HOST"]:
            Write2CSV(dictHosts)
        else:
          iTotalCount += 1
          LogEntry ("Only one host in results")
          Write2CSV (APIResponse["HOST_LIST_OUTPUT"]["RESPONSE"]["HOST_LIST"]["HOST"])
        LogEntry("total processed so far {}".format(iTotalCount))
      else:
        LogEntry("there is hosts list but no hosts, weird!!!!")
    else:
      LogEntry ("There are no results")
    if "WARNING" in APIResponse["HOST_LIST_OUTPUT"]["RESPONSE"]:
      strURL = APIResponse["HOST_LIST_OUTPUT"]["RESPONSE"]["WARNING"]["URL"]
      LogEntry ("Next URL: {}".format(strURL))
      APIResponse = MakeAPICall(strURL,strHeader,strUserName,strPWD,strMethod)
      while strErrCode == 1965:
        LogEntry ("Got Error 409 Code 1965, looking for retry interval")
        if "ITEM_LIST" in dictResponse["SIMPLE_RETURN"]["RESPONSE"]:
          iRetrySec = dictResponse["SIMPLE_RETURN"]["RESPONSE"]["ITEM_LIST"]["ITEM"]["VALUE"]
          LogEntry("retrying in {} sec".format(iRetrySec))
          time.sleep(iRetrySec)
          APIResponse = MakeAPICall(strURL,strHeader,strUserName,strPWD,strMethod)      
    else:
      bMoreData = False

if bSuccess:
  LogEntry("Complete, processed {} hosts".format(iTotalCount))
else:
  LogEntry("API FAILURE, ABORTED. Only processed {} hosts".format(iTotalCount))
  if objCSVOut is not None:
    objCSVOut.write("APIResponse\n")

objLogOut.close()
if objCSVOut is not None:
  objCSVOut.close()
