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
  global strParam
  global strAPIObject

  strBaseURL = ""
  strHeader = ""
  strUserName = ""
  strPWD = ""
  strFileout = ""
  strParam = ""
  strAPIObject = ""
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
      if strVarName == "ParaMeters":
        strParam  = strValue
      if strVarName == "APIObject":
        strAPIObject  = strValue
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

strMethod = "get"
dictParams = {}

if strParam != "":
  lstStrParts = strParam.split("|")
  for strFilter in lstStrParts:
    lstFilterParts = strFilter.split(":")
    if len(lstFilterParts) > 1:
      if isInt(lstFilterParts[1]):
        dictParams[lstFilterParts[0]] = int(lstFilterParts[1])
      elif lstFilterParts[1][0]=="[":
        lstTmp = lstFilterParts[1][1:-1].split(",")
        lstClean = []
        for strTemp in lstTmp:
          if isInt(strTemp):
            lstClean.append(int(strTemp))
          else:
            lstClean.append(strTemp)
        dictParams[lstFilterParts[0]] = lstClean
      else:
        dictParams[lstFilterParts[0]] = lstFilterParts[1]
  LogEntry ("Found filter:{}".format(dictParams))

dictParams["action"] = "list"
dictParams["truncation_limit"] = iBatchSize

strFileout = strFileout.replace("\\","/")
if not os.path.exists(os.path.dirname(strFileout)):
  LogEntry ("Path '{0}' for output files didn't exists, so I'm creating it!".format(strFileout))
  try:
    os.makedirs(os.path.dirname(strFileout))
  except Exception as err:
    LogEntry ("failed to create output path. Error: {}".format(err),True)


LogEntry ("API Function: {}".format(strAPIFunction))

if strAPIObject == "":
  iLoc = strAPIFunction.rfind("/",0,-1)
  strAPIObject = strAPIFunction[iLoc+1:-1].upper()
strObjListOutput = "{}_LIST_OUTPUT".format(strAPIObject)
strObjList = "{}_LIST".format(strAPIObject)
LogEntry("We are working with {} object, with {} and {}".format(strAPIObject,strObjListOutput,strObjList))

LogEntry("Base filename provided: {}".format(strFileout))

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
    try:
      os.remove(os.path.join(strPath,strFile))
    except Exception as err:
      LogEntry ("Error while attempting to delete {}. Error:{}".format(strFile,err))

strURL = strBaseURL + strAPIFunction +"?" + strListScans

APIResponse = MakeAPICall(strURL,strHeader,strUserName,strPWD,strMethod)

while bMoreData:
  if rawAPIResponse != "":
    rawAPIResponse = rawAPIResponse.encode("ascii", "ignore")
    rawAPIResponse = rawAPIResponse.decode("ascii", "ignore")
    iLoc = strFileout.rfind(".")
    strFileChunkName = "{}-{}{}".format(strFileout[:iLoc],iCount,strFileout[iLoc:])
    LogEntry("Writing results to {}".format(strFileChunkName))
    objOutFile = open(strFileChunkName,"w",1)
    try:
      objOutFile.write(rawAPIResponse)
    except Exception as err:
      LogEntry("Error when writing raw file: Error:{}".format(err),True)
    objOutFile.close()
    iCount += 1
  if isinstance (APIResponse,str):
    LogEntry (APIResponse)
    bMoreData = False
  if isinstance(APIResponse,dict):
    if strObjListOutput in APIResponse:
      if "RESPONSE" in APIResponse[strObjListOutput]:
        if strObjList in APIResponse[strObjListOutput]["RESPONSE"]:
          if strAPIObject in APIResponse[strObjListOutput]["RESPONSE"][strObjList]:
            if isinstance(APIResponse[strObjListOutput]["RESPONSE"][strObjList][strAPIObject],list):
              iResultCount = len(APIResponse[strObjListOutput]["RESPONSE"][strObjList][strAPIObject])
              iTotalCount += iResultCount
              LogEntry("{} hosts in results".format(iResultCount))
            else:
              iTotalCount += 1
              LogEntry ("Only one host in results")
            LogEntry("total processed so far {}".format(iTotalCount))
          else:
            LogEntry("there is an object list but no objects, weird!!!!")
        else:
          LogEntry ("There are no Object List")
          bMoreData = False
        if "WARNING" in APIResponse[strObjListOutput]["RESPONSE"]:
          strURL = APIResponse[strObjListOutput]["RESPONSE"]["WARNING"]["URL"]
          LogEntry ("Next URL: {}".format(strURL))
          APIResponse = MakeAPICall(strURL,strHeader,strUserName,strPWD,strMethod)
        else:
          bMoreData = False
      else:
        LogEntry ("No Response Object")
        bMoreData = False
    else:
      LogEntry ("No List Output")
      bMoreData = False

LogEntry("Complete, processed {} hosts".format(iTotalCount))
objLogOut.close()
