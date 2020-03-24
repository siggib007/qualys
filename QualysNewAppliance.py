'''
Qualys Scanner Appliance Create
Author Siggi Bjarnason Copyright 2017
Website http://www.ipcalc.us/ and http://www.icecomputing.com

Description:
This script will create new virtual appliances based on supplied name field

Following packages need to be installed as administrator
pip install requests
pip install xmltodict
pip install jason

'''
# Import libraries
import sys
import requests
import os
import string
import time
import xmltodict
import urllib.parse as urlparse
import subprocess as proc
import xml.parsers.expat
import json
import platform
# End imports


dictHeader = {}
iLoc = sys.argv[0].rfind(".")
strConf_File = sys.argv[0][:iLoc] + ".ini"
strMethod = "post"

strAPIFunction = "/api/2.0/fo/appliance"
dictParams = {}
dictParams["action"] = "create"



strHostName = platform.node().upper()
print ("This is a script that updates Qualys Scanning appliance. This is running under Python Version {0}.{1}.{2} on {3}".format(
  sys.version_info[0],sys.version_info[1],sys.version_info[2],strHostName))
now = time.asctime()
print ("The time now is {}".format(now))

if os.path.isfile(strConf_File):
  print ("Configuration File exists")
else:
  print ("Can't find configuration file {}, make sure it is the same directory as this script".format(strConf_File))
  sys.exit(4)

strLine = "  "
print ("Reading in configuration")
objINIFile = open(strConf_File,"r")
strLines = objINIFile.readlines()
objINIFile.close()

for strLine in strLines:
  strLine = strLine.strip()
  if "=" in strLine:
    strConfParts = strLine.split("=")
    if strConfParts[0] == "APIBaseURL":
      strBaseURL = strConfParts[1]
    if strConfParts[0] == "APIRequestHeader":
      strHeadReq = strConfParts[1]
    if strConfParts[0] == "QUserID":
      strUserName = strConfParts[1]
    if strConfParts[0] == "QUserPWD":
      strPWD = strConfParts[1]
    if strConfParts[0] == "SaveLocation":
      strSavePath = strConfParts[1]
    if strConfParts[0] == "NotificationURL":
      strNotifyURL = strConfParts[1]
    if strConfParts[0] == "NotifyChannel":
      strNotifyChannel = strConfParts[1]
    if strConfParts[0] == "NotifyToken":
      strNotifyToken = strConfParts[1]
    if strConfParts[0] == "infile":
      strFilein = strConfParts[1]

print ("calculating stuff ...")
dictHeader["X-Requested-With"] = strHeadReq

if strBaseURL[-1:] != "/":
  strBaseURL += "/"

if strAPIFunction[0] == "/":
  strAPIFunction = strAPIFunction[1:]

if strAPIFunction[-1:] != "/":
  strAPIFunction += "/"

def LogEntry(strMsg):
  print (strMsg)

def SendNotification (strMsg):
  dictNotify = {}
  dictNotify["token"] = strNotifyToken
  dictNotify["channel"] = strNotifyChannel
  dictNotify["text"]=strMsg
  strNotifyParams = urlparse.urlencode(dictNotify)
  strURL = strNotifyURL + "?" + strNotifyParams
  bStatus = False
  try:
    WebRequest = requests.get(strURL)
  except Exception as err:
    LogEntry ("Issue with sending notifications. {}".format(err))
  if isinstance(WebRequest,requests.models.Response)==False:
    LogEntry ("response is unknown type")
  else:
    dictResponse = json.loads(WebRequest.text)
    if isinstance(dictResponse,dict):
      if "ok" in dictResponse:
        bStatus = dictResponse["ok"]
    if not bStatus or WebRequest.status_code != 200:
      LogEntry ("Problme: Status Code:[] API Response OK={}")
      LogEntry (WebRequest.text)


def MakeAPICall (strURL, dictHeader, strUserName,strPWD, strMethod):

  iErrCode = ""
  iErrText = ""
  dictResponse = {}

  print ("Doing a {} to URL: \n {}\n".format(strMethod,strURL))
  try:
    if strMethod.lower() == "get":
      WebRequest = requests.get(strURL, headers=dictHeader, auth=(strUserName, strPWD))
      print ("get executed")
    if strMethod.lower() == "post":
      WebRequest = requests.post(strURL, headers=dictHeader, auth=(strUserName, strPWD))
      print ("post executed")
  except Exception as err:
    print ("Issue with API call. {}".format(err))
    raise
    sys.exit(7)

  if isinstance(WebRequest,requests.models.Response)==False:
    print ("response is unknown type")
    sys.exit(5)
  # end if
  print ("call resulted in status code {}".format(WebRequest.status_code))

  try:
    dictResponse = xmltodict.parse(WebRequest.text)
  except xml.parsers.expat.ExpatError as err:
    print ("Expat Error: {}\n{}".format(err,WebRequest.text))
    iErrCode = "Expat Error"
    iErrText = "Expat Error: {}\n{}".format(err,WebRequest.text)


  if isinstance(dictResponse,dict):
    if "SIMPLE_RETURN" in dictResponse:
      try:
        if "CODE" in dictResponse["SIMPLE_RETURN"]["RESPONSE"]:
          iErrCode = dictResponse["SIMPLE_RETURN"]["RESPONSE"]["CODE"]
          iErrText = dictResponse["SIMPLE_RETURN"]["RESPONSE"]["TEXT"]
      except KeyError as e:
        print ("KeyError: {}".format(e))
        print (WebRequest.text)
        iErrCode = "Unknown"
        iErrText = "Unexpected error"
  elif isinstance(dictResponse,list):
    print ("Response is a list of {} elements".format(len(dictResponse)))
    print ("First element is of type {}".format(type(dictResponse[0])))
  else:
    print ("Response not a dictionary or a list. it's {}".format(type(dictResponse)))
    sys.exit(8)

  if iErrCode != "" or WebRequest.status_code !=200:
    return "There was a problem with your request. HTTP error {} code {} {}".format(WebRequest.status_code,iErrCode,iErrText)
  else:
    return dictResponse

iLoc = strFilein.rfind(".")
strOutFile = strFilein[:iLoc] + "-results" + strFilein[iLoc:]
print ("Opening the outfile {}".format(strOutFile))
objFileOut = open(strOutFile,"w")
objFileOut.write ("Element ID,Appliance ID,Type,Friendly Name,Auth Code\n")

print ("Opening up input file")
objFileIn  = open(strFilein,"r")
strLine = "xyz"
while strLine:
  strLine = objFileIn.readline()
  strLineParts = strLine.split(",")
  if len(strLineParts) < 1 or strLineParts[0] == "":
    continue

  dictParams["name"] = strLineParts[0].strip()
  strListScans = urlparse.urlencode(dictParams)
  strURL = strBaseURL + strAPIFunction + "?" + strListScans

  APIResponse = MakeAPICall(strURL,dictHeader,strUserName,strPWD,strMethod)

  if isinstance(APIResponse,dict):
    if "APPLIANCE_CREATE_OUTPUT" in APIResponse:
      try:
        if "ID" in APIResponse["APPLIANCE_CREATE_OUTPUT"]["RESPONSE"]["APPLIANCE"]:
          iScannerID = APIResponse["APPLIANCE_CREATE_OUTPUT"]["RESPONSE"]["APPLIANCE"]["ID"]
        else:
          iScannerID = -1
        if "ACTIVATION_CODE" in APIResponse["APPLIANCE_CREATE_OUTPUT"]["RESPONSE"]["APPLIANCE"]:
          iActivationCode = APIResponse["APPLIANCE_CREATE_OUTPUT"]["RESPONSE"]["APPLIANCE"]["ACTIVATION_CODE"]
        else:
          iActivationCode = -1
        if "FRIENDLY_NAME" in APIResponse["APPLIANCE_CREATE_OUTPUT"]["RESPONSE"]["APPLIANCE"]:
          strName = APIResponse["APPLIANCE_CREATE_OUTPUT"]["RESPONSE"]["APPLIANCE"]["FRIENDLY_NAME"]
        else:
          strName = "unknown"
        print ("{} ID {}. Activation Code: {}\n".format(strName, iScannerID, iActivationCode))
      except KeyError as e:
        print ("KeyError: {}".format(e))
        print ("Results: {}\n".format(APIResponse))
        iScannerID = -1
        iActivationCode = -1
        strName = "KeyError"
    else:
      print ("API Response is not APPLIANCE_CREATE_OUTPUT")
      iScannerID = -1
      iActivationCode = -1
      strName = "Response Issue"
  else:
    print ("{}".format(APIResponse))
    iScannerID = -1
    iActivationCode = -1
    strName = "Error"
  objFileOut.write ("{},{},Virtual,{},{}\n".format(strLineParts[0].strip(),iScannerID,strName,iActivationCode))

print ("Done")
# SendNotification ("Scanning Appliance update completed successfully on {}".format(strHostName))
