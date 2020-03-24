'''
Qualys Scanner Appliance Update
Author Siggi Bjarnason Copyright 2017
Website http://www.ipcalc.us/ and http://www.icecomputing.com

Description:
This script will update the comment field of all Qualys Scanning appliance with values supplied by an external file

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
dictParams["action"] = "update"



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

# lstApplianceList = strApplianceList.split(",")
print ("Opening up input file")
objFileIn  = open(strFilein,"r")
strLine = objFileIn.readline()
strComment = ""
# print (strLine)

while strLine:
  strLine = objFileIn.readline()
  strLineParts = strLine.split(",")
  if len(strLineParts) < 14:
    continue
  if strLineParts[2].lower() == "physical":
    strComment = " Net: {}\n Switch: {} {}\n Location: {} {}.{}.{}\n Console: {} ({}) Port {}\n Alt Name: {}\n {}".format(strLineParts[3],
                      strLineParts[4],strLineParts[5],strLineParts[6],strLineParts[7],strLineParts[8],strLineParts[9],
                      strLineParts[10],strLineParts[11],strLineParts[12],strLineParts[13],strLineParts[14])
    strType = "physical/"
  elif strLineParts[2].lower() == "virtual":
    strType = ""
    if strLineParts[10] != "":
      strComment = " Net: {}\n Console: {}\n Alt Name: {}\n {}".format(strLineParts[3],strLineParts[10],strLineParts[13],strLineParts[14])
    else:
      strComment = " Net: {}\n Alt Name: {}\n {}".format(strLineParts[3],strLineParts[13],strLineParts[14])
  else:
    print ("{} is of type {} which is unknown".format(strLineParts[0],strLineParts[2]))
    continue
  print ("{} {}\n{}".format(strLineParts[0], strLineParts[2], strComment))

  dictParams["comment"] = strComment
  dictParams["id"] = strLineParts[1]
  strListScans = urlparse.urlencode(dictParams)
  strURL = strBaseURL + strAPIFunction + strType + "?" + strListScans

  APIResponse = MakeAPICall(strURL,dictHeader,strUserName,strPWD,strMethod)

  if isinstance(APIResponse,dict):
    if "SIMPLE_RETURN" in APIResponse:
      try:
        if "TEXT" in APIResponse["SIMPLE_RETURN"]["RESPONSE"]:
          strTextResponse = APIResponse["SIMPLE_RETURN"]["RESPONSE"]["TEXT"]
        else:
          strTextResponse = "No Response"
        if "VALUE" in APIResponse["SIMPLE_RETURN"]["RESPONSE"]["ITEM_LIST"]["ITEM"]:
          iItemValue = APIResponse["SIMPLE_RETURN"]["RESPONSE"]["ITEM_LIST"]["ITEM"]["VALUE"]
        else:
          iItemValue = -1
        print ("{}. Item ID: {}\n".format(strTextResponse,iItemValue))
      except KeyError as e:
        print ("KeyError: {}".format(e))
        print ("Results: {}\n".format(APIResponse))
    else:
      print ("API Response is not a Simple Return")
  else:
    print ("{}".format(APIResponse))

print ("Done")
# SendNotification ("Scanning Appliance update completed successfully on {}".format(strHostName))
