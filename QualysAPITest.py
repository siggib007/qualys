'''
Qualys API Sample Script
Author Siggi Bjarnason Copyright 2017
Website http://www.ipcalc.us/ and http://www.icecomputing.com

Description:
This is script you can put in your specific Qualys API details and the script will save the raw response to a text as well as process it into a dict and write that to a file.

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

bOpenInEditor = False
# strTextEditor = "subl" #sublime
# strTextEditor = "notepad"
strTextEditor = "uedit64.exe"
iTimeOut = 5

dictHeader = {}
iLoc = sys.argv[0].rfind(".")
strConf_File = sys.argv[0][:iLoc] + ".ini"
strMethod = "get"
bParams = True
# dictHeader["Content-Type"] = "application/json"
# dictHeader["Accept"] = "application/json"

strAPIFunction = "/api/2.0/fo/scan"
# strAPIFunction = "/qps/rest/2.0/get/am/tag/11152949"
# strAPIFunction = "api/2.0/fo/asset/host/vm/detection"
# strAPIFunction = "/api/2.0/fo/knowledge_base/vuln/"
# strAPIFunction = "/api/2.0/fo/appliance"

dictParams = {}
dictParams["action"] = "fetch"
# dictParams["mode"] = "full"
# dictParams["mode"] = "extended"
# dictParams["action"] = "list"
# dictParams["echo_request"] = 1
# dictParams["output_mode"] = "full"
# dictParams["name"] = "SCNSNQ07"
# dictParams["last_modified_by_service_after"] = "2018-04-04"
# dictParams["show_igs"] = 1
# dictParams["launched_after_datetime"]="2015-01-02"
# dictParams["state"] = "Finished"
# dictParams["show_op"] = 1
# dictParams["vm_scan_date_after"]="2018-01-02"
# dictParams["vm_scan_since"]="2018-01-02"
# dictParams["truncation_limit"] = "15"
# dictParams["details"] = "All/AGs"
# dictParams["ids"] = "11415943,13554968,13556160,13556901,13556949,13556955,13558352,13558416,13558453,13559510,13559945,13559981,22386140,22386141,23271764,23289258,23292775,23292928,60771303,60771325,60771399,60771941,60772151,60772711,60773306,60773370,60774808,60774868,60775743,60775851,60776829,60777232,60788269,61321129"
# dictParams["show_tags"] = "1"
dictParams["output_format"] = "json_extended"
# dictParams["output_format"] = "XML"
dictParams["scan_ref"]="scan/1534568265.40093"
# dictParams["show_results"] = "0"
# dictParams["show_reopened_info"] = "1"
# dictParams["id_min"] = 0
# dictParams["status"] = "New,Active,Re-Opened,Fixed"
# dictParams["detection_updated_since"]="2018-03-13"
# dictParams["qids"] = "87313"
# dictParams["max_days_since_last_vm_scan"] = "1"
# dictParams["ips"] = "10.158.20.151-10.158.20.152, 10.158.20.234-10.158.20.235, 10.158.20.238, 10.158.20.240, 10.158.21.26, 10.158.143.187, 10.158.150.87, 10.158.150.90, 10.158.150.95-10.158.150.96, 10.158.150.101, 10.158.150.104-10.158.150.105, 10.158.150.108, 10.158.152.61, 10.158.198.164, 10.158.198.190, 206.29.171.129"
# dictParams["username"] = "MyTesting"
# dictParams["password"] = "qawerewrqwert"

strHostName = platform.node().upper()
print ("This is a Qualys API Sample script. This is running under Python Version {0}.{1}.{2} on {3}".format(sys.version_info[0],sys.version_info[1],sys.version_info[2],strHostName))
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


print ("calculating stuff ...")
dictHeader["X-Requested-With"] = strHeadReq

if strBaseURL[-1:] != "/":
  strBaseURL += "/"

if strAPIFunction[0] == "/":
  strAPIFunction = strAPIFunction[1:]

if strAPIFunction[-1:] != "/":
  strAPIFunction += "/"

if strSavePath[-1:] != "\\":
  strSavePath += "\\"

if strAPIFunction[:11]=="api/2.0/fo/":
  strAPIName = strAPIFunction[11:-1].replace("/","-")
elif strAPIFunction[:13]=="qps/rest/2.0/":
  strAPIName = strAPIFunction[13:-1].replace("/","-")
else:
  strAPIName = strAPIFunction[:-1].replace("/","-")

if "Content-Type" in dictHeader:
  if dictHeader["Content-Type"] == "application/json":
    strType = "json"
  else:
    strType = "xml"
else:
  strType = "xml"

if "output_format" in dictParams:
  if dictParams["output_format"][:4] == "json":
    strType = "json"
  else:
    strType = dictParams["output_format"]

if bParams:
  if "action" in dictParams:
    strAction = "-" + dictParams["action"]
  else:
    strAction = ""
else:
  strAction = ""

ISO = time.strftime("-%m-%d-%Y-%H-%M-%S")
strRAWout = strSavePath + strAPIName + strAction + ISO +"." + strType
strResponseOut = strSavePath + strAPIName + strAction + ISO +"-out.txt"

print ("API Function: {}".format(strAPIFunction))
print ("APIName: {}".format(strAPIName))

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
  global strType

  iErrCode = ""
  iErrText = ""
  dictResponse = {}

  print ("Doing a {} to URL: \n {}\n".format(strMethod,strURL))
  try:
    if strMethod.lower() == "get":
      WebRequest = requests.get(strURL,timeout=iTimeOut, headers=dictHeader, auth=(strUserName, strPWD))
      print ("get executed")
    if strMethod.lower() == "post":
      WebRequest = requests.post(strURL,timeout=iTimeOut, headers=dictHeader, auth=(strUserName, strPWD))
      print ("post executed")
  # except requests.exceptions.ReadTimeout as err:
  except Exception as err:
    print ("Issue with API call. {}".format(err))
    # raise
    sys.exit(7)

  if isinstance(WebRequest,requests.models.Response)==False:
    print ("response is unknown type")
    sys.exit(5)
  # end if
  print ("call resulted in status code {}".format(WebRequest.status_code))
  objFileOut = open(strRAWout,"w")
  objFileOut.write ("{}".format(WebRequest.text))
  objFileOut.close()
  print ("{} results written to file {}".format(strType, strRAWout))

  if WebRequest.text[:2] == "[{":
    strType = "json"
  if WebRequest.text[:5] == "<?xml":
    strType = "xml"
  if strType.lower() == "xml":
    try:
      dictResponse = xmltodict.parse(WebRequest.text)
      print ("xml loaded into dictionary")
    except xml.parsers.expat.ExpatError as err:
      print ("Expat Error: {}\n{}".format(err,WebRequest.text))
      iErrCode = "Expat Error"
      iErrText = "Expat Error: {}\n{}".format(err,WebRequest.text)
  elif strType == "json" :
    dictResponse = json.loads(WebRequest.text)
    print ("json loaded into dictionary")
  else:
    dictResponse = {}

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


if bParams:
  strListScans = urlparse.urlencode(dictParams)
  strURL = strBaseURL + strAPIFunction +"?" + strListScans
else:
  strURL = strBaseURL + strAPIFunction

APIResponse = MakeAPICall(strURL,dictHeader,strUserName,strPWD,strMethod)

if isinstance(APIResponse,dict):
  if len(APIResponse)>0:
    objFileOut = open(strResponseOut,"w")
    objFileOut.write ("{}".format(APIResponse))
    objFileOut.close()
    print ("dictionary results written to file {}".format(strResponseOut))
    if bOpenInEditor:
      strCmdLine = "{0} \"{1}\"".format(strTextEditor,strResponseOut)
      print (strCmdLine)
      proc.Popen(strCmdLine)
if isinstance(APIResponse,str):
  print (APIResponse)

if bOpenInEditor:
  strCmdLine = "{0} \"{1}\"".format(strTextEditor,strRAWout)
  print (strCmdLine)
  proc.Popen(strCmdLine)

print ("Done")
# SendNotification ("APITest completed successfully on {}".format(strHostName))
