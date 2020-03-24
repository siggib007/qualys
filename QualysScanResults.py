'''
Script to pull all scan results details data from Qualys
Author Siggi Bjarnason Copyright 2018
Website http://www.ipcalc.us/ and http://www.icecomputing.com

Following packages need to be installed as administrator
pip install requests
pip install xmltodict
pip install pymysql
pip install jason

'''
# Import libraries
import sys
import requests
import os
import time
import xmltodict
import urllib.parse as urlparse
import pymysql
import xml.parsers.expat
import json
import platform
# End imports

dictHeader = {}
iLoc = sys.argv[0].rfind(".")
strConf_File = sys.argv[0][:iLoc] + ".ini"
strScriptName = os.path.basename(sys.argv[0])
strVersion = "{0}.{1}.{2}".format(sys.version_info[0],sys.version_info[1],sys.version_info[2])
ISO = time.strftime("-%m-%d-%Y-%H-%M-%S")

strAPIFunction = "/api/2.0/fo/scan"
dictParams = {}
dictParams["action"] = "fetch"
dictParams["output_format"] = "json_extended"
# dictParams["scan_ref"]="scan/1523671259.42830"
# dictParams["scan_ref"]="scan/1520403158.35120"
# dictParams["scan_ref"]="scan/1524078845.80808"


strScriptHost = platform.node().upper()
if strScriptHost == "DEV-APS-RHEL-STD-A":
  strScriptHost = "VMSAWS01"

print ("This is a script to gather all scan results details from Qualys via API. This is running under Python Version {}".format(strVersion))
now = time.asctime()
print ("The time now is {}".format(now))

def processConf():
  global strBaseURL
  global strHeadReq
  global strUserName
  global strPWD
  global strNotifyURL
  global strNotifyToken
  global strNotifyChannel
  global strSavePath
  global strScanRef

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
        strHeadReq = strValue
      if strVarName == "QUserID":
        strUserName = strValue
      if strVarName == "QUserPWD":
        strPWD = strValue
      if strVarName == "NotificationURL":
        strNotifyURL = strValue
      if strVarName == "NotifyChannel":
        strNotifyChannel = strValue
      if strVarName == "NotifyToken":
        strNotifyToken = strValue
      if strVarName == "NotifyEnabled":
        bNotify = strValue.lower()=="yes" or strValue.lower()=="true"
      if strVarName == "SaveLocation":
        strSavePath = strValue
      if strVarName == "ResultRef":
        strScanRef = strValue

  if strBaseURL[-1:] != "/":
    strBaseURL += "/"

  LogEntry ("Done processing configuration, moving on")

def LogEntry(strMsg,bAbort=False):
  print (strMsg)
  if bAbort:
    sys.exit()

# Function DotDecGen
# Takes a decimal value and converts it to a dotted decimal string
# Number has to be greater than 0 and 32 bits.
def DotDecGen (iDecValue):
  if iDecValue < 1 or iDecValue > 4294967295:
    return "Invalid"
  # end if

  # Convert decimal to hex
  HexValue = hex(iDecValue)

  #Ensure the results is 8 hex digits long.
  #IP's lower than 16.0.0.0 have trailing 0's that get trimmed off by hex function
  HexValue = "0"*8+HexValue[2:]
  HexValue = "0x"+HexValue[-8:]
  # Convert Hex to dot dec
  strTemp = str(int(HexValue[2:4],16)) + "." + str(int(HexValue[4:6],16)) + "."
  strTemp = strTemp + str(int(HexValue[6:8],16)) + "." + str(int(HexValue[8:10],16))
  return strTemp
# End Function

# Function ValidateIP
# Takes in a string and validates that it follows standard IP address format
# Should be four parts with period deliniation
# Each nubmer should be a number from 0 to 255.
def ValidateIP(strToCheck):
  Quads = strToCheck.split(".")
  if len(Quads) != 4:
    return False
  # end if

  for Q in Quads:
    try:
      iQuad = int(Q)
    except ValueError:
      return False
    # end try

    if iQuad > 255 or iQuad < 0:
      return False
    # end if

  return True
# end function

# Function DotDec2Int
# Takes in a string like an IP address or a mask
# returns decimal integer representation of that string
def DotDec2Int (strValue):
  strHex = ""
  if ValidateIP(strValue) == False:
    return 0
  # end if

  Quads = strValue.split(".")
  for Q in Quads:
    QuadHex = hex(int(Q))
    strwp = "00"+ QuadHex[2:]
    strHex = strHex + strwp[-2:]
  # next

  return int(strHex,16)
# end function

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


def ListIPs (strAddress):
  if "-" in strAddress:
    strTemp = strAddress.split("-")
    iStart = DotDec2Int(strTemp[0])
    iStop = DotDec2Int(strTemp[1])+1
    lstAddr=[]
    for iAddr in range(iStart,iStop):
      lstAddr.append(DotDecGen(iAddr))
  else:
    lstAddr = [strAddress]
  return lstAddr

def WriteResults (strMsg,bScreen):
  objFileOut.write ("{}\n".format(strMsg))
  if bScreen:
    print (strMsg)

def FetchScanResults (strScanRef):
  global objFileOut
  dictParams["scan_ref"] = strScanRef
  strScanRefSafe = dictParams["scan_ref"].replace("/","-")
  strOutFileName = strSavePath + strScanRefSafe + ISO +".csv"
  strOutJSONFile = strSavePath + strScanRefSafe + ISO +".json"

  objFileOut = open(strOutFileName,"w")
  objJSONFile = open(strOutJSONFile,"w")
  strListScans = urlparse.urlencode(dictParams)
  strURL = strBaseURL + strAPIFunction +"?" + strListScans

  print ("Doing a get to URL: \n {}\n".format(strURL))
  try:
    WebRequest = requests.get(strURL, headers=dictHeader, auth=(strUserName, strPWD), stream=True)
    print ("get executed")
  except Exception as err:
    print ("Issue with API call. {}".format(err))
    sys.exit(7)

  if isinstance(WebRequest,requests.models.Response)==False:
    print ("response is unknown type")
    sys.exit(5)
  # end if
  print ("call resulted in status code {}".format(WebRequest.status_code))

  if WebRequest.status_code != 200:
    for strLine in WebRequest.iter_lines():
      if strLine:
        strLine = strLine.decode("utf-8")
        print (strLine)
  else:
    iLineNum = 1
    for strLine in WebRequest.iter_lines():
      if strLine:
        strLine = strLine.decode("ascii","ignore")
        objJSONFile.write ("{}\n".format(strLine))
        if strLine[0] == "[":
          strLine = strLine[1:]
        if strLine[-1] == "]":
          strLine = strLine[:-1]
        if strLine[-1] == ",":
          strLine = strLine[:-1]
        try:
          dictResponse = json.loads(strLine)
        except json.decoder.JSONDecodeError as err:
          LogEntry ("Failed to parse JSON: {}\n{}".format(err,strLine),True)
        if "launch_date" in dictResponse:
          print ("")
          WriteResults ("Scan Title: {}".format(dictResponse["scan_title"]),True)
          WriteResults ("Scan Reference: {}".format(dictResponse["reference"]),True)
          WriteResults ("Date Scan Launced: {}".format(dictResponse["launch_date"]),True)
          WriteResults ("Total Number of hosts in scan: {}".format(dictResponse["total_hosts"]),True)
          WriteResults ("Number of active hosts in scan: {}".format(dictResponse["active_hosts"]),True)
          WriteResults ("Option profile: {}\n".format(dictResponse["option_profile"]),True)
          WriteResults ("IP Address,DNS Name,NetBIOS name,Operating System,IP Status,QID,Title,Severity,Port,Protocol,FQDN,SSL",False)
        if "ip" in dictResponse:
          WriteResults ("{},{},{},{},{},{},{},{},{},{},{}".format(dictResponse["ip"],dictResponse["dns"],dictResponse["netbios"],dictResponse["os"],dictResponse["ip_status"].replace(", ","-") ,
            dictResponse["qid"],dictResponse["title"],dictResponse["severity"],dictResponse["port"],dictResponse["protocol"],dictResponse["fqdn"],dictResponse["ssl"]),False)
        if "hosts_not_scanned_host_not_alive_ip" in dictResponse:
          strLineParts = dictResponse["hosts_not_scanned_host_not_alive_ip"].split(",")
          print ("\n\nHosts not alive")
          for strElement in strLineParts:
            lstTemp = ListIPs(strElement.strip())
            for strIPAddr in lstTemp:
              print (strIPAddr)
        if "hosts_not_scanned_excluded_host_ip" in dictResponse:
          strLineParts = dictResponse["hosts_not_scanned_excluded_host_ip"].split(",")
          print ("\nExcluded Hosts")
          for strElement in strLineParts:
            lstTemp = ListIPs(strElement.strip())
            for strIPAddr in lstTemp:
              print (strIPAddr)
        if "host_not_scanned,_scan_canceled_by_user_ip_" in dictResponse:
          strLineParts = dictResponse["host_not_scanned,_scan_canceled_by_user_ip_"].split(",")
          print ("\nNot Scanned, job cancelled")
          for strElement in strLineParts:
            lstTemp = ListIPs(strElement.strip())
            for strIPAddr in lstTemp:
              print (strIPAddr)
        if "no_vulnerabilities_match_your_filters_for_these_hosts" in dictResponse:
          strLineParts = dictResponse["no_vulnerabilities_match_your_filters_for_these_hosts"].split(",")
          print ("\nIndetermined hosts")
          for strElement in strLineParts:
            lstTemp = ListIPs(strElement.strip())
            for strIPAddr in lstTemp:
              print (strIPAddr)
        if "target_distribution_across_scanner_appliances" in dictResponse:
          strLineParts = dictResponse["target_distribution_across_scanner_appliances"].split(",")
          print ("\nScanner appliance target distrobution")
          for strElement in strLineParts:
            if " : " in strElement:
              strTemp = strElement.split(" : ")
              print ("Scanner {}".format(strTemp[0].strip()))
              lstTemp = ListIPs(strTemp[1].strip())
              for strIPAddr in lstTemp:
                print (strIPAddr)
            else:
              lstTemp = ListIPs(strElement.strip())
              for strIPAddr in lstTemp:
                print (strIPAddr)
          print()
        print ("Downloaded {} lines.".format(iLineNum),end="\r")
        iLineNum += 1

    print ("\n\n results written to file {}".format(strOutFileName))
  objFileOut.close()
  objJSONFile.close()

processConf()
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

FetchScanResults (strScanRef)

print ("Done")
SendNotification ("{} completed successfully on {}".format(strScriptName, strScriptHost))
