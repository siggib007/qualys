'''
Qualys API Scan Results Report Generator
Version 1.0

Author Siggi Bjarnason Copyright 2018
Website http://www.ipcalc.us/ and http://www.icecomputing.com

Description:
This is script will search for scans launched by certain user, during certain time period, who's name matches supplied keyword
and will generate and excel based scan results report based on downloaded raw scan results

Following packages need to be installed as administrator
pip install requests
pip install xmltodict
pip install pymysql
pip install pyodbc
pip install pypiwin32
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
import json
import re
import win32com.client as win32
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
strSearchCrit = ""
strSaveLoc = ""
iLineNum = 0
iMinSev = 2

olMailItem = 0
xlTop=-4160
xlCenter=-4108
xlBottom=-4107
xlLeft=-4131
xlCenter=-4108
xlRight=-4152
xlSrcExternal = 0 #External data source
xlSrcModel = 4 #PowerPivot Model
xlSrcQuery = 3 #Query
xlSrcRange = 1 #Range
xlSrcXml = 2 #XML
xlGuess = 0 # Excel determines whether there is a header, and where it is, if there is one.
xlNo = 2 # Default. The entire range should be sorted.
xlYes = 1 # The entire range should not be sorted.

strScriptHost = platform.node().upper()
if strScriptHost == "DEV-APS-RHEL-STD-A":
  strScriptHost = "VMSAWS01"

def SendNotification (strMsg):
  dictNotify = {}
  dictNotify["token"] = strNotifyToken
  dictNotify["channel"] = strNotifyChannel
  dictNotify["text"]=strMsg[:199]
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

def getInput(strPrompt):
    if sys.version_info[0] > 2 :
        return input(strPrompt)
    else:
        return raw_input(strPrompt)
# end getInput

def processConf():
  global strBaseURL
  global dictHeader
  global strUserName
  global strPWD
  global strNotifyURL
  global strNotifyToken
  global strNotifyChannel
  global strSaveLoc
  global iNumDays
  global strTimeLastNight
  global strFilterUser
  global strSearchCrit
  global iMinSev
  global strEmailTo
  global strEmailSubject
  global strEmailIntro

  if os.path.isfile(strConf_File):
    LogEntry ("Configuration File exists")
  else:
    LogEntry ("Can't find configuration file {}, "
      " make sure it is the same directory as this script".format(strConf_File),True)

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
        dictHeader={'X-Requested-With': strValue}
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
      if strVarName == "ShowNumDays":
        if isInt(strValue):
          iNumDays = int(strValue)
        else:
          print ("Invalid value: {}, setting iNumDays to 1".format(strLine))
          iNumDays = 1
      if strVarName == "MinSeverity":
        if isInt(strValue):
          iMinSev = int(strValue)
        else:
          print ("Invalid value: {}, setting iMinSev to 2".format(strLine))
          iMinSev = 2
      if strVarName == "ShowStartTime":
        strTimeLastNight = str(strValue)
      if strVarName == "FilterByUser":
        strFilterUser = strValue
      if strVarName == "ReportSaveLocation":
        strSaveLoc = strValue
      if strVarName == "KeyWord":
        strSearchCrit = strValue
      if strVarName == "EmailTo":
        strEmailTo = strValue
      if strVarName == "EmailSubject":
        strEmailSubject = strValue
      if strVarName == "EmailIntro":
        strEmailIntro = strValue

  if strBaseURL[-1:] != "/":
    strBaseURL += "/"
  if strSaveLoc[-1:] != "\\":
    strSaveLoc += "\\"

  LogEntry ("Done processing configuration, moving on")

def MakeAPICall (strURL, dictHeader, strUserName,strPWD, strMethod):

  iErrCode = ""
  iErrText = ""
  WebRequest = None
  dictResponse = {}

  LogEntry ("Doing a {} to URL: \n {}\n".format(strMethod,strURL))
  try:
    if strMethod.lower() == "get":
      WebRequest = requests.get(strURL, headers=dictHeader, auth=(strUserName, strPWD))
      LogEntry ("get executed")
    elif strMethod.lower() == "post":
      WebRequest = requests.post(strURL, headers=dictHeader, auth=(strUserName, strPWD))
      LogEntry ("post executed")
    else:
      LogEntry ("Unkown method {}".format(strMethod),True)
  except Exception as err:
    LogEntry ("Issue with API call. {}".format(err))
    CleanExit("due to issue with API, please check the logs")

  if isinstance(WebRequest,requests.models.Response)==False:
    LogEntry ("response is unknown type")
    iErrCode = "ResponseErr"
    iErrText = "response is unknown type: {}".format(type(WebRequest))

  LogEntry ("call resulted in status code {}".format(WebRequest.status_code))

  try:
    dictResponse = xmltodict.parse(WebRequest.text)
  except xml.parsers.expat.ExpatError as err:
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
        LogEntry ("KeyError while decoding error response in XML: {}".format(e))
        LogEntry (WebRequest.text)
        iErrCode = "Unknown"
        iErrText = "Unexpected error"
  else:
    LogEntry ("Aborting abnormally because API response not translated to a dictionary",True)

  if iErrCode != "" or WebRequest.status_code !=200:
    return "There was a problem with your request. "
    " HTTP error {} code {} {}".format(WebRequest.status_code,iErrCode,iErrText)
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

def QD2Human (strDate):
  return time.strftime("%m/%d/%Y %H:%M %Z",time.localtime(time.mktime(time.strptime(strDate,"%Y-%m-%dT%H:%M:%SZ"))))

def ConvertFloat (fValue):
  if isinstance(fValue,(float,int,str)):
    try:
      fTemp = float(fValue)
    except ValueError:
      fTemp = "NULL"
  else:
    fTemp = "NULL"
  return fTemp

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

def UpdateAppliance():
  iRowNum = 2
  while wsSource.Cells(iRowNum,1).Value != "" and wsSource.Cells(iRowNum,1).Value is not None:
    strApplianceName = wsSource.Cells(iRowNum,1).Value
    strAPIFunction = "/api/2.0/fo/appliance/?"
    dictParams={}
    dictParams["action"] = "list"
    dictParams["output_mode"] = "full"
    dictParams["name"] = strApplianceName
    strListScans = urlparse.urlencode(dictParams)
    strURL = strBaseURL + strAPIFunction + strListScans
    LogEntry ("Fetching details about scan appliance {}".format(strApplianceName))
    APIResponse = MakeAPICall(strURL,dictHeader,strUserName,strPWD,"Get")
    if isinstance (APIResponse,str):
      LogEntry ("API Response is a string: {}".format(APIResponse))
      break
    else:
      if "APPLIANCE_LIST_OUTPUT" in APIResponse:
        if "RESPONSE" in APIResponse["APPLIANCE_LIST_OUTPUT"]:
          if "APPLIANCE_LIST" in APIResponse["APPLIANCE_LIST_OUTPUT"]["RESPONSE"]:
            if "APPLIANCE" in APIResponse["APPLIANCE_LIST_OUTPUT"]["RESPONSE"]["APPLIANCE_LIST"]:
              dictAppliance = APIResponse["APPLIANCE_LIST_OUTPUT"]["RESPONSE"]["APPLIANCE_LIST"]["APPLIANCE"]
              wsSource.Cells(iRowNum,2).Value = dictAppliance["ML_VERSION"]["#text"]
              wsSource.Cells(iRowNum,3).Value = dictAppliance["VULNSIGS_VERSION"]["#text"]
              wsSource.Cells(iRowNum,4).Value = dictAppliance["INTERFACE_SETTINGS"][0]["IP_ADDRESS"]
              iRowNum += 1
            else:
              print ("No appliance in apppliance list: {}".format(
                APIResponse["APPLIANCE_LIST_OUTPUT"]["RESPONSE"]["APPLIANCE_LIST"]))
          else:
            print ("No appliance list in response: {}".format(APIResponse["APPLIANCE_LIST_OUTPUT"]["RESPONSE"]))
        else:
          print ("No response element in APPLIANCE_LIST_OUTPUT: {}".format(APIResponse["APPLIANCE_LIST_OUTPUT"]))
      else:
          print ("No APPLIANCE_LIST_OUTPUT in APIResponse: {}".format(APIResponse))
  objWB.Save()



def FetchScanResults (strScanRef,strScanTitle):
  global iLineNum
  global wsSource
  global objWB
  global strFileName
  global dictSummary

  strSafeTitle = re.sub('[^\w\-_\. ]', '', strScanTitle)
  strFileName = strSaveLoc + strSafeTitle + ISO + ".xlsx"
  LogEntry ("Saving report to {}".format(strFileName))
  LogEntry ("starting Excel...")
  try:
    app = win32.gencache.EnsureDispatch('Excel.Application')
  except:
    LogEntry ("unable to start excel",True)

  LogEntry ("adding new Workbook")
  objWB = app.Workbooks.Add()
  LogEntry ("adding worksheets with headers, labels and stuff")
  wsSummary = objWB.ActiveSheet
  wsSummary.Name = "Summary"
  wsSummary.Cells(1,1).Value = "Launch Date"
  wsSummary.Cells(2,1).Value = "Active Hosts"
  wsSummary.Cells(3,1).Value = "Total Hosts"
  wsSummary.Cells(4,1).Value = "Type"
  wsSummary.Cells(5,1).Value = "Status"
  wsSummary.Cells(6,1).Value = "Scan Reference"
  wsSummary.Cells(7,1).Value = "Duration"
  wsSummary.Cells(8,1).Value = "Scan Title"
  wsSummary.Cells(9,1).Value = "Asset Groups"
  wsSummary.Cells(10,1).Value = "Option Profile"
  wsSummary.Range("A1:A10").Font.Bold = True
  wsSummary.Range("A1:A10").HorizontalAlignment = xlRight
  wsSummary.Columns("A:A").EntireColumn.AutoFit()
  objWB.Sheets.Add(After=wsSummary)
  wsResults = objWB.ActiveSheet
  wsResults.Name = "Scan Results"
  wsResults.Cells(1,1).Value = "IP"
  wsResults.Cells(1,2).Value = "DNS"
  wsResults.Cells(1,3).Value = "QID"
  wsResults.Cells(1,4).Value = "Title"
  wsResults.Cells(1,5).Value = "Type"
  wsResults.Cells(1,6).Value = "Serverity"
  wsResults.Cells(1,7).Value = "Port"
  wsResults.Cells(1,8).Value = "Protocol"
  wsResults.Cells(1,9).Value = "CVSS Base"
  wsResults.Cells(1,10).Value = "CVSS Temporal"
  wsResults.Cells(1,11).Value = "Results"
  objWB.Sheets.Add(After=wsResults)
  wsSource = objWB.ActiveSheet
  wsSource.Name = "Source Scanners"
  wsSource.Cells(1,1).Value = "Scanner Appliance"
  wsSource.Cells(1,2).Value = "Scanner Version"
  wsSource.Cells(1,3).Value = "Vulnerability Signatures"
  wsSource.Cells(1,4).Value = "Source IP Addr"
  wsSource.Range("A1:D1").Font.Bold = True
  wsSource.Range("A1:D1").HorizontalAlignment = xlCenter
  wsSource.Columns("A:D").EntireColumn.AutoFit()
  objWB.Sheets.Add(After=wsSource)
  wsScope = objWB.ActiveSheet
  wsScope.Name = "IPScope"
  wsScope.Cells(1,1).Value = "IP Address block"
  wsScope.Range("A1:A1").Font.Bold = True
  wsScope.Range("A1:A1").HorizontalAlignment = xlCenter
  wsScope.Columns("A:A").EntireColumn.AutoFit()
  wsSummary.Select()
  objWB.SaveAs(strFileName)

  dictResults = {}
  dictSummary = {}
  dictParams = {}
  dictParams["scan_ref"] = strScanRef
  dictParams["action"] = "fetch"
  dictParams["output_format"] = "json_extended"

  strListScans = urlparse.urlencode(dictParams)
  strURL = strBaseURL + strAPIFunction + strListScans

  LogEntry ("Doing a get to URL: \n {}\n".format(strURL))
  try:
    WebRequest = requests.get(strURL, headers=dictHeader, auth=(strUserName, strPWD), stream=True)
    LogEntry ("get executed")
  except Exception as err:
    LogEntry ("Issue with API call. {}".format(err),True)

  if isinstance(WebRequest,requests.models.Response)==False:
    LogEntry ("response is unknown type",True)
  # end if
  LogEntry ("call resulted in status code {}".format(WebRequest.status_code))

  strErr = ""
  if WebRequest.status_code != 200:
    for strLine in WebRequest.iter_lines():
      if strLine:
        strLine = strLine.decode("ascii","ignore")
        strErr += strLine
    LogEntry ("HTTP Error {}\n{}".format(WebRequest.status_code,strErr))
  else:
    LogEntry ("Downloading full response line by line, and processing each line as I receive it")
    iLineNum = 1
    iResultsRow = 2
    for strLine in WebRequest.iter_lines():
      strLine = strLine.decode("ascii","ignore")
      if strErr != "":
        strErr += strLine + "\n"
      elif strLine[:5] == "<?xml":
        strErr += strLine + "\n"
      elif strLine :
        if strLine[0] == "[":
          strLine = strLine[1:]
        if strLine[-1] == "]":
          strLine = strLine[:-1]
        if strLine[-1] == ",":
          strLine = strLine[:-1]
        try:
          dictResponse = json.loads(strLine)
        except json.decoder.JSONDecodeError as err:
          LogEntry ("JSONDecodeError: {}\n{}".format(err,strLine),True)
        dictResults = {}

        if "launch_date" in dictResponse:
          print("\nAdding Summary.......")
          try:
            wsSummary.Cells(1,2).Value = dictResponse["launch_date"]
            wsSummary.Cells(2,2).Value = dictResponse["active_hosts"]
            wsSummary.Cells(3,2).Value = dictResponse["total_hosts"]
            wsSummary.Cells(4,2).Value = dictResponse["type"]
            wsSummary.Cells(5,2).Value = dictResponse["status"]
            wsSummary.Cells(6,2).Value = dictResponse["reference"]
            wsSummary.Cells(7,2).Value = dictResponse["duration"]
            wsSummary.Cells(8,2).Value = dictResponse["scan_title"]
            wsSummary.Cells(9,2).Value = dictResponse["asset_groups"]
            wsSummary.Cells(10,2).Value = dictResponse["option_profile"]
          except KeyError as e:
            LogEntry ("KeyError in worksheet summary: {}".format(e))
        if "ips" in dictResponse:
          strLineParts = dictResponse["ips"].split(",")
          iRowNum = 2
          print ("\nAdding IP Scope........................")
          for strElement in strLineParts:
            wsScope.Cells(iRowNum,1).Value = strElement
            print ("Added {} lines.................".format(iRowNum),end="\r")
            iRowNum += 1
        if "scanner_appliance" in dictResponse:
          strLineParts = dictResponse["scanner_appliance"].split("; ")
          iRowNum = 2
          print ("\nScanner Appliance.......................")
          for strElement in strLineParts:
            iLoc = strElement.find(" (")
            wsSource.Cells(iRowNum,1).Value = strElement[:iLoc]
            iRowNum += 1
        if "severity" in dictResponse:
          if int(dictResponse["severity"]) >= iMinSev:
            try:
              if dictResponse["severity"] in dictSummary:
                if dictResponse["title"] in dictSummary[dictResponse["severity"]]:
                  dictSummary[dictResponse["severity"]][dictResponse["title"]] += 1
                else:
                  dictSummary[dictResponse["severity"]][dictResponse["title"]] = 1
              else:
                dictSummary[dictResponse["severity"]] = {}
                dictSummary[dictResponse["severity"]][dictResponse["title"]] = 1

              wsResults.Cells(iResultsRow,1).Value = dictResponse["ip"]
              wsResults.Cells(iResultsRow,2).Value = dictResponse["dns"]
              wsResults.Cells(iResultsRow,3).Value = dictResponse["qid"]
              wsResults.Cells(iResultsRow,4).Value = dictResponse["title"]
              wsResults.Cells(iResultsRow,5).Value = dictResponse["type"]
              wsResults.Cells(iResultsRow,6).Value = dictResponse["severity"]
              wsResults.Cells(iResultsRow,7).Value = dictResponse["port"]
              wsResults.Cells(iResultsRow,8).Value = dictResponse["protocol"]
              wsResults.Cells(iResultsRow,9).Value = dictResponse["cvss_base"]
              wsResults.Cells(iResultsRow,10).Value = dictResponse["cvss_temporal"]
              wsResults.Cells(iResultsRow,11).Value = dictResponse["results"]
              iResultsRow += 1
            except KeyError as e:
              LogEntry ("KeyError in worksheet Results: {}".format(e))
        print ("Downloaded {} lines.................".format(iLineNum),end="\r")
        iLineNum += 1
        continue

        if "hosts_not_scanned_host_not_alive_ip" in dictResponse:
          dictResults = {}
          strLineParts = dictResponse["hosts_not_scanned_host_not_alive_ip"].split(",")
          print ("\nHost Not Scanned, not alive...")
          for strElement in strLineParts:
            lstTemp = ListIPs(strElement.strip())
            for strIPAddr in lstTemp:
              if strIPAddr != "Invalid":
                dictResults["Status"] = "No response"
                print ("Updating {}.........".format(strIPAddr),end="\r")
                # UpdateSummary(dictResults,strIPAddr,iScanID)
        if "hosts_not_scanned_excluded_host_ip" in dictResponse:
          print ("\nHost Not Scanned, Excluded...")
          dictResults = {}
          strLineParts = dictResponse["hosts_not_scanned_excluded_host_ip"].split(",")
          for strElement in strLineParts:
            lstTemp = ListIPs(strElement.strip())
            for strIPAddr in lstTemp:
              if strIPAddr != "Invalid":
                dictResults["Status"] = "Excluded from scanning"
                print ("Updating {}.........".format(strIPAddr),end="\r")
                # UpdateSummary(dictResults,strIPAddr,iScanID)
        if "host_not_scanned,_scan_canceled_by_user_ip_" in dictResponse:
          print ("\nHost Not Scanned, Cancelled...")
          dictResults = {}
          strLineParts = dictResponse["host_not_scanned,_scan_canceled_by_user_ip_"].split(",")
          for strElement in strLineParts:
            lstTemp = ListIPs(strElement.strip())
            for strIPAddr in lstTemp:
              if strIPAddr != "Invalid":
                dictResults["Status"] = "Job Cancelled, not scanned"
                print ("Updating {}.........".format(strIPAddr),end="\r")
                # UpdateSummary(dictResults,strIPAddr,iScanID)
        if "no_vulnerabilities_match_your_filters_for_these_hosts" in dictResponse:
          print ("\nno match to filter...")
          dictResults = {}
          strLineParts = dictResponse["no_vulnerabilities_match_your_filters_for_these_hosts"].split(",")
          for strElement in strLineParts:
            lstTemp = ListIPs(strElement.strip())
            for strIPAddr in lstTemp:
              if strIPAddr != "Invalid":
                dictResults["Status"] = "No match for filter"
                print ("Updating {}.........".format(strIPAddr),end="\r")
                # UpdateSummary(dictResults,strIPAddr,iScanID)
        if "target_distribution_across_scanner_appliances" in dictResponse:
          print ("\nscanner distribution...")
          dictResults = {}
          strLineParts = dictResponse["target_distribution_across_scanner_appliances"].split(",")
          for strElement in strLineParts:
            if " : " in strElement:
              strTemp = strElement.split(" : ")
              lstTemp = ListIPs(strTemp[1].strip())
              for strIPAddr in lstTemp:
                if strIPAddr != "Invalid":
                  dictResults["Scanner"] = strTemp[0].strip()
                  print ("Updating {}.........".format(strIPAddr),end="\r")
                  # UpdateSummary(dictResults,strIPAddr,iScanID)
            else:
              lstTemp = ListIPs(strElement.strip())
              for strIPAddr in lstTemp:
                if strIPAddr != "Invalid":
                  dictResults["Scanner"] = strTemp[0].strip()
                  print ("Updating {}.........".format(strIPAddr),end="\r")
                  # UpdateSummary(dictResults,strIPAddr,iScanID)
        print ("Downloaded {} lines.................".format(iLineNum),end="\r")
        iLineNum += 1
  if strErr != "":
    LogEntry("response was an XML error:\n{}".format(strErr))
  else:
    print()

  wsResults.ListObjects.Add(xlSrcRange, wsResults.Range(wsResults.Cells(1,1),wsResults.Cells(iResultsRow-1,11)),
    "",xlYes,"","TableStyleLight1").Name = wsResults.Name
  LogEntry("")
  wsResults.Columns("A:K").EntireColumn.AutoFit()
  wsSummary.Range("B1:B10").HorizontalAlignment = xlLeft
  wsSummary.Columns("A:B").EntireColumn.AutoFit()
  wsScope.Columns("A:A").EntireColumn.AutoFit()
  wsSummary.Range("B2:B3").NumberFormat = "#,##0"
  objWB.Save()
  UpdateAppliance()
  wsSummary.Cells(1,4).Value = "Result Summary"
  wsSummary.Cells(2,4).Value = "Priority"
  wsSummary.Cells(2,5).Value = "Title"
  wsSummary.Cells(2,6).Value = "Count"
  iSumRow = 3
  iTitleRow = 4
  for iPriority in dictSummary:
    wsSummary.Cells(iSumRow,4).Value = iPriority
    wsSummary.Cells(iSumRow,5).Value = "Summary "
    wsSummary.Cells(iSumRow,6).Value = len(dictSummary[iPriority])
    iSumRow += 1
    for strTitle in dictSummary[iPriority]:
      wsSummary.Cells(iTitleRow,4).Value = iPriority
      wsSummary.Cells(iTitleRow,5).Value = strTitle
      wsSummary.Cells(iTitleRow,6).Value = dictSummary[iPriority][strTitle]
      iTitleRow += 1
  wsSummary.Columns("A:F").EntireColumn.HorizontalAlignment = xlLeft
  wsSummary.Range("D1:F1").Merge()
  wsSummary.Range("D1:F1").HorizontalAlignment = xlCenter
  wsSummary.Range("D1:F1").Font.Bold = True
  wsSummary.Range("D1:F1").Font.Size = 14
  wsSummary.Range("D2:F2").Font.Bold = True
  wsSummary.Range("D2:F2").HorizontalAlignment = xlCenter
  wsSummary.Columns("A:F").EntireColumn.AutoFit()
  objWB.Save()
  app.Visible = True
  LogEntry ("Done with scan job, downloaded {} lines".format(iLineNum-1))
  objWB.Close()
  wsSummary = None
  wsScope = None
  wsResults = None
  wsSource = None
  objWB = None
  app = None


print ("This is a Qualys Scan Report generator. This is running under Python Version {}".format(strVersion))
print ("Running from: {}".format(strRealPath))
now = time.asctime()
print ("The time now is {}".format(now))
print ("Logs saved to {}".format(strLogFile))
objLogOut = open(strLogFile,"w",1)

processConf()

if strSaveLoc == "":
  LogEntry ("No save location, exiting",True)

if not os.path.isdir(strSaveLoc):
  print ("{} doesn't exists, creating it".format(strSaveLoc))
  os.makedirs(strSaveLoc)

sa = sys.argv
lsa = len(sys.argv)
if lsa > 1:
  strSearchCrit = sa[1]
else:
  if strSearchCrit == "":
    print ("Project keyword was not provided and is required to continue. "
      " Project keyword can be partial but unique string.\n REQ1234 and 1234 are both acceptable.")
    strSearchCrit = input("Please provide project keyword: ")

print ("calculating stuff ...")

iSecInDays = 86400
iSecDays = iSecInDays * iNumDays

timeNow = time.localtime(time.time())
iGMT_offset = timeNow.tm_gmtoff

timeLastNightLocal = time.strftime("%Y-%m-%d",time.localtime(time.time()-iSecDays)) + " " + strTimeLastNight
timeLastNightGMT = time.localtime(time.mktime(time.strptime(timeLastNightLocal,"%Y-%m-%d %H:%M"))-iGMT_offset)
strQualysTime = time.strftime("%Y-%m-%dT%H:%M:%SZ",timeLastNightGMT)
strLastNight = time.strftime("%m/%d/%Y %H:%M %Z",time.localtime(time.mktime(time.strptime(timeLastNightLocal,"%Y-%m-%d %H:%M"))))
dictParams = {}
lstScanRefs = []
dictScanRefs = {}
iSelNum = 0

strAPIFunction = "api/2.0/fo/scan/?"
dictParams.clear()
dictParams["action"] = "list"
dictParams["state"] = "Finished"
if strFilterUser != "":
  dictParams["user_login"] = strFilterUser
dictParams["launched_after_datetime"] = strQualysTime
strListScans = urlparse.urlencode(dictParams)

strURL = strBaseURL + strAPIFunction + strListScans
print ("Fetching a list of scans since {}".format(strLastNight))
APIResponse = MakeAPICall(strURL,dictHeader,strUserName,strPWD,"Get")
if isinstance(APIResponse,str):
  print(APIResponse)
if isinstance(APIResponse,dict):
  if "SCAN_LIST" in APIResponse["SCAN_LIST_OUTPUT"]["RESPONSE"]:
    print ("Here are the scans since {}".format(strLastNight))
    if isinstance(APIResponse["SCAN_LIST_OUTPUT"]["RESPONSE"]["SCAN_LIST"]["SCAN"],list):
      print ("There were {} scans during that that timeframe.".format(len(APIResponse["SCAN_LIST_OUTPUT"]["RESPONSE"]["SCAN_LIST"]["SCAN"])))
      print ("Title Refernce User Launch Date")
      bFoundRef = False
      for scan in APIResponse["SCAN_LIST_OUTPUT"]["RESPONSE"]["SCAN_LIST"]["SCAN"]:
        if strSearchCrit.lower() in scan["TITLE"].lower():
          iSelNum += 1
          bFoundRef = True
          print ("{}: {} {} {} {}".format(iSelNum, scan["TITLE"],scan["REF"],scan["USER_LOGIN"], QD2Human(scan["LAUNCH_DATETIME"])))
          lstScanRefs.append(scan["REF"])
          dictScanRefs[scan["REF"]] = scan["TITLE"]
      if not bFoundRef:
        print ("And none of them matched the criteria")
    else:
      print ("There was only a single scan completed.")
      print ("Title Refernce User Launch Date")
      scan = APIResponse["SCAN_LIST_OUTPUT"]["RESPONSE"]["SCAN_LIST"]["SCAN"]
      if strSearchCrit.lower() in scan["TITLE"].lower():
        print ("{}: {} {} {} {}".format(iSelNum, scan["TITLE"],scan["REF"],scan["USER_LOGIN"], QD2Human(scan["LAUNCH_DATETIME"])))
        lstScanRefs.append(scan["REF"])
        dictScanRefs[scan["REF"]] = scan["TITLE"]
      else:
        print ("and it did not match the search criteria")
  else:
    print ("There are no scans since {}".format(strLastNight))

if len(lstScanRefs) == 1:
  strScanRef = lstScanRefs[0]
  strScanTitle = dictScanRefs[strScanRef]
  print ("Fetching scan result for {} {}".format(strScanRef, strScanTitle))
  FetchScanResults(strScanRef,strScanTitle)
if len(lstScanRefs) > 1:
  strInput = getInput("Please select which scan job to use: ")
  if isInt(strInput):
    iSelection = int(strInput)
    if iSelection <= len(lstScanRefs):
      strScanRef = lstScanRefs[iSelection - 1]
      strScanTitle = dictScanRefs[strScanRef]
      print ("Fetching scan result for {} {}".format(strScanRef,strScanTitle))
      FetchScanResults(strScanRef,strScanTitle)
    else:
      print ("Selection {} is out of bounds. ".format(iSelection))
  else:
    print ("{} is invalid input".format(strInput))

try:
  app = win32.gencache.EnsureDispatch('Outlook.Application')
except:
  LogEntry ("unable to get a hook into Outlook",True)

strTemp = "\n<table>\n<tr><th>Priority</th><th>Title</th><th>Count</th></tr>\n"
objMail = app.CreateItem(olMailItem)
objMail.Attachments.Add(strFileName)
objMail.To = strEmailTo
objMail.Subject = strEmailSubject
for iPriority in dictSummary:
  strTemp += "<tr><td align=center>{}</td><td>Summary</td><td align=center>{}</td></tr>\n".format(iPriority,len(dictSummary[iPriority]))
  for strTitle in dictSummary[iPriority]:
    strTemp += "<tr><td align=center>{}</td><td>{}</td><td align=center>{}</td></tr>\n".format(iPriority,strTitle,dictSummary[iPriority][strTitle])
strTemp += "</table>\n"
strTemp += objMail.HTMLBody
objMail.HTMLBody = strEmailIntro + strTemp
objMail.Display()
objMail.Save()
objMail = None
app = None
print ("Mission completed!")