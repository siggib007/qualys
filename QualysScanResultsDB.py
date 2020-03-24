'''
Script to pull all scan result data from Qualys
Version 2.2
Author Siggi Bjarnason Copyright 2018
Website http://www.ipcalc.us/ and http://www.icecomputing.com

Following packages need to be installed as administrator
pip install requests
pip install xmltodict
pip install pymysql
pip install pyodbc
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
# End imports

iTimeOut = 120
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

print ("This is a script to gather all scan results from Qualys via API. This is running under Python Version {}".format(strVersion))
print ("Running from: {}".format(strRealPath))
now = time.asctime()
print ("The time now is {}".format(now))
print ("Logs saved to {}".format(strLogFile))
objLogOut = open(strLogFile,"w",1)

dboErr = None
dbo = None
strDBType = "undef"
iEntryID = 0
strDBUser = ""
strDBPWD = ""
strdbNow = time.strftime("%Y-%m-%d %H:%M:%S")

def SendNotification (strMsg):
  dictNotify = {}
  dictNotify["token"] = strNotifyToken
  dictNotify["channel"] = strNotifyChannel
  dictNotify["text"]=strMsg[:199]
  strNotifyParams = urlparse.urlencode(dictNotify)
  strURL = strNotifyURL + "?" + strNotifyParams
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
  if dbConn !="":
    strdbNow = time.strftime("%Y-%m-%d %H:%M:%S")
    strSQL = ("update tblScriptExecuteList set dtStopTime='{}', bComplete=0, "
        " iRowsUpdated={} where iExecuteID = {} ;".format(strdbNow, iIPCount,iEntryID))
    lstReturn = SQLQuery (strSQL,dbConn)
    dbConn.close()

  objLogOut.close()
  sys.exit(9)

def LogEntry(strMsg,bAbort=False):
  strTemp = ""
  strDBMsg = DBClean(strMsg[:9990])
  if dbConn !="":
    strSQL = "INSERT INTO tblLogs (vcScriptName, vcLogEntry) VALUES ('{}','{}');".format(strScriptName,strDBMsg)
    lstReturn = SQLQuery (strSQL,dbConn)
    if not ValidReturn(lstReturn):
      strTemp = ("   Unexpected issue inserting log entry to the database: {}\n{}".format(lstReturn,strSQL))
    elif lstReturn[0] != 1:
      strTemp = ("   Records affected {}, expected 1 record affected when inserting log entry to the database".format(lstReturn[0]))
  else:
    strTemp = ". Database connection not established yet"

  strMsg += strTemp
  strTimeStamp = time.strftime("%m-%d-%Y %H:%M:%S")
  objLogOut.write("{0} : {1}\n".format(strTimeStamp,strMsg))
  print (strMsg)
  if bAbort:
    SendNotification("{} on {}: {}".format (strScriptName,strScriptHost,strMsg[:99]))
    CleanExit("")

def processConf():
  global strBaseURL
  global dictHeader
  global strUserName
  global strPWD
  global strServer
  global strDBUser
  global strDBPWD
  global strInitialDB
  global iMinQuietTime
  global strLoadType
  global dtFullLoad
  global iTestRef
  global strNotifyURL
  global strNotifyToken
  global strNotifyChannel
  global strDBType

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
        dictHeader={'X-Requested-With': strValue}
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
      if strVarName == "TestRef":
        iTestRef = strValue
      if strVarName == "NotificationURL":
        strNotifyURL = strValue
      if strVarName == "NotifyChannel":
        strNotifyChannel = strValue
      if strVarName == "NotifyToken":
        strNotifyToken = strValue
      if strVarName == "DBType":
        strDBType  = strValue

  if strBaseURL[-1:] != "/":
    strBaseURL += "/"

  LogEntry ("Done processing configuration, moving on")

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

def SQLConn (strServer,strDBUser,strDBPWD,strInitialDB):
  global dboErr
  global dbo
  strError = ""

  try:
    # Open database connection
    if strDBType == "mssql":
      import pyodbc as dbo
      import pyodbc as dboErr
      if strDBUser == "":
        strConnect = (" DRIVER={{ODBC Driver 17 for SQL Server}};"
                      " SERVER={};"
                      " DATABASE={};"
                      " Trusted_Connection=yes;".format(strServer,strInitialDB))
        LogEntry ("Connecting to MSSQL server {} via trusted connection".format(strServer))
      else:
        strConnect = (" DRIVER={{ODBC Driver 17 for SQL Server}};"
                      " SERVER={};"
                      " DATABASE={};"
                      " UID={};"
                      " PWD={};".format(strServer,strInitialDB,strDBUser,strDBPWD))
        LogEntry ("Connecting to MSSQL server {} via username/password".format(strServer))
      return dbo.connect(strConnect)
    elif strDBType == "mysql":
      import pymysql as dbo
      from pymysql import err as dboErr
      LogEntry ("Connecting to MySQL server {}".format(strServer))
      return dbo.connect(strServer,strDBUser,strDBPWD,strInitialDB)
    else:
      strError = ("Unknown database type: {}".format(strDBType))
  except dboErr.InternalError as err:
    LogEntry ("Error: unable to connect: {}".format(err),True)
  except dboErr.OperationalError as err:
    LogEntry ("Operational Error: unable to connect: {}".format(err),True)
  except dboErr.ProgrammingError as err:
    LogEntry ("Programing Error: unable to connect: {}".format(err),True)
  if strError != "":
    LogEntry (strError,True)

def SQLQuery (strSQL,db):
  try:
    # prepare a cursor object using cursor() method
    dbCursor = db.cursor()
    # Execute the SQL command
    dbCursor.execute(strSQL)
    # Count rows
    iRowCount = dbCursor.rowcount
    if strSQL[:6].lower() == "select" or strSQL[:4].lower() == "call":
      dbResults = dbCursor.fetchall()
    else:
      db.commit()
      dbResults = ()
    return [iRowCount,dbResults]
  except dboErr.InternalError as err:
    return "Internal Error: unable to execute: {}\n{}\nLength of SQL statement {}\n".format(err,strSQL[:255],len(strSQL))
  except dboErr.ProgrammingError as err:
    return "Programing Error: unable to execute: {}\n{}\nLength of SQL statement {}\n".format(err,strSQL[:255],len(strSQL))
  except dboErr.OperationalError as err:
    return "Programing Error: unable to execute: {}\n{}\nLength of SQL statement {}\n".format(err,strSQL[:255],len(strSQL))
  except dboErr.IntegrityError as err:
    return "Integrity Error: unable to execute: {}\n{}\nLength of SQL statement {}\n".format(err,strSQL[:255],len(strSQL))
  except dboErr.DataError as err:
    return "Data Error: unable to execute: {}\n{}\nLength of SQL statement {}\n".format(err,strSQL[:255],len(strSQL))
  except dboErr.InterfaceError as err:
    return "Interface Error: unable to execute: {}\n{}\nLength of SQL statement {}\n".format(err,strSQL[:255],len(strSQL))


def ValidReturn(lsttest):
  if isinstance(lsttest,list):
    if len(lsttest) == 2:
      if isinstance(lsttest[0],int) and (isinstance(lsttest[1],tuple) or isinstance(lsttest[1],list)):
        return True
      else:
        return False
    else:
      return False
  else:
    return False

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

def ConvertFloat (fValue):
  if isinstance(fValue,(float,int,str)):
    try:
      fTemp = float(fValue)
    except ValueError:
      fTemp = "NULL"
  else:
    fTemp = "NULL"
  return fTemp

def QDate2DB(strDate):
  strTemp = strDate.replace("T"," ")
  return strTemp.replace("Z","")

def DBClean(strText):
  if strText is None:
    return ""
  strTemp = strText.encode("ascii","ignore")
  strTemp = strTemp.decode("ascii","ignore")
  strTemp = strTemp.replace("\\","\\\\")
  strTemp = strTemp.replace("'","\"")
  return strTemp

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

def FetchScanResults (strScanRef):
  global iScanCount

  strIPTemp = ""
  iScanSumID = -23
  bFoundIPs = False

  LogEntry ("Fetching ScanID for ScanRef {}".format(strScanRef))
  strSQL = "select iScanID from tblScanList where vcScanRef = '{}';".format(strScanRef)
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    CleanExit("due to unexpected SQL return, please check the logs")
  elif len(lstReturn[1]) != 1:
    LogEntry ("Received {} ScanID's for Scan Reference {} when I should have received 1. "
      " Something is horrible wrong so I'm bailing".format(len(lstReturn[1]),strScanRef),True)
    iScanID = -10
  else:
    iScanID = lstReturn[1][0][0]
  LogEntry ("ScanRef {} has scanID of {}".format(strScanRef,iScanID))

  strSQL = "delete from tblScanSummary where iScanID = {};".format(iScanID)
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    CleanExit("due to unexpected SQL return, please check the logs")
  else:
    LogEntry ("Deleted {} scan summaries".format(lstReturn[0]))

  dictResults = {}
  dictParams["scan_ref"] = strScanRef

  strListScans = urlparse.urlencode(dictParams)
  strURL = strBaseURL + strAPIFunction +"?" + strListScans

  LogEntry ("Doing a get to URL: \n {}\n".format(strURL))
  try:
    WebRequest = requests.get(strURL,timeout=iTimeOut, headers=dictHeader, auth=(strUserName, strPWD), stream=True)
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
    for strLine in WebRequest.iter_lines():
      # print ("\nnext line")
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
          if isInt(dictResponse["total_hosts"]):
            iTotalHosts = dictResponse["total_hosts"]
          else:
            iTotalHosts = 0
          if isInt(dictResponse["active_hosts"]):
            iActiveHosts = dictResponse["active_hosts"]
          else:
            iActiveHosts = 0
          strSQL = "update tblScanList set iHostCount = {}, iLiveHosts = {} where vcScanRef = '{}';".format(
            iTotalHosts,iActiveHosts,dictResponse["reference"])
          lstReturn = SQLQuery (strSQL,dbConn)
          if not ValidReturn(lstReturn):
            LogEntry ("Unexpected: {}".format(lstReturn))
            CleanExit("due to unexpected SQL return, please check the logs")
          else:
            LogEntry ("Updated scan {}, affected {} records".format(dictResponse["reference"],lstReturn[0]))
        if "ip" in dictResponse:
          bFoundIPs = True
          dictTemp = {}
          dictTemp["QID"] = dictResponse["qid"]
          dictTemp["Title"] = dictResponse["title"]
          dictTemp["Severity"] = dictResponse["severity"]
          dictTemp["ProtPort"] = dictResponse["port"]
          dictTemp["Protocol"] = dictResponse["protocol"]
          dictTemp["FQDN"] = dictResponse["fqdn"]
          dictTemp["SSL"] = dictResponse["ssl"]

          dictResults["DNSName"] = dictResponse["dns"]
          dictResults["NBName"] = dictResponse["netbios"]
          dictResults["OS"] = dictResponse["os"]
          if dictResponse["ip_status"] != "host scanned, found vuln":
            dictResults["Status"] = dictResponse["ip_status"]
          if dictResponse["ip"] != strIPTemp:
            strIPTemp = dictResponse["ip"]
            UpdateSummary(dictResults,dictResponse["ip"],iScanID)

            strSQL = "select iScanSumID from tblScanSummary where iScanID = {} and vcIPAddr = '{}' ;".format(iScanID,strIPTemp)
            lstReturn = SQLQuery (strSQL,dbConn)
            if not ValidReturn(lstReturn):
              LogEntry ("Unexpected: {}".format(lstReturn))
              CleanExit("due to unexpected SQL return, please check the logs")
            elif len(lstReturn[1]) != 1:
              LogEntry ("Received {} Scan Summary ID's for Scan ID {} and IP address{}, should only be one. "
                " Bailing because I don't know which to pick".format(len(lstReturn[1]),iScanID,strIPTemp),True)
            else:
              iScanSumID = lstReturn[1][0][0]
          UpdateScanDetails(iScanSumID,dictTemp)

        if "hosts_not_scanned_host_not_alive_ip" in dictResponse:
          dictResults = {}
          strLineParts = dictResponse["hosts_not_scanned_host_not_alive_ip"].split(",")
          print ("\nHost Not Scanned, not alive...")
          for strElement in strLineParts:
            lstTemp = ListIPs(strElement.strip())
            for strIPAddr in lstTemp:
              if strIPAddr != "Invalid":
                bFoundIPs = True
                dictResults["Status"] = "No response"
                print ("Updating {}.........".format(strIPAddr),end="\r")
                UpdateSummary(dictResults,strIPAddr,iScanID)
        if "hosts_not_scanned_excluded_host_ip" in dictResponse:
          print ("\nHost Not Scanned, Excluded...")
          dictResults = {}
          strLineParts = dictResponse["hosts_not_scanned_excluded_host_ip"].split(",")
          for strElement in strLineParts:
            lstTemp = ListIPs(strElement.strip())
            for strIPAddr in lstTemp:
              if strIPAddr != "Invalid":
                bFoundIPs = True
                dictResults["Status"] = "Excluded from scanning"
                print ("Updating {}.........".format(strIPAddr),end="\r")
                UpdateSummary(dictResults,strIPAddr,iScanID)
        if "host_not_scanned,_scan_canceled_by_user_ip_" in dictResponse:
          print ("\nHost Not Scanned, Cancelled...")
          dictResults = {}
          strLineParts = dictResponse["host_not_scanned,_scan_canceled_by_user_ip_"].split(",")
          for strElement in strLineParts:
            lstTemp = ListIPs(strElement.strip())
            for strIPAddr in lstTemp:
              if strIPAddr != "Invalid":
                bFoundIPs = True
                dictResults["Status"] = "Job Cancelled, not scanned"
                print ("Updating {}.........".format(strIPAddr),end="\r")
                UpdateSummary(dictResults,strIPAddr,iScanID)
        if "no_vulnerabilities_match_your_filters_for_these_hosts" in dictResponse:
          print ("\nno match to filter...")
          dictResults = {}
          strLineParts = dictResponse["no_vulnerabilities_match_your_filters_for_these_hosts"].split(",")
          for strElement in strLineParts:
            lstTemp = ListIPs(strElement.strip())
            for strIPAddr in lstTemp:
              if strIPAddr != "Invalid":
                bFoundIPs = True
                dictResults["Status"] = "No match for filter"
                print ("Updating {}.........".format(strIPAddr),end="\r")
                UpdateSummary(dictResults,strIPAddr,iScanID)
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
                  bFoundIPs = True
                  dictResults["Scanner"] = strTemp[0].strip()
                  print ("Updating {}.........".format(strIPAddr),end="\r")
                  UpdateSummary(dictResults,strIPAddr,iScanID)
            else:
              lstTemp = ListIPs(strElement.strip())
              for strIPAddr in lstTemp:
                if strIPAddr != "Invalid":
                  bFoundIPs = True
                  dictResults["Scanner"] = strTemp[0].strip()
                  print ("Updating {}.........".format(strIPAddr),end="\r")
                  UpdateSummary(dictResults,strIPAddr,iScanID)
        print ("Downloaded {} lines.................".format(iLineNum),end="\r")
        iLineNum += 1
  if strErr != "":
    LogEntry("response was an XML error:\n{}".format(strErr))
    strSQL = ("INSERT INTO tblScanSummary (iScanID,iHostID,vcDNSName) "
          " VALUES ({iScanID},-25,'Error with Scan Job');".format(iScanID=iScanID))
    lstReturn = SQLQuery (strSQL,dbConn)
    if not ValidReturn(lstReturn):
      LogEntry ("Unexpected: {}".format(lstReturn))
      CleanExit("due to unexpected SQL return, please check the logs")
    elif lstReturn[0] != 1:
      LogEntry ("While updating a Scan Summary entry for problematic scan job, Records affected {}, "
        " expected 1 record affected".format(lstReturn[0]))
  elif not bFoundIPs:
    LogEntry("\nNo IP's processed in this Scan Job")
    strSQL = ("INSERT INTO tblScanSummary (iScanID,iHostID,vcDNSName) "
          " VALUES ({iScanID},-35,'No IPs in Scan Job');".format(iScanID=iScanID))
    lstReturn = SQLQuery (strSQL,dbConn)
    if not ValidReturn(lstReturn):
      LogEntry ("Unexpected: {}".format(lstReturn))
      CleanExit("due to unexpected SQL return, please check the logs")
    elif lstReturn[0] != 1:
      LogEntry ("While updating a Scan Summary entry for no IP scan job, Records affected {}, "
        " expected 1 record affected".format(lstReturn[0]))
  else:
    iScanCount += 1
    print()

  LogEntry ("Done with that scan job, downloaded {} lines and processed {} IP's so far. "
    "On to next job ...".format(iLineNum-1,iIPCount))

def UpdateSummary(dictSummary,strIPAddr,iScanID):
  global iIPCount

  # print ("\n   Updating IP {}, dictSummary length is {}: {}".format(strIPAddr,len(dictSummary),dictSummary))
  if "DNSName" in dictSummary:
    strDNSName = "'{}'".format(DBClean(dictSummary["DNSName"]))
  else:
    strDNSName = "NULL"
  if "NBName" in dictSummary:
    strNBName = "'{}'".format(DBClean(dictSummary["NBName"]))
  else:
    strNBName = "NULL"
  if "OS" in dictSummary:
    strOS = "'{}'".format( DBClean(dictSummary["OS"]))
  else:
    strOS = "NULL"
  if "Scanner" in dictSummary:
    strScanner = "'{}'".format(DBClean(dictSummary["Scanner"]))
  else:
    strScanner = "NULL"
  if "Status" in dictSummary:
    strStatus = "'{}'".format( DBClean(dictSummary["Status"]))
  else:
    strStatus = "NULL"
  strSQL = "select iHostID from tblhostlist where vcIPAddr = '{}' and vcTrackingMethod = 'IP';".format(strIPAddr)
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    CleanExit("due to unexpected SQL return, please check the logs")
  elif len(lstReturn[1]) > 1:
    LogEntry ("Received {} HostID's for IP address {} when I should have received 1. "
      " No idea which hostID to use so I have to bail".format(len(lstReturn[1]),strIPAddr),True)
  elif len(lstReturn[1]) == 0:
    iHostID = -13
  else:
    iHostID = lstReturn[1][0][0]

  strSQL = "select iScanSumID from tblScanSummary where iScanID = {} and vcIPAddr = '{}' ;".format(iScanID,strIPAddr)
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    CleanExit("due to unexpected SQL return, please check the logs")
  elif len(lstReturn[1]) == 0:
    if len(dictSummary) == 0:
      strSQL = ("INSERT INTO tblScanSummary (iScanID,vcIPAddr,iHostID) "
       " VALUES ({iScanID},'{vcIPAddr}',{iHostID});".format(
        iScanID=iScanID,vcIPAddr=strIPAddr,iHostID=iHostID,))
    elif len(dictSummary) == 1:
      if "Scanner" in dictSummary:
        strSQL = ("INSERT INTO tblScanSummary (iScanID,vcIPAddr,iHostID,vcScanner) "
          " VALUES ({iScanID},'{vcIPAddr}',{iHostID},{vcScanner});".format(
          iScanID=iScanID,vcIPAddr=strIPAddr,iHostID=iHostID,vcScanner=strScanner))
      elif "Status" in dictSummary:
        strSQL = ("INSERT INTO tblScanSummary (iScanID,vcIPAddr,iHostID,vcStatus) "
          " VALUES ({iScanID},'{vcIPAddr}',{iHostID},{vcStatus});".format(
          iScanID=iScanID,vcIPAddr=strIPAddr,iHostID=iHostID,vcStatus=strStatus))
      else:
        LogEntry("DictSummary is one element but it is neither Status nor Scanner, WTF???",True)
    else:
      strSQL = ("INSERT INTO tblScanSummary (iScanID,vcIPAddr,iHostID,vcDNSName,vcNBName,vcOS,vcStatus,vcScanner) "
       " VALUES ({iScanID},'{vcIPAddr}',{iHostID},{vcDNSName},{vcNBName},{vcOS},{vcStatus},{vcScanner});".format(
        iScanID=iScanID,vcIPAddr=strIPAddr,iHostID=iHostID,vcDNSName=strDNSName,
        vcNBName=strNBName,vcOS=strOS,vcStatus=strStatus,vcScanner=strScanner))
    iIPCount += 1
  elif len(lstReturn[1]) == 1:
    if len(dictSummary) == 1:
      if "Scanner" in dictSummary:
        strSQL = ("UPDATE tblScanSummary SET iHostID = {iHostID}, vcScanner = {vcScanner} WHERE iScanID = {iScanID} "
          " and vcIPAddr = '{vcIPAddr}';".format(iScanID=iScanID,vcIPAddr=strIPAddr,iHostID=iHostID,vcScanner=strScanner))
      elif "Status" in dictSummary:
        strSQL = ("UPDATE tblScanSummary SET iHostID = {iHostID}, vcStatus = {vcStatus} WHERE iScanID = {iScanID} "
                " and vcIPAddr = '{vcIPAddr}';".format(iScanID=iScanID,vcIPAddr=strIPAddr,iHostID=iHostID,
                  vcStatus=strStatus))
      else:
        LogEntry("DictSummary is one element but it is neither Status nor Scanner, WTF???",True)
    else:
      strSQL = ("UPDATE tblScanSummary SET iHostID = {iHostID}, vcDNSName = {vcDNSName}, vcNBName = {vcNBName}, "
                " vcOS = {vcOS}, vcStatus = {vcStatus}, vcScanner = {vcScanner} WHERE iScanID = {iScanID} "
                " and vcIPAddr = '{vcIPAddr}';".format(iScanID=iScanID,vcIPAddr=strIPAddr,iHostID=iHostID,
                  vcDNSName=strDNSName,vcNBName=strNBName,vcOS=strOS,vcStatus=strStatus,vcScanner=strScanner))
  else:
    LogEntry ("Received {} Scan Summary ID's for Scan ID {} and IP address {}, should only be one. "
      " Bailing because that aint right".format(len(lstReturn[1]),iScanID,strIPAddr),True)

  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    CleanExit("due to unexpected SQL return, please check the logs")
  elif lstReturn[0] != 1:
    LogEntry ("While updating a Scan Summary entry, Records affected {}, expected 1 record affected".format(lstReturn[0]))


def UpdateScanDetails(iScanSumID,dictQID):
  global iQIDCount

  iQIDCount += 1
  if "QID" in dictQID:
    iQID = dictQID["QID"]
  else:
    iQID = -15
  if "Title" in dictQID:
    strTitle = DBClean (dictQID["Title"])
  else:
    strTitle = ""
  if "Severity" in dictQID:
    iSeverity = DBClean (dictQID["Severity"])
  else:
    iSeverity = -15
  if "ProtPort" in dictQID:
    strPortProt = DBClean (dictQID["ProtPort"])
  else:
    strPortProt = ""
  if "Protocol" in dictQID:
    strProtocol = DBClean (dictQID["Protocol"])
  else:
    strProtocol = ""
  if "FQDN" in dictQID:
    strFQDN = DBClean (dictQID["FQDN"])
  else:
    strFQDN = ""
  if "SSL" in dictQID:
    strSSL = DBClean (dictQID["SSL"])
  else:
    strSSL = ""
  strSQL = ("INSERT INTO tblScanDetails (iScanSumID,iQID,vcTitle,iSeverity,vcPortProt,vcProtocol,vcFQDN,vcSSL) "
    " VALUES ({iScanSumID},{iQID},'{vcTitle}',{iSeverity},'{vcPortProt}','{vcProtocol}','{vcFQDN}','{vcSSL}');".format(
      iScanSumID=iScanSumID,iQID=iQID,vcTitle=strTitle,iSeverity=iSeverity,vcPortProt=strPortProt,
      vcProtocol=strProtocol,vcFQDN=strFQDN,vcSSL=strSSL))
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    CleanExit("due to unexpected SQL return, please check the logs")
  elif lstReturn[0] != 1:
    LogEntry ("While inserting a Scan detail entry, Records affected {}, expected 1 record affected".format(lstReturn[0]))



iRowNum = 1
iScanCount = 0
iIPCount = 0
iQIDCount = 0
iEntryID = 0
dtStartTime = ""
dbConn = ""
processConf()
dbConn = SQLConn (strServer,strDBUser,strDBPWD,strInitialDB)
strSQL = ("select dtStartTime from tblScriptExecuteList where iExecuteID = "
    " (select max(iExecuteID) from tblScriptExecuteList where vcScriptName = '{}')").format(strScriptName)
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
  CleanExit("due to unexpected SQL return, please check the logs")
elif len(lstReturn[1]) != 1:
  LogEntry ("Looking for last execution date, fetched {} rows, expected 1 record affected".format(len(lstReturn[1])))
  dtLastExecute = -10
else:
  dtLastExecute = lstReturn[1][0][0]

if strDBType == "mysql":
  strSQL = ("select TIMESTAMPDIFF(MINUTE,max(dtTimestamp),now()) as timediff "
              " from tblLogs where vcLogEntry not like '%last execution date%' and vcScriptName = '{}';".format(strScriptName))
elif strDBType == "mssql":
  strSQL = ("select datediff(MINUTE,max(dtTimestamp),GETDATE()) as timediff "
              " from tblLogs where vcLogEntry not like '%last execution date%' and vcScriptName = '{}';".format(strScriptName))
else:
  LogEntry ("Unknown database type {}".format(strDBType),True)
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
  CleanExit("due to unexpected SQL return, please check the logs")
elif len(lstReturn[1]) != 1:
  LogEntry ("While looking for quiet time fetched {}, rows expected 1 record affected".format(len(lstReturn[1])))
  iQuietMin = iMinQuietTime
else:
  if isInt(lstReturn[1][0][0]):
    iQuietMin = int(lstReturn[1][0][0])
  else:
    LogEntry ("This is the first time this script is run in this environment, "
      "setting last scan time to {} minutes to work around quiet time logic".format(iMinQuietTime))
    iQuietMin = iMinQuietTime

if iQuietMin < iMinQuietTime :
  dbConn = ""
  LogEntry ("Either the script is already running or it's been less that {0} min since it last run, "
              "please wait until after {0} since last run. "
              " It's been {1} minutes since last log entry. Exiting".format(iMinQuietTime,iQuietMin))
  objLogOut.close()
  sys.exit()
else:
  LogEntry("{} Database connection established. It's been {} minutes since last log entry.".format(strDBType.upper(), iQuietMin))

LogEntry("Starting Processing. Script {} running under Python version {}".format(strRealPath,strVersion))

strdbNow = time.strftime("%Y-%m-%d %H:%M:%S")
strSQL = ("INSERT INTO tblScriptExecuteList (vcScriptName,dtStartTime,iGMTOffset) "
          " VALUES('{}','{}',{});".format(strScriptName,strdbNow,iGMTOffset))
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
  CleanExit("due to unexpected SQL return, please check the logs")
elif lstReturn[0] != 1:
  LogEntry ("Inserting tblScriptExecuteList Records affected {}, expected 1 record affected".format(lstReturn[0]))

strSQL = ("select iExecuteID,dtStartTime from tblScriptExecuteList where iExecuteID in "
  " (select max(iExecuteID) from tblScriptExecuteList where vcScriptName = '{}');".format(strScriptName))
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
  CleanExit("due to unexpected SQL return, please check the logs")
elif len(lstReturn[1]) != 1:
  LogEntry ("Received {} records when retrieving entry ID, should only be one. "
    "Since I can't figure out entry ID I'm bailing".format(len(lstReturn[1])),True)
  iEntryID = -10
else:
  iEntryID = lstReturn[1][0][0]
  dtStartTime = lstReturn[1][0][1]

LogEntry("Recorded start entry, ID {}".format(iEntryID))

if strLoadType.lower() == "test" :
  LogEntry("Per configuration file doing a test load focusing on Scan Reference {}".format(iTestRef))
  strSQL = "select distinct vcScanRef from tblScanList where vcScanRef = '{}';".format(iTestRef)
else:
  LogEntry("Configured load type is not test, which means incremental load")
  strSQL = "select vcScanRef from tblScanList where iScanID not in (select distinct iScanID from tblScanSummary);"

LogEntry ("Fetching list of Scan references from the database")
lstScanRef = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstScanRef):
  LogEntry ("Unexpected: {}".format(lstScanRef))
  CleanExit("due to unexpected SQL return, please check the logs")
else:
  LogEntry ("Fetched {} rows".format(len(lstScanRef[1])))

iTotalRows = len(lstScanRef[1])

strAPIFunction = "/api/2.0/fo/scan"

if strAPIFunction[0] == "/":
  strAPIFunction = strAPIFunction[1:]

if strAPIFunction[-1:] != "/":
  strAPIFunction += "/"

strMethod = "get"
dictParams = {}
dictParams["action"] = "fetch"
dictParams["output_format"] = "json_extended"

for dbRow in lstScanRef[1]:
  LogEntry("\n--------------\nWorking on Scan reference: {} record {} out of {}. "
    " {:.1%} complete".format(dbRow[0],iRowNum,iTotalRows,(iRowNum-1)/iTotalRows))
  FetchScanResults (dbRow[0])
  LogEntry("Updating tblScriptExecuteList")
  strdbNow = time.strftime("%Y-%m-%d %H:%M:%S")
  strSQL = ("update tblScriptExecuteList set dtStopTime='{}', bComplete=0, iRowsUpdated={} "
              " where iExecuteID = {} ;".format(strdbNow,iIPCount,iEntryID))
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
  elif lstReturn[0] != 1:
    LogEntry ("Updating tblScriptExecuteList: Records affected {}, expected 1 record affected".format(lstReturn[0]))
  iRowNum += 1

LogEntry("Updating completion entry")
strdbNow = time.strftime("%Y-%m-%d %H:%M:%S")
strSQL = ("update tblScriptExecuteList set dtStopTime='{}', bComplete=1, "
        " iRowsUpdated={} where iExecuteID = {} ;".format(strdbNow,iIPCount,iEntryID))
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
elif lstReturn[0] != 1:
  LogEntry ("Updating tblScriptExecuteList: Records affected {}, expected 1 record affected".format(lstReturn[0]))
SendNotification("{} has completed processing on {}. Processed {} scans, "
    " {} IP's and {} QID's.".format(strScriptName,strScriptHost,iScanCount,iIPCount,iQIDCount))
LogEntry ("All Done!")
dbConn.close()
objLogOut.close()