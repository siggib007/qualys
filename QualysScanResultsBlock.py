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

strFormat = "json"
ISO = time.strftime("-%Y-%m-%d-%H-%M-%S")
iLoc = sys.argv[0].rfind(".")
strConf_File = sys.argv[0][:iLoc] + ".ini"
strChild_File = sys.argv[0][:iLoc] + "-children.txt"
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

print ("This is a script to gather all scan results details from Qualys via API. This is running under Python Version {}".format(strVersion))
print ("Running from: {}".format(strRealPath))
now = time.asctime()
print ("The time now is {}".format(now))
print ("Logs saved to {}".format(strLogFile))
objLogOut = open(strLogFile,"w",1)

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
    if not bStatus or WebRequest.status_code != 200:
      LogEntry ("Problme: Status Code:[] API Response OK={}")
      LogEntry (WebRequest.text)

def CleanExit(strCause):
  # if dbConn !="":
  #   strSQL = "update tblScriptExecuteList set dtStopTime=now(), bComplete=0, iRowsUpdated={} where iExecuteID = {} ;".format(iUpdateCount,iEntryID)
  #   lstReturn = SQLQuery (strSQL,dbConn)
  dbConn.close()

  SendNotification("{} is exiting abnormally on {} {}".format(strScriptName,strScriptHost, strCause))
  objLogOut.close()
  objChildFile.close()
  sys.exit(9)

def LogEntry(strMsg,bAbort=False):
  strTemp = ""
  strDBMsg = DBClean(strMsg)
  strSQL = "INSERT INTO tblLogs (dtTimestamp, vcScriptName, vcLogEntry) VALUES (now(),'{}','{}');".format(strScriptName,strDBMsg)
  if dbConn !="":
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
      if strVarName == "BatchSize":
        iBatchSize = int(strValue)

  if strBaseURL[-1:] != "/":
    strBaseURL += "/"

  LogEntry ("Done processing configuration, moving on")

def MakeAPICall (strURL, dictHeader, strUserName,strPWD, strMethod):

  iErrCode = ""
  iErrText = ""
  dictResponse = {}

  LogEntry ("Doing a {} to URL: \n {}\n".format(strMethod,strURL))
  try:
    if strMethod.lower() == "get":
      WebRequest = requests.get(strURL, headers=dictHeader, auth=(strUserName, strPWD))
      LogEntry ("get executed")
    if strMethod.lower() == "post":
      WebRequest = requests.post(strURL, headers=dictHeader, auth=(strUserName, strPWD))
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
    if strFormat == "xml":
      try:
        dictResponse = xmltodict.parse(WebRequest.text)
      except xml.parsers.expat.ExpatError as err:
        # LogEntry("Expat Error: {}\n{}".format(err,WebRequest.text))
        iErrCode = "Expat Error"
        iErrText = "Expat Error: {}\n{}".format(err,WebRequest.text)
      except Exception as err:
        LogEntry("Unkown xmltodict exception: {}".format(err))
        CleanExit(", Unkown xmltodict exception, please check the logs")
    elif strFormat == "json":
      dictResponse = json.loads(WebRequest.text)
  else:
    iErrCode = WebRequest.status_code
    iErrText = WebRequest.text


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
    elif "ServiceResponse" in dictResponse:
      if "responseCode" in dictResponse["ServiceResponse"]:
        if dictResponse["ServiceResponse"]["responseCode"] != "SUCCESS":
          iErrCode = "json error"
          iErrText = dictResponse["ServiceResponse"]["responseCode"]
      else:
        LogEntry ("KeyError: No response code")
        LogEntry (WebRequest.text)
        iErrCode = "Unknown"
        iErrText = "Unexpected error"
  elif isinstance(dictResponse,list):
    LogEntry ("Response is a list of {} elements".format(len(dictResponse)))
  else:
    LogEntry ("Aborting abnormally because API response not translated to a dictionary. it's {}".format(type(dictResponse)),True)

  if iErrCode != "" or WebRequest.status_code !=200:
    LogEntry ("There was a problem with your request. HTTP error {} code {} {}".format(WebRequest.status_code,iErrCode,iErrText))
    if WebRequest.status_code !=200:
      LogEntry ("Since HTTP status is {}, Exiting".format(WebRequest.status_code),True)
  else:
    return dictResponse

def SQLConn (strServer,strDBUser,strDBPWD,strInitialDB):
  try:
    # Open database connection
    return pymysql.connect(strServer,strDBUser,strDBPWD,strInitialDB)
  except pymysql.err.InternalError as err:
    LogEntry ("Error: unable to connect: {}".format(err),True)
  except pymysql.err.OperationalError as err:
    LogEntry ("Operational Error: unable to connect: {}".format(err),True)
  except pymysql.err.ProgrammingError as err:
    LogEntry ("Programing Error: unable to connect: {}".format(err),True)

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
  except pymysql.err.InternalError as err:
    return "Internal Error: unable to execute: {}\n{}\nLength of SQL statement {}\n".format(err,strSQL[:255],len(strSQL))
  except pymysql.err.ProgrammingError as err:
    return "Programing Error: unable to execute: {}\n{}\nLength of SQL statement {}\n".format(err,strSQL[:255],len(strSQL))
  except pymysql.err.OperationalError as err:
    return "Programing Error: unable to execute: {}\n{}\nLength of SQL statement {}\n".format(err,strSQL[:255],len(strSQL))
  except pymysql.err.IntegrityError as err:
    return "Integrity Error: unable to execute: {}\n{}\nLength of SQL statement {}\n".format(err,strSQL[:255],len(strSQL))
  except pymysql.err.DataError as err:
    return "Data Error: unable to execute: {}\n{}\nLength of SQL statement {}\n".format(err,strSQL[:255],len(strSQL))
  except pymysql.err.InterfaceError as err:
    return "Interface Error: unable to execute: {}\n{}\nLength of SQL statement {}\n".format(err,strSQL[:255],len(strSQL))

def ValidReturn(lsttest):
  if isinstance(lsttest,list):
    if len(lsttest) == 2:
      if isinstance(lsttest[0],int) and isinstance(lsttest[1],tuple):
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
  strTemp = DBClean(strDate)
  strTemp = strTemp.replace("T"," ")
  return strTemp.replace("Z","")

def DBClean(strText):
  strTemp = strText.encode("ascii","ignore")
  strTemp = strTemp.decode("ascii","ignore")
  strTemp = strTemp.replace("\\","\\\\")
  strTemp = strTemp.replace("'","\\'")
  return strTemp

dbConn = ""
processConf()
dbConn = SQLConn (strServer,strDBUser,strDBPWD,strInitialDB)
strSQL = "select dtStartTime from tblScriptExecuteList where bComplete = 1 and vcScriptName = '{}' order by dtStartTime desc limit 1;".format(strScriptName)
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
  sys.exit(9)
elif lstReturn[0] != 1:
  LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))
  dtLastExecute = -10
else:
  dtLastExecute = lstReturn[1][0][0]

strSQL = "select TIMESTAMPDIFF(MINUTE,max(dtTimestamp),now()) as timediff from tblLogs where vcScriptName = '{}';".format(strScriptName)
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
  sys.exit(9)
elif lstReturn[0] != 1:
  LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))
  iQuietMin = iMinQuietTime
else:
  if isInt(lstReturn[1][0][0]):
    iQuietMin = int(lstReturn[1][0][0])
  else:
    LogEntry ("This is the first time this script is run in this environment, setting last scan time to {} minutes to work around quiet time logic".format(iMinQuietTime))
    iQuietMin = iMinQuietTime

if iQuietMin < iMinQuietTime :
  dbConn = ""
  LogEntry ("Either the script is already running or it's been less that {0} min since it last run, please wait until after {0} since last run. Exiting".format(iMinQuietTime))
  sys.exit()
else:
  LogEntry("Database connection established. It's been {} minutes since last log entry.".format(iQuietMin))

LogEntry("Starting Processing. Script {} running under Python version {}".format(strRealPath,strVersion))

strSQL = "INSERT INTO tblScriptExecuteList (vcScriptName,dtStartTime,iGMTOffset) VALUES('{}',now(),{});".format(strScriptName,iGMTOffset)
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
  CleanExit("due to unexpected SQL return, please check the logs")
elif lstReturn[0] != 1:
  LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))

strSQL = "select iExecuteID,dtStartTime from tblScriptExecuteList where vcScriptName = '{}' order by dtStartTime desc limit 1;".format(strScriptName)
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
  CleanExit("due to unexpected SQL return, please check the logs")
elif lstReturn[0] != 1:
  LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))
  iEntryID = -10
else:
  iEntryID = lstReturn[1][0][0]
  dtStartTime = lstReturn[1][0][1]

LogEntry("Recorded start entry, ID {}".format(iEntryID))

strAPIFunction = "/api/2.0/fo/scan"
if strAPIFunction[0] == "/":
  strAPIFunction = strAPIFunction[1:]

if strAPIFunction[-1:] != "/":
  strAPIFunction += "/"

LogEntry ("API Function: {}".format(strAPIFunction))

strMethod = "get"
dictParams = {}
dictParams["action"] = "fetch"
dictParams["output_format"] = "json_extended"
dictParams["scan_ref"]="scan/1524010672.73931"

if "output_format" in dictParams:
  if dictParams["output_format"][:4] == "json":
    strType = "json"
  else:
    strType = dictParams["output_format"]

strListScans = urlparse.urlencode(dictParams)
strURL = strBaseURL + strAPIFunction +"?" + strListScans
APIResponse = MakeAPICall(strURL,strHeader,strUserName,strPWD,strMethod)

for element in APIResponse:
  if "launch_date" in element:
    print ("\nScan Title: {}".format(element["scan_title"]))
    print ("Date Scan Launced: {}".format(element["launch_date"]))
    print ("Number of hosts in scan: {}".format(element["total_hosts"]))
    print ("Option profile: {}\n".format(element["option_profile"]))
    print ("IP Address,DNS Name,NetBIOS name,Operating System,IP Status,QID,Severity,Port,Protocol,FQDN,SSL")
  if "ip" in element:
    print ("{},{},{},{},{},{},{},{},{},{},{}".format(element["ip"],element["dns"],element["netbios"],element["os"],element["ip_status"].replace(", ","-") ,
      element["qid"],element["severity"],element["port"],element["protocol"],element["fqdn"],element["ssl"]))
