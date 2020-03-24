'''
Script to pull all Host Detection data from Qualys
Author Siggi Bjarnason Copyright 2017
Website http://www.ipcalc.us/ and http://www.icecomputing.com

Following packages need to be installed as administrator
pip install requests
pip install xmltodict
pip install pymysql

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
localtime = time.localtime(time.time())
gmt_time = time.gmtime()
iGMTOffset = (time.mktime(localtime) - time.mktime(gmt_time))/3600

print ("This is a script to gather all asset host detections from Qualys via API. This is running under "
        " Python Version {}".format(strVersion))
print ("Running from: {}".format(strRealPath))
now = time.asctime()
print ("The time now is {}".format(now))
print ("Logs saved to {}".format(strLogFile))
objLogOut = open(strLogFile,"w",1)

def LogEntry(strMsg):
  strTemp = ""
  strDBMsg = DBClean(strMsg)
  strSQL = ("INSERT INTO tblLogs (dtTimestamp, vcScriptName, vcLogEntry) "
            " VALUES (now(),'{}','{}');").format(strScriptName,strDBMsg)
  if dbConn !="":
    lstReturn = SQLQuery (strSQL,dbConn)
    if not ValidReturn(lstReturn):
      strTemp = ("   Unexpected issue inserting log entry to the database: {}\n{}".format(lstReturn,strSQL))
    elif lstReturn[0] != 1:
      strTemp = ("   Records affected {}, expected 1 record affected when inserting "
                  " log entry to the database".format(lstReturn[0]))
  else:
    strTemp = ". Database connection not established yet"

  strMsg += strTemp
  strTimeStamp = time.strftime("%m-%d-%Y %H:%M:%S")
  objLogOut.write("{0} : {1}\n".format(strTimeStamp,strMsg))
  print (strMsg)

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

  if os.path.isfile(strConf_File):
    LogEntry ("Configuration File exists")
  else:
    LogEntry ("Can't find configuration file {}, make sure it is the same directory as this script".format(strConf_File))
    sys.exit(4)

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


  if strBaseURL[-1:] != "/":
    strBaseURL += "/"

  LogEntry ("Done processing configuration, moving on")

def ConvertFloat (fValue):
  if isinstance(fValue,(float,int,str)):
    try:
      fTemp = float(fValue)
    except ValueError:
      fTemp = "NULL"
  else:
    fTemp = "NULL"
  return fTemp

def MakeAPICall (strURL, strHeader, strUserName,strPWD, strMethod):

  iErrCode = ""
  iErrText = ""
  dictResponse = {}

  LogEntry ("Doing a {} to URL: \n {}\n".format(strMethod,strURL))
  try:
    if strMethod.lower() == "get":
      WebRequest = requests.get(strURL, headers=strHeader, auth=(strUserName, strPWD))
      LogEntry ("get executed")
    if strMethod.lower() == "post":
      WebRequest = requests.post(strURL, headers=strHeader, auth=(strUserName, strPWD))
      LogEntry ("post executed")
  except Exception as err:
    LogEntry ("Issue with API call. {}".format(err))
    iErrCode = "APIErr"
    iErrText = err
    exit()

  if isinstance(WebRequest,requests.models.Response)==False:
    LogEntry ("response is unknown type")
    iErrCode = "ResponseErr"
    iErrText = "response is unknown type"

  LogEntry ("call resulted in status code {}".format(WebRequest.status_code))

  try:
    dictResponse = xmltodict.parse(WebRequest.text)
  except xml.parsers.expat.ExpatError as err:
    # LogEntry("Expat Error: {}\n{}".format(err,WebRequest.text))
    iErrCode = "Expat Error"
    iErrText = "Expat Error: {}\n{}".format(err,WebRequest.text)
  except Exception as err:
    LogEntry("Unkown xmltodict exception: {}\n{}".format(err,WebRequest.text))
    iErrCode = "xmltodict"
    iErrText = "Unkown xmltodict exception: {}\n{}".format(err,WebRequest.text)
    exit()

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
    LogEntry ("Response not a dictionary")
    sys.exit(8)

  if iErrCode != "" or WebRequest.status_code !=200:
    return "There was a problem with your request. HTTP error {} code {} {}".format(
              WebRequest.status_code,iErrCode,iErrText)
  else:
    return dictResponse

def SQLConn (strServer,strDBUser,strDBPWD,strInitialDB):
  try:
    # Open database connection
    return pymysql.connect(strServer,strDBUser,strDBPWD,strInitialDB)
  except pymysql.err.InternalError as err:
    LogEntry ("Error: unable to connect: {}".format(err))
    sys.exit(5)
  except pymysql.err.OperationalError as err:
    LogEntry ("Operational Error: unable to connect: {}".format(err))
    sys.exit(5)
  except pymysql.err.ProgrammingError as err:
    LogEntry ("Programing Error: unable to connect: {}".format(err))
    sys.exit(5)

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
    if strSQL[:6].lower() != "select":
      db.rollback()
    return "Internal Error: unable to execute: {}\n{}".format(err,strSQL)
  except pymysql.err.ProgrammingError as err:
    if strSQL[:6].lower() != "select":
      db.rollback()
    return "Programing Error: unable to execute: {}\n{}".format(err,strSQL)
  except pymysql.err.OperationalError as err:
    if strSQL[:6].lower() != "select":
      db.rollback()
    return "Programing Error: unable to execute: {}\n{}".format(err,strSQL)
  except pymysql.err.IntegrityError as err:
    if strSQL[:6].lower() != "select":
      db.rollback()
    return "Integrity Error: unable to execute: {}\n{}".format(err,strSQL)
  except pymysql.err.DataError as err:
    if strSQL[:6].lower() != "select":
      db.rollback()
    return "Data Error: unable to execute: {}\n{}".format(err,strSQL)

def UpdateKB (dictResults):
  strSQL = "select * from tbldetections where iQID = {};".format(dictResults["QID"])
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    return
  elif lstReturn[0] == 0:
    # LogEntry ("No detection for QID {}, don't need to save details".format(dictResults["QID"]))
    return
  if "DISCOVERY" in dictResults:
    if "ADDITIONAL_INFO" in dictResults["DISCOVERY"]:
      strAddDetail = DBClean(dictResults["DISCOVERY"]["ADDITIONAL_INFO"])
    else:
      strAddDetail = ""
    if "REMOTE" in dictResults["DISCOVERY"]:
      strRemoteDisc = dictResults["DISCOVERY"]["REMOTE"]
    else:
      strRemoteDisc = ""
  else:
    strRemoteDisc = ""
    strAddDetail = ""

  if "CVSS" in dictResults:
    if "BASE" in dictResults["CVSS"]:
      if isinstance(dictResults["CVSS"]["BASE"],str):
        iCVSSBase = dictResults["CVSS"]["BASE"]
      elif isinstance(dictResults["CVSS"]["BASE"],dict):
        iCVSSBase = dictResults["CVSS"]["BASE"]["#text"]
      else:
        iCVSSBase = "NULL"
    else:
      iCVSSBase = "NULL"
    if "TEMPORAL" in dictResults["CVSS"]:
      iCVSSTemp = ConvertFloat(dictResults["CVSS"]["TEMPORAL"])
    else:
      iCVSSTemp = "NULL"
  else:
    iCVSSTemp = "NULL"
    iCVSSBase = "NULL"


  if "SOLUTION" in dictResults:
    strSolution = DBClean(dictResults["SOLUTION"])
  else:
    strSolution = ""

  if "CONSEQUENCE" in dictResults:
    strConsequence = DBClean(dictResults["CONSEQUENCE"])
  else:
    strConsequence = ""

  strSQL = "select * from tblVulnDetails where iQID = {};".format(dictResults["QID"])
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    sys.exit(9)
  elif lstReturn[0] == 0:
    LogEntry ("Adding QID {} {}".format(dictResults["QID"],dictResults["TITLE"] ))
    try:
      strSQL = ("INSERT INTO tblVulnDetails (iQID, iSeverity, vcTitle, vcCategory, dtLastServiceModified, "
          "dtPublished, bPatchable, tDiagnosis, tSolution, iCVSSBase, iCVSSTemporal, bPCIFlag, bRemoteDisc, "
          "tAdditionalInfo,tConsequence,dtLastTouched) "
          "VALUES('{0}','{1}','{2}','{3}','{4}','{5}','{6}','{7}','{8}',{9},{10},'{11}','{12}','{13}', "
          "'{14}',now());".format(
            dictResults["QID"],dictResults["SEVERITY_LEVEL"],DBClean(dictResults["TITLE"]),
            DBClean(dictResults["CATEGORY"]),QDate2DB(dictResults["LAST_SERVICE_MODIFICATION_DATETIME"]),
            QDate2DB(dictResults["PUBLISHED_DATETIME"]),dictResults["PATCHABLE"],DBClean(dictResults["DIAGNOSIS"]),
            strSolution,iCVSSBase,iCVSSTemp,dictResults["PCI_FLAG"],strRemoteDisc,strAddDetail,strConsequence
            )
          )
    except KeyError as e:
      LogEntry ("KeyError: {}".format(e))
      exit()
  elif lstReturn[0] == 1:
    LogEntry ("QID {} exists, need to update record for {}".format(dictResults["QID"],dictResults["TITLE"] ))
    try:
      strSQL = ("UPDATE tblVulnDetails SET iSeverity = '{}', vcTitle = '{}', vcCategory = '{}', "
            "dtLastServiceModified = '{}', dtPublished = '{}', bPatchable = '{}',tConsequence = '{}',"
            " tDiagnosis = '{}',tSolution = '{}', iCVSSBase = {}, iCVSSTemporal = {}, bPCIFlag = '{}', "
            "bRemoteDisc = '{}', tAdditionalInfo = '{}', dtLastTouched = now() "
            " WHERE iQID = '{}'; ".format(
            dictResults["SEVERITY_LEVEL"],DBClean(dictResults["TITLE"]),DBClean(dictResults["CATEGORY"]),
            QDate2DB(dictResults["LAST_SERVICE_MODIFICATION_DATETIME"]),QDate2DB(dictResults["PUBLISHED_DATETIME"]),
            dictResults["PATCHABLE"],strConsequence, DBClean(dictResults["DIAGNOSIS"]),strSolution,iCVSSBase,
            iCVSSTemp,dictResults["PCI_FLAG"],strRemoteDisc,strAddDetail,dictResults["QID"]
            )
        )
    except KeyError as e:
      LogEntry ("KeyError: {}".format(e))
      exit()
  else:
    LogEntry ("Something is horrible wrong, there are {} entries with QID of {}".format(lstReturn[0],dictResults["QID"]))
    return "Abort!!!"
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    LogEntry (strSQL)
    # sys.exit(9)
  elif lstReturn[0] != 1:
    LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))

  if "BUGTRAQ_LIST" in dictResults:
    strSQL = "delete from tblQID2Bugtraq where iQID = {};".format(dictResults["QID"])
    lstReturn = SQLQuery (strSQL,dbConn)
    if not ValidReturn(lstReturn):
      LogEntry ("Unexpected: {}".format(lstReturn))
      sys.exit(9)
    else:
      LogEntry ("Deleted {} QID to bugtraq mappings".format(lstReturn[0]))


    if isinstance(dictResults["BUGTRAQ_LIST"]["BUGTRAQ"] ,list):
      LogEntry("{} bugtraq's on this QID".format(len(dictResults["BUGTRAQ_LIST"])))
      lstTemp = dictResults["BUGTRAQ_LIST"]["BUGTRAQ"]
    else:
      lstTemp = [dictResults["BUGTRAQ_LIST"]["BUGTRAQ"]]
      LogEntry("Only one bugtraq on this QID")

    for dictBugTraq in lstTemp:
      strSQL = "select * from tblBugTraq where iBugTraqID = {};".format(dictBugTraq["ID"])
      lstReturn = SQLQuery (strSQL,dbConn)
      LogEntry("Records affected: {}".format(lstReturn[0]))
      if not ValidReturn(lstReturn):
        LogEntry ("Unexpected: {}".format(lstReturn))
        sys.exit(9)
      elif lstReturn[0] == 0:
        LogEntry ("bugtraq ID {} doesn't exists, inserting it".format(dictBugTraq["ID"]))
        strSQL = "INSERT INTO tblBugTraq (iBugTraqID,vcURL) VALUES ({}, '{}');".format(dictBugTraq["ID"],dictBugTraq["URL"])
        lstReturn = SQLQuery (strSQL,dbConn)
        if not ValidReturn(lstReturn):
          LogEntry ("Unexpected: {}".format(lstReturn))
          sys.exit(9)
      else:
        LogEntry("bugtraq ID {} already exists, not doing anything".format(dictBugTraq["ID"]))

      strSQL = "INSERT INTO tblQID2Bugtraq (iQID,iBugTraqID) VALUES ({},{});".format(dictResults["QID"],dictBugTraq["ID"])
      lstReturn = SQLQuery (strSQL,dbConn)
      if not ValidReturn(lstReturn):
        LogEntry ("Unexpected: {}".format(lstReturn))
        sys.exit(9)
  else:
    LogEntry("No bugtraq in this one")


def ProcessKBResponse(APIResponse):
  iRowCount = 0
  if isinstance(APIResponse,str):
    LogEntry(APIResponse)
  if isinstance(APIResponse,dict):
    if "VULN_LIST" in APIResponse["KNOWLEDGE_BASE_VULN_LIST_OUTPUT"]["RESPONSE"]:
      if "VULN" in APIResponse["KNOWLEDGE_BASE_VULN_LIST_OUTPUT"]["RESPONSE"]["VULN_LIST"]:
        if isinstance(APIResponse["KNOWLEDGE_BASE_VULN_LIST_OUTPUT"]["RESPONSE"]["VULN_LIST"]["VULN"],list):
          iRowCount = len(APIResponse["KNOWLEDGE_BASE_VULN_LIST_OUTPUT"]["RESPONSE"]["VULN_LIST"]["VULN"])
          LogEntry ("{} QIDs in results".format(iRowCount))
          for dictVuln in APIResponse["KNOWLEDGE_BASE_VULN_LIST_OUTPUT"]["RESPONSE"]["VULN_LIST"]["VULN"]:
            UpdateKB (dictVuln)
        else:
          LogEntry ("Only one QID in results")
          iRowCount = 1
          UpdateKB (APIResponse["KNOWLEDGE_BASE_VULN_LIST_OUTPUT"]["RESPONSE"]["VULN_LIST"]["VULN"])
      else:
        LogEntry("there is vulnerabitlity list but no vulnerabitlities, weird!!!!")
    else:
      LogEntry ("There are no results")
  if "WARNING" in APIResponse["KNOWLEDGE_BASE_VULN_LIST_OUTPUT"]["RESPONSE"]:
    strURL = APIResponse["KNOWLEDGE_BASE_VULN_LIST_OUTPUT"]["RESPONSE"]["WARNING"]["URL"]
    LogEntry ("Next URL: {}".format(strURL))
    APIResponse = MakeAPICall(strURL,strHeader,strUserName,strPWD,strMethod)
    ProcessKBResponse(APIResponse)


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

def DBClean(strText):
  strTemp = strText.encode("ascii","ignore")
  strTemp = strTemp.decode("ascii","ignore")
  strTemp = strTemp.replace("\\","\\\\")
  strTemp = strTemp.replace("'","\\'")
  return strTemp

def QDate2DB(strDate):
  strTemp = strDate.replace("T"," ")
  return strTemp.replace("Z","")

def UpdateDB (dictResults):
  global iTotalCount

  LogEntry("\n--------------------\nProcessing host id {}".format(dictResults["ID"]))
  strSQL = "delete from tbldetections where iHostID = {};".format(dictResults["ID"])
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    sys.exit(9)
  else:
    LogEntry ("Deleted {} detections".format(lstReturn[0]))

  if "DNS" in dictResults:
    strHostName = DBClean(dictResults["DNS"])
  else:
    strHostName = "Unknown"

  if "OS" in dictResults:
    strOS = DBClean(dictResults["OS"])
  else:
    strOS = "Unknown"

  if "LAST_VM_SCANNED_DATE" in dictResults:
    dtLastVMSCan = "'" + QDate2DB(dictResults["LAST_VM_SCANNED_DATE"]) + "'"
  else:
    dtLastVMSCan = "NULL"

  if "LAST_VM_SCANNED_DURATION" in dictResults:
    iVMScanDuration = DBClean(dictResults["LAST_VM_SCANNED_DURATION"])
  else:
    iVMScanDuration = "NULL"

  if "OS_CPE" in dictResults:
    strOS_CPE = DBClean(dictResults["OS_CPE"])
  else:
    strOS_CPE = ""

  if "TRACKING_METHOD" in dictResults:
    strTracking = DBClean(dictResults["TRACKING_METHOD"])
  else:
    strTracking = ""

  if "NETBIOS" in dictResults:
    strNetBIOS = DBClean(dictResults["NETBIOS"])
  else:
    strNetBIOS = ""

  if "LAST_VM_AUTH_SCANNED_DATE" in dictResults:
    dtVMAuth = "'" + QDate2DB(dictResults["LAST_VM_AUTH_SCANNED_DATE"]) + "'"
  else:
    dtVMAuth = "NULL"

  if "LAST_PC_SCANNED_DATE" in dictResults:
    dtPCScan = "'" + QDate2DB(dictResults["LAST_PC_SCANNED_DATE"]) + "'"
  else:
    dtPCScan = "NULL"

  if "LAST_VM_AUTH_SCANNED_DURATION" in dictResults:
    if isInt(dictResults["LAST_VM_AUTH_SCANNED_DURATION"]):
      iAuthDuration = int(dictResults["LAST_VM_AUTH_SCANNED_DURATION"])
    else:
      iAuthDuration = "NULL"
  else:
    iAuthDuration = "NULL"

  if "EC2_INSTANCE_ID" in dictResults:
    strECID = DBClean(dictResults["EC2_INSTANCE_ID"])
  else:
    strECID = ""

  if "QG_HOSTID" in dictResults:
    strQGID = DBClean(dictResults["QG_HOSTID"])
  else:
    strQGID = ""

  strSQL = "select * from tblhostlist where iHostID = {};".format(dictResults["ID"])
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    sys.exit(9)
    return lstReturn
  elif lstReturn[0] == 0:
    LogEntry ("Adding ID {} {}".format(dictResults["ID"],strHostName))
    strSQL = ("INSERT INTO tblhostlist (iHostID,vcIPAddr,vcOperatingSystem,vcHostName,dtLastScan,dtVMScanned,"
          "iLastScanDuration,vcOS_CPE,vcTrackingMethod,vcNetBIOS,dtVMAuthScanned,iVMAuthDuration,dtLastPCScan,vcEC_ID,"
          "vcQGid,dtLastAPIUpdate) "
          "VALUES({0},'{1}','{2}','{3}','{4}',{5},{6},'{7}','{8}','{9}',{10},{11},{12},'{13}','{14}',now());".format(
            dictResults["ID"],dictResults["IP"],strOS,strHostName,QDate2DB(dictResults["LAST_SCAN_DATETIME"]),
            dtLastVMSCan,iVMScanDuration,strOS_CPE,strTracking,strNetBIOS,dtVMAuth,iAuthDuration,dtPCScan,strECID,
            strQGID)
          )
  elif lstReturn[0] == 1:
    LogEntry ("ID {} exists, need to update record for {}".format(dictResults["ID"],strHostName))
    strSQL = ("UPDATE tblhostlist SET vcIPAddr = '{}',vcOperatingSystem = '{}',vcHostName = '{}',dtLastScan = '{}',"
          "dtVMScanned = {},iLastScanDuration = {},vcOS_CPE = '{}',vcTrackingMethod = '{}',vcNetBIOS = '{}',"
          "dtVMAuthScanned = {},iVMAuthDuration = {},dtLastPCScan = {},vcEC_ID = '{}',vcQGid = '{}',"
          "dtLastAPIUpdate = now() WHERE iHostID = {};".format(dictResults["IP"],strOS,strHostName,
            QDate2DB(dictResults["LAST_SCAN_DATETIME"]),dtLastVMSCan,iVMScanDuration,strOS_CPE,strTracking,
            strNetBIOS,dtVMAuth,iAuthDuration,dtPCScan,strECID,strQGID,dictResults["ID"]
            )
        )
  else:
    LogEntry ("Something is horrible wrong, there are {} entries with ID of {}".format(lstReturn[0],dictResults["ID"]))
    return "Abort!!!"
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    LogEntry (strSQL)
    sys.exit(9)
  elif lstReturn[0] > 1:
    LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))

  if isinstance(dictResults["DETECTION_LIST"]["DETECTION"],list):
    LogEntry ("There are {} detections".format(len(dictResults["DETECTION_LIST"]["DETECTION"])))
    lstTemp = dictResults["DETECTION_LIST"]["DETECTION"]
  else:
    LogEntry ("Only One detection")
    lstTemp = [dictResults["DETECTION_LIST"]["DETECTION"]]

  lstQID = []
  dictKBParams = {}
  dictKBParams["action"] = "list"
  for dictTemp in lstTemp:
    if "PORT" in dictTemp:
      strPort = dictTemp["PORT"]
    else:
      strPort = "NULL"

    if "PROTOCOL" in dictTemp:
      strProtocol = dictTemp["PROTOCOL"]
    else:
      strProtocol = ""

    if "RESULTS" in dictTemp:
      strResults = dictTemp["RESULTS"].replace("\\","\\\\")
      strResults = strResults.replace("'","\\'")
    else:
      strResults = ""

    if "LAST_PROCESSED_DATETIME" in dictTemp:
      dtProccess = "'" + QDate2DB(dictTemp["LAST_PROCESSED_DATETIME"]) +"'"
    else:
      dtProccess = "NULL"

    if "FQDN" in dictResults:
      strFQDN = DBClean(dictResults["FQDN"])
    else:
      strFQDN = ""

    if "LAST_FIXED_DATETIME" in dictResults:
      dtFixed = "'" + QDate2DB(dictResults["LAST_FIXED_DATETIME"]) + "'"
    else:
      dtFixed = "NULL"

    if "FIRST_REOPENED_DATETIME" in dictResults:
      dtReopened = "'" + QDate2DB(dictResults["FIRST_REOPENED_DATETIME"]) + "'"
    else:
      dtReopened = "NULL"

    if "LAST_REOPENED_DATETIME" in dictResults:
      dtLastReopen = "'" + QDate2DB(dictResults["LAST_REOPENED_DATETIME"]) + "'"
    else:
      dtLastReopen = "NULL"

    if "TIMES_REOPENED" in dictResults:
      if isInt(dictResults["TIMES_REOPENED"]):
        iReopenCount = int(dictResults["TIMES_REOPENED"])
      else:
        iReopenCount = "NULL"
    else:
      iReopenCount = "NULL"

    if "SERVICE" in dictResults:
      strService = DBClean(dictResults["SERVICE"])
    else:
      strService = ""

    strSQL = ("INSERT INTO tbldetections (iHostID, iQID, vcType, iSeverity, iPortNumber, vcProtocol, bSSL, "
          "tResults, vcStatus, dtFirstFound, dtLastFound, iTimesFound, dtLastTest, dtLastUpdate, bIsIgnored, "
          "bIsDisabled, dtLastProcessed, vcFQDN, dtLastFixed, dtFirstReopened, dtLastReopened, iTimesReopened, "
          "vcService, dtLastAPIUpdate) "
          "VALUES('{0}','{1}','{2}','{3}',{4},'{5}','{6}','{7}','{8}','{9}','{10}','{11}','{12}','{13}','{14}',"
          " '{15}',{16},'{17}',{18},{19},{20}, "
          "{21},'{22}',now());".format(
            dictResults["ID"],dictTemp["QID"],dictTemp["TYPE"],dictTemp["SEVERITY"],strPort,strProtocol,
            dictTemp["SSL"],strResults,dictTemp["STATUS"],QDate2DB(dictTemp["FIRST_FOUND_DATETIME"]),
            QDate2DB(dictTemp["LAST_FOUND_DATETIME"]),dictTemp["TIMES_FOUND"],
            QDate2DB(dictTemp["LAST_TEST_DATETIME"]), QDate2DB(dictTemp["LAST_UPDATE_DATETIME"]),
            dictTemp["IS_IGNORED"],dictTemp["IS_DISABLED"], dtProccess, strFQDN,dtFixed,dtReopened,
            dtLastReopen,iReopenCount,strService
            )
          )
    lstReturn = SQLQuery (strSQL,dbConn)
    if not ValidReturn(lstReturn):
      LogEntry ("Unexpected: {}".format(lstReturn))
      sys.exit(9)
    elif lstReturn[0] != 1:
      LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))

    lstQID.append(dictTemp["QID"])

  dictKBParams["ids"] = ",".join(lstQID)
  strListScans = urlparse.urlencode(dictKBParams)
  strURL = strBaseURL + strKBAPI +"?" + strListScans
  APIResponse = MakeAPICall(strURL,strHeader,strUserName,strPWD,strMethod)
  ProcessKBResponse(APIResponse)
  iTotalCount += 1
  strSQL = "update tblScriptExecuteList set dtStopTime=now(), bComplete=0, iRowsUpdated={} where iExecuteID = {} ;".format(iTotalCount,iEntryID)
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    exit()
  elif lstReturn[0] != 1:
    LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))

dbConn = ""
processConf()
dbConn = SQLConn (strServer,strDBUser,strDBPWD,strInitialDB)
strSQL = ("select date(dtStartTime) from tblScriptExecuteList where bComplete = 1 and "
          " vcScriptName = '{}' order by dtStartTime desc limit 1;").format(strScriptName)
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
  sys.exit(9)
elif lstReturn[0] != 1:
  dtLastExecute = lstReturn[0]
else:
  dtLastExecute = lstReturn[1][0][0]

strSQL = "select TIMESTAMPDIFF(MINUTE,max(dtTimestamp),now()) as timediff from tblLogs where vcScriptName = '{}';".format(strScriptName)
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
  sys.exit(9)
elif lstReturn[0] == 0:
  iQuietMin = -1
elif lstReturn[0] > 1:
  iQuietMin = lstReturn[0] * -1
else:
  if isInt(lstReturn[1][0][0]):
    iQuietMin = int(lstReturn[1][0][0])
  else:
    iQuietMin = -1

strSQL = "select vcLogEntry from tblLogs where ILogID = (select max(ILogID) from tblLogs where vcScriptName = '{}');".format(strScriptName)
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
  sys.exit(9)
elif lstReturn[0] != 1:
  LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))
  strLastEntry = "All Done!"
else:
  strLastEntry = lstReturn[1][0][0]

if iQuietMin == -1:
  LogEntry ("This is the first time this script is run in this environment, setting last scan time to {} "
              "minutes to work around quiet time logic".format(iMinQuietTime))
  iQuietMin = iMinQuietTime
elif iQuietMin < -1:
  LogEntry ("There were {} records returned when querying for last execute, this should not happen. Since I can't "
            "deterministicly figure out this out, setting last scan time {} minutes to work "
            "around quiet time logic".format(iQuietMin * -1, iMinQuietTime))
  iQuietMin = iMinQuietTime

if iQuietMin < iMinQuietTime :
  dbConn = ""
  LogEntry ("Last Log update {1} min ago. Either the script is already running or it's been less that {0} min "
        "since it last run, please wait until after {0} since last run. Exiting".format(iMinQuietTime,iQuietMin ))
  sys.exit()
else:
  LogEntry("Database connection established. It's been {} minutes since last log entry.".format(iQuietMin))


LogEntry("Starting Processing. Script {} running under Python version {}".format(strRealPath,strVersion))

strSQL = "INSERT INTO tblScriptExecuteList (vcScriptName,dtStartTime,iGMTOffset) VALUES('{}',now(),{});".format(strScriptName,iGMTOffset)
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
  sys.exit(9)
elif lstReturn[0] != 1:
  LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))

strSQL = ("select iExecuteID from tblScriptExecuteList where dtStartTime = "
" (select max(dtStartTime) from tblScriptExecuteList where vcScriptName = '{}');").format(strScriptName)
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
  sys.exit(9)
elif lstReturn[0] != 1:
  LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))
  iEntryID = -10
else:
  iEntryID = lstReturn[1][0][0]

LogEntry("Recorded start entry, ID {}".format(iEntryID))

if strLoadType.lower() == "full":
  dtLastExecute = dtFullLoad
  LogEntry("Doing a Full Load per directive from configuration file, going back to {}".format(dtFullLoad))
else:
  LogEntry("Configuration file indicates incementatal load, finding last execution date")
  if isInt(dtLastExecute):
    LogEntry ("Records affected {}, expected 1 record affected".format(dtLastExecute))
    LogEntry ("Since the result set is Unexpected, switching to full load, going back to {}".format(dtFullLoad))
    dtLastExecute = dtFullLoad
  else:
    LogEntry ("starting from {}".format(dtLastExecute))

strAPIFunction = "/api/2.0/fo/asset/host/vm/detection"
if strAPIFunction[0] == "/":
  strAPIFunction = strAPIFunction[1:]

if strAPIFunction[-1:] != "/":
  strAPIFunction += "/"

strKBAPI = "/api/2.0/fo/knowledge_base/vuln/"

if strKBAPI[0] == "/":
  strKBAPI = strKBAPI[1:]

if strKBAPI[-1:] != "/":
  strKBAPI += "/"

LogEntry ("API Function: {}".format(strAPIFunction))

strMethod = "get"
dictParams = {}
dictParams["action"] = "list"
dictParams["output_format"] = "XML"
dictParams["show_reopened_info"] = "1"
dictParams["id_min"] = 0
dictParams["status"] = "New,Active,Re-Opened,Fixed"
# dictParams["ids"] = "11038877"
dictParams["detection_updated_since"]=dtLastExecute

strListScans = urlparse.urlencode(dictParams)

if strLastEntry != "All Done!":
  LogEntry ("Either this is the first time this script is being run or it ended abnormally last time.")
  strSQL = ("select vcLogEntry from tblLogs where ILogID = (select max(ILogID) from tblLogs where vcLogEntry like "
            " '%Next URL%'and vcScriptName = '{}');").format(strScriptName)
  lstReturn = SQLQuery (strSQL,dbConn)
  if not ValidReturn(lstReturn):
    LogEntry ("Unexpected: {}".format(lstReturn))
    sys.exit(9)
  elif lstReturn[0] != 1:
    LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))
    if lstReturn[0] == 0:
      LogEntry ("Looks like this is the first time the script is run in this environment, starting from scratch")
    else:
      LogEntry ("don't know what to do with multiple next URL's, so starting from scratch")
    strURL = strBaseURL + strAPIFunction +"?" + strListScans
  else:
    LogEntry ("confirmed last job ended abnormally, found were it left off and starting from there.")
    strURL = lstReturn[1][0][0][10:]
else:
  LogEntry ("Confirmed last job exited normally, starting from scratch")
  strURL = strBaseURL + strAPIFunction +"?" + strListScans

LogEntry ("Next URL: {}".format(strURL))
APIResponse = MakeAPICall(strURL,strHeader,strUserName,strPWD,strMethod)

bMoreData = True
iTotalCount = 0

while bMoreData:
  # strSQL = "update tblScriptExecuteList set dtStopTime=now(), bComplete=0, iRowsUpdated={} where iExecuteID = {} ;".format(iTotalCount,iEntryID)
  # lstReturn = SQLQuery (strSQL,dbConn)
  # if not ValidReturn(lstReturn):
  #   LogEntry ("Unexpected: {}".format(lstReturn))
  #   exit()
  # elif lstReturn[0] != 1:
  #   LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))
  if isinstance(APIResponse,str):
    LogEntry(APIResponse)
    bMoreData = False
  if isinstance(APIResponse,dict):
    if "HOST_LIST" in APIResponse["HOST_LIST_VM_DETECTION_OUTPUT"]["RESPONSE"]:
      if "HOST" in APIResponse["HOST_LIST_VM_DETECTION_OUTPUT"]["RESPONSE"]["HOST_LIST"]:
        if isinstance(APIResponse["HOST_LIST_VM_DETECTION_OUTPUT"]["RESPONSE"]["HOST_LIST"]["HOST"],list):
          iResultCount = len(APIResponse["HOST_LIST_VM_DETECTION_OUTPUT"]["RESPONSE"]["HOST_LIST"]["HOST"])
          # iTotalCount += iResultCount
          LogEntry ("{} hosts in results".format(iResultCount))
          for dictHosts in APIResponse["HOST_LIST_VM_DETECTION_OUTPUT"]["RESPONSE"]["HOST_LIST"]["HOST"]:
            UpdateDB (dictHosts)
        else:
          # iTotalCount += 1
          LogEntry ("Only one host in results")
          UpdateDB (APIResponse["HOST_LIST_VM_DETECTION_OUTPUT"]["RESPONSE"]["HOST_LIST"]["HOST"])
      else:
        LogEntry("there is hosts list but no hosts, weird!!!!")
    else:
      LogEntry ("There are no results")
    if "WARNING" in APIResponse["HOST_LIST_VM_DETECTION_OUTPUT"]["RESPONSE"]:
      strURL = APIResponse["HOST_LIST_VM_DETECTION_OUTPUT"]["RESPONSE"]["WARNING"]["URL"]
      LogEntry ("Next URL: {}".format(strURL))
      APIResponse = MakeAPICall(strURL,strHeader,strUserName,strPWD,strMethod)
    else:
      bMoreData = False

LogEntry("Updating completion entry")
strSQL = "update tblScriptExecuteList set dtStopTime=now(), bComplete=1, iRowsUpdated={} where iExecuteID = {} ;".format(iTotalCount,iEntryID)
lstReturn = SQLQuery (strSQL,dbConn)
if not ValidReturn(lstReturn):
  LogEntry ("Unexpected: {}".format(lstReturn))
elif lstReturn[0] != 1:
  LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))
LogEntry ("All Done!")