##
## Copyright (c) 2023, Crash Override, Inc.
##
## This file is part of Chalk
## (see https://crashoverride.com/docs/chalk)
##

## See if we have PII data present at the time of chalk
import std/re
import std/tables
import std/hashes
import ../config, ../plugin_api

type TechStackType* = enum
    database = 1,
    webServer = 2,
    protocol = 3,
    language = 4

proc hash(t: TechStackType): Hash =
    result = int(t)

type DatabaseType* = enum
    firebird = 100,
    hypersonicSQL = 101,
    ibmDb2 = 102,
    microsoftAccess = 103,
    microsoftSQLServer = 104,
    mongoDB = 105,
    mySQL = 106,
    oracle = 107,
    postgreSQL = 108,
    sqlite = 109,
    sysbase = 110

# we need this as DatabaseType is not a simple standard type and needs
# to be used as a key to the dictionary
proc hash(t: DatabaseType): Hash =
    result = int(t)

type WebServerType* = enum
    apache = 200,
    nginx = 201,
    iis = 202

proc hash(t: WebServerType): Hash =
    result = int(t)


type ProtocolType* = enum
    ldap = 300

proc hash(t: ProtocolType): Hash =
    result = int(t)

#
# Firebird
#
let RE_FIREBIRD_PYTHON* = re"^import\s+fdb\b"
let RE_FIREBIRD_GENERIC* = re"(using\s+FirebirdSql.Data.FirebirdClient|^include\s+.ibpp.h.|^require\(.node-firebird.\)|^require\s+.fb.\b)"

#
# Hypersonic SQL
#
let RE_HYPERSONIC_SQL* = re"(hsqldb|HyperSQL|org.hsqldb.jdbc)"

#
# IBM DB2
#
let RE_IBM_DB2* = re"\b(db2jcc|com\.ibm\.db2\.jdbc|(ibm_db|ibm_db_dbi))\b"
let RE_IBM_DB2_JAVA* = re"import\s+com.ibm.db2.jcc.DB2Driver"

#
# MS Access
#
let RE_MS_ACCESS_JAVA* = re"\b(jdbc:odbc:|ucanaccess|msaccess|jackcess)\b"

#
# MS SQL Server
#
let RE_MS_SQL* = re"\b(?:mssql|sqlserver|ms_sql)\b"

#
# MongoDB
#
let RE_MONGODB* = re"\b(mongodb|mongoclient|mongodbdriver|mongodatabase)\b"
#
# MySQL
#
# https://github.com/nim-lang/Nim/issues/14049
let RE_MYSQL* = re"mysql:\/\/[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[\w\.]+\/[a-zA-Z0-9_]+"
let RE_PYTHON_MYSQL* = re"^import\s+(mysql.connector|pymysql|MySQLdb)\b"
let RE_PHP_MYSQL* = re"\b(mysqli|mysql\_.*|PDO::MYSQL|pdo::mysql|pdo.mysql|->mysql)\b"
# let RE_GO_MYSQL2* = re"import\s+.github.com/siddontang/go-mysql/mysql"
let RE_GO_MYSQL* = re"^import\s+.*/mysql"
let RE_JS_MYSQL* = re"^require\(.mysql.+\);"
let RE_JAVA_MYSQL* = re"jdbc:mysql:"

#
# Oracle
#
let RE_ORACLE* = re"\b(oracledb|oraclient|oradatabase)\b"

#
# PostgreSQL
#
let RE_POSTGRES* = re"\b(postgres(ql)?|pgclient|pgdatabase)\b"

#
# SQLite
#
let RE_SQLITE* = re"\bsqlite:\/\/\b"


#
# Sysbase
#

let dbRegexDict* = {
    mySQL: @[RE_MYSQL, RE_PYTHON_MYSQL, RE_GO_MYSQL, RE_JS_MYSQL, RE_JAVA_MYSQL],
    firebird: @[RE_FIREBIRD_GENERIC, RE_FIREBIRD_PYTHON],
    sqlite: @[RE_SQLITE],
}.toTable()

let dbResultDict* = {
    mySQL: false,
    firebird: false,
    sqlite: false,
}.toTable()

let techStackResult* = {
    database: dbResultDict,
}.toTable()

template checkLine(seen: bool, line: string, regexes: seq[Regex]) =
    if not seen:
        for regex in regexes:
            if find(line, regex) != -1:
                seen = true
                trace("Found match for regex in line " & $(line))
                break

let names = ["firebird", "hypersonicSQL", "ibmDb2", "miscrosoftAccess",
"microsoftSQLServer", "mongoDB", "mySQL", "oracle", "postgreSQL", "sqlite",
"sysbase"]

# only parse top 20 lines for imports
let head = 20

var dbDetected = initTable[string, bool]()

proc scanFile(filePath: string, kind: string) =
    var strm = newFileStream(filePath, fmRead)
    if isNil(strm):
        return

    var line = ""
    # FIXME initialize from dictionary
    var foundKind = false

    var i = 0
    while strm.readLine(line):
        if i >= head:
            break
        i += 1

        if not dbDetected[kind]:
            if kind == "mySQL":
                checkLine(foundKind, line, dbRegexDict[mySQL])
            elif kind == "firebird":
                checkLine(foundKind, line, @[RE_FIREBIRD_PYTHON, RE_FIREBIRD_GENERIC])
            elif kind == "hypersonicSQL":
                checkLine(foundKind, line, @[RE_HYPERSONIC_SQL])
            elif kind == "ibmDb2":
                checkLine(foundKind, line, @[RE_IBM_DB2, RE_IBM_DB2_JAVA])
            elif kind == "miscrosoftAccess":
                checkLine(foundKind, line, @[RE_MS_ACCESS_JAVA])
            elif kind == "microsoftSQLServer":
                checkLine(foundKind, line, @[RE_MS_SQL])
            elif kind == "mongoDB":
                checkLine(foundKind, line, @[RE_MONGODB])
            elif kind == "oracle":
                checkLine(foundKind, line, @[RE_ORACLE])

            if foundKind:
                dbDetected[kind] = true
                return

        if foundKind:
            break

    strm.close()

# FIXME check that we don't fall into infinite loops with a symlink here
proc scanDirectory(directory: string, kind: string) =
    if dbDetected[kind]:
        return
    for filePath in walkDir(directory):
        if dbDetected[kind]:
            break
        if filePath.kind == pcFile:
            scanFile(filePath.path, kind)
            continue
        if filePath.kind == pcDir:
            scanDirectory(filePath.path, kind)
            continue

proc techStackGeneric*(self: Plugin, objs: seq[ChalkObj]):
    ChalkDict {.cdecl.} =

  result = ChalkDict()
  # for db in names:
  #   dbDetected[db] = false

  # for item in getContextDirectories():
  #   for db in names:
  #     trace("$\n## scanning for " & db)
  #     let fpath = expandFilename(item)
  #     if fpath.dirExists():
  #       scanDirectory(fpath, db)
  #       trace(" |- " & fpath & " " & $(dbDetected[db]))
  #     else:
  #       let (head, _) = splitPath(fPath)
  #       if head.dirExists():
  #         scanDirectory(head, db)
  #         trace(" |- " & head & " " & $(dbDetected[db]))
  # trace($(dbDetected))
  try:
    result["_INFERRED_TECH_STACKS"] = pack(techStackResult)
  except:
    dumpExOnDebug()
    trace("Testing packing")

proc loadtechStackGeneric*() =
  newPlugin("techStackGeneric", rtHostCallback = RunTimeHostCb(techStackGeneric))
