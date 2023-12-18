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

# rule identifiers by filetype
var ftRules = newTable[string, seq[string]]()
# tech stack rules by each identifier
var tsRules = newTable[string, TechStackRule]()
# regex by name
var regexes = newTable[string, Regex]()
# category: [subcategory: name]
var categories = newTable[string, TableRef[string, string]]()

var detected = initTable[string, bool]()

const
    database = "database"
    webServer = "webServer"
    protocol = "protocol"
    language = "language"
    # db types
    firebird = "firebird"
    hypersonicSQL = "hypersonicSQL"
    ibmDb2 = "ibmDb2"
    microsoftAccess = "microsoftAccess"
    microsoftSQLServer = "microsoftSQLServer"
    mongoDB = "mongoDB"
    mySQL = "mySQL"
    oracle = "oracle"
    postgreSQL = "postgreSQL"
    sqlite = "sqlite"
    sysbase = "sysbase"
    # web server types
    apache = "apache"
    nginx = "nginx"
    iis = "iis"
    # protocol types
    ldap = "ldap"

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
    # firebird: @[RE_FIREBIRD_GENERIC, RE_FIREBIRD_PYTHON],
    sqlite: @[RE_SQLITE],
}.toTable()

let dbResultDict* = {
    mySQL: false,
    # firebird: false,
    sqlite: false,
}.newTable()

let techStackResult* = {
    database: dbResultDict,
}.newTable()

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

        if not detected[kind]:
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
                detected[kind] = true
                return

        if foundKind:
            break

    strm.close()

# FIXME check that we don't fall into infinite loops with a symlink here
proc scanDirectory(directory: string, kind: string) =
    if detected[kind]:
        return
    for filePath in walkDir(directory):
        if detected[kind]:
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

  for category, subcategories in categories:
    for subcategory, regex_name in subcategories:
        echo category, "_", subcategory, "_", regex_name
        detected[category & "_" & subcategory] = false

  # for item in getContextDirectories():
  #   for db in names:
  #     trace("$\n## scanning for " & db)
  #     let fpath = expandFilename(item)
  #     if fpath.dirExists():
  #       scanDirectory(fpath, db)
  #       trace(" |- " & fpath & " " & $(detected[db]))
  #     else:
  #       let (head, _) = splitPath(fPath)
  #       if head.dirExists():
  #         scanDirectory(head, db)
  #         trace(" |- " & head & " " & $(detected[db]))
  # trace($(detected))
  try:
    result["_INFERRED_TECH_STACKS"] = pack[TableRef[string,TableRef[string,bool]]](cast[TableRef[string,TableRef[string,bool]]](techStackResult))
  except:
    echo getStackTrace()
    dumpExOnDebug()
    trace("Testing packing")

proc loadtechStackGeneric*() =
  for key, val in chalkConfig.techStackRules:
    tsRules[key] = val
    regexes[key] = re(val.getRegex())
    echo "rule name = ", key
    let category = val.getCategory()
    if contains(categories, category):
        categories[category][val.getSubcategory()] = key
    else:
        categories[category] = newTable[string, string]()
        categories[category][val.getSubcategory()] = key
    if val.fileScope != nil:
        if val.fileScope.getHead().isSome():
            echo "head = ", val.fileScope.getHead().get()
            let filetypes = val.fileScope.getFileTypes()
            if filetypes.isSome():
                for ft in filetypes.get():
                    if contains(ftRules, ft):
                        ftRules[ft].add(key)
                    else:
                        ftRules[ft] = @[key]
    else:
        if contains(ftRules, "all"):
            ftRules["all"].add(key)
        else:
            ftRules["all"] = @[key]
  newPlugin("techStackGeneric", rtHostCallback = RunTimeHostCb(techStackGeneric))
