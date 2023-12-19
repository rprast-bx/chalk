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

const FT_ANY = "*"
# rule identifiers by filetype
# FIXME change to hashset
# https://nim-lang.org/docs/sets.html
var ftRules = newTable[string, seq[string]]()
var excludeFtRules = newTable[string, seq[string]]()
# tech stack rules by each identifier
var tsRules = newTable[string, TechStackRule]()
# regex by name
var regexes = newTable[string, Regex]()
# category: [subcategory: seq[regex_name]]
var categories = newTable[string, TableRef[string, seq[string]]]()
# category: [subcategory: bool]
var detected = newTable[string, TableRef[string, bool]]()

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
# let head = 20


proc scanFile(filePath: string, category: string, subCategory: string) =
    var strm = newFileStream(filePath, fmRead)
    if isNil(strm):
        return

    let splFile = splitFile(filePath)
    let rule_names = categories[category][subCategory]
    var applicable_rules: seq[string]
    # applicable rules are eitehr rules that apply to all filetypes (FT_ANY)
    # or to the filetype matching the given extension
    for rule_name in categories[category][subCategory]:
        let tsRule = tsRules[rule_name]
        if contains(ftRules, FT_ANY) and contains(ftRules[FT_ANY], rule_name):
            var exclude = false
            if (tsRule.fileScope != nil and
                tsRule.fileScope.getExclude().isSome()):
                for ft in tsRule.fileScope.getExclude().get():
                    # if the filetype does not match the current extension proceed
                    if ft != splFile.ext and ft != "":
                        continue
                    # if we have a matching extension and a rule for that extenion,
                    # append the rule in the rule to be run
                    if contains(excludeFtRules, ft) and contains(excludeFtRules[ft], rule_name):
                        exclude = true
                        break
            if not exclude:
                applicable_rules.add(rule_name)
            continue

        if (tsRule.fileScope != nil and
            tsRule.fileScope.getFileTypes().isSome()):
            for ft in tsRule.fileScope.getFileTypes().get():
                # if the filetype does not match the current extension proceed
                if ft != splFile.ext and ft != "":
                    continue
                # if we have a matching extension and a rule for that extenion,
                # append the rule in the rule to be run
                if contains(ftRules, ft) and contains(ftRules[ft], rule_name):
                    applicable_rules.add(rule_name)
                    break

    # if filePath == "/home/nettrino/projects/crashappsec/chalk/server/server/db/database.py":
    #     trace("$$$\n$$$\n$$$\n")
    #     trace($(applicable_rules))
    var line = ""
    var i = 0
    while strm.readLine(line):
        i += 1
        if detected[category][subCategory]:
            break

        for rule_name in applicable_rules:
            let tsRule = tsRules[rule_name]
            if (tsRule.fileScope != nil and
                tsRule.fileScope.getHead().isSome() and
                tsRule.fileScope.getHead().get() < i):
                break

            if find(line, regexes[rule_name]) != -1:
                trace("Found match for regex " & rule_name & " in line " & $(line))
                detected[category][subCategory] = true
                break

            # break
            # if kind == "mySQL":
            #     checkLine(foundKind, line, dbRegexDict[mySQL])
            # elif kind == "firebird":
            #     checkLine(foundKind, line, @[RE_FIREBIRD_PYTHON, RE_FIREBIRD_GENERIC])
            # elif kind == "hypersonicSQL":
            #     checkLine(foundKind, line, @[RE_HYPERSONIC_SQL])
            # elif kind == "ibmDb2":
            #     checkLine(foundKind, line, @[RE_IBM_DB2, RE_IBM_DB2_JAVA])
            # elif kind == "miscrosoftAccess":
            #     checkLine(foundKind, line, @[RE_MS_ACCESS_JAVA])
            # elif kind == "microsoftSQLServer":
            #     checkLine(foundKind, line, @[RE_MS_SQL])
            # elif kind == "mongoDB":
            #     checkLine(foundKind, line, @[RE_MONGODB])
            # elif kind == "oracle":
            #     checkLine(foundKind, line, @[RE_ORACLE])

    strm.close()

# FIXME check that we don't fall into infinite loops with a symlink here
proc scanDirectory(directory: string, category: string, subCategory: string) =
    if detected[category][subCategory]:
        return
    for filePath in walkDir(directory):
        if detected[category][subCategory]:
            break
        if filePath.kind == pcFile:
            scanFile(filePath.path, category, subCategory)
            continue
        if filePath.kind == pcDir:
            scanDirectory(filePath.path, category, subCategory)
            continue

proc techStackGeneric*(self: Plugin, objs: seq[ChalkObj]):
    ChalkDict {.cdecl.} =

  result = ChalkDict()

  for category, subcategories in categories:
    for subcategory, _ in subcategories:
        # re-initialize to false again
        # XXX check the diff between load time and invocation state
        # does this need to be re-set upon every invocation here?
        detected[category][subCategory] = false
        for item in getContextDirectories():
            let fpath = expandFilename(item)
            if fpath.dirExists():
                scanDirectory(fpath, category, subCategory)
            else:
                let (head, _) = splitPath(fPath)
                if head.dirExists():
                    scanDirectory(head, category, subCategory)
                    trace(" |- " & head & " " & category & " " & subCategory & " " & $(detected[category][subCategory]))
  try:
    result["_INFERRED_TECH_STACKS"] = pack[TableRef[string,TableRef[string,bool]]](detected)
  except:
    echo getStackTrace()
    dumpExOnDebug()
    trace("Testing packing")

proc loadtechStackGeneric*() =
  for key, val in chalkConfig.techStackRules:
    tsRules[key] = val
    regexes[key] = re(val.getRegex())
    let category = val.getCategory()
    let subCategory = val.getSubcategory()
    if contains(categories, category):
        if contains(categories[category], subCategory):
            categories[category][subCategory].add(key)
        else:
            categories[category][subCategory] = @[key]
    else:
        categories[category] = newTable[string, seq[string]]()
        categories[category][subCategory] = @[key]
        detected[category] = newTable[string, bool]()
        detected[category][subCategory] = false
    if val.fileScope != nil:
        let filetypes = val.fileScope.getFileTypes()
        if filetypes.isSome():
            for ft in filetypes.get():
                if contains(ftRules, ft):
                    ftRules[ft].add(key)
                else:
                    ftRules[ft] = @[key]
        else:
            # we only have exclude rules therefore we match by default
            # XXX move to a tempalate for looking things up and adding if
            # they don't exist
            if contains(ftRules, FT_ANY):
                ftRules[FT_ANY].add(key)
            else:
                ftRules[FT_ANY] = @[key]
            let excludeFiletypes = val.fileScope.getExclude()
            if excludeFiletypes.isSome():
                for ft in excludeFiletypes.get():
                    if contains(excludeFtRules, ft):
                        excludeFtRules[ft].add(key)
                    else:
                        excludeFtRules[ft] = @[key]
    else:
        if contains(ftRules, FT_ANY):
            ftRules[FT_ANY].add(key)
        else:
            ftRules[FT_ANY] = @[key]
  newPlugin("techStackGeneric", rtHostCallback = RunTimeHostCb(techStackGeneric))
