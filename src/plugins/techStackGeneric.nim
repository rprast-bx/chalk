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

#
# Hypersonic SQL
#
let RE_HYPERSONIC_SQL* = re"(hsqldb|HyperSQL|org.hsqldb.jdbc)"

#
# IBM DB2
#
let RE_IBM_DB2* = re"\b(db2jcc|com\.ibm\.db2\.jdbc|(ibm_db|ibm_db_dbi))\b"
let RE_IBM_DB2_JAVA* = re"import\s+com.ibm.db2.jcc.DB2Driver"

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
                trace(filePath & ": found match for regex " & rule_name & " in line \n" & $(line))
                detected[category][subCategory] = true
                break
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
