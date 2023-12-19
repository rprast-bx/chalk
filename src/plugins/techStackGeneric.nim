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
import std/sets
import std/sequtils
import system
import ../config, ../plugin_api

const FT_ANY = "*"
var languages = newTable[string, string]()
# rule identifiers by filetype
var ftRules = newTable[string, HashSet[string]]()
# rules to be excluded from given filetypes
var excludeFtRules = newTable[string, HashSet[string]]()
# tech stack rules by each identifier
var tsRules = newTable[string, TechStackRule]()
# regex by name
var regexes = newTable[string, Regex]()
# category: [subcategory: seq[regex_name]]
var categories = newTable[string, TableRef[string, seq[string]]]()
# category: [subcategory: bool]
var detected = newTable[string, TableRef[string, bool]]()
# limits for what portion from the start of the file a rule must read into
var headLimits = newTable[string, int]()

var ruleFiletypes = newTable[string, seq[string]]()
var ruleExcludeFiletypes = newTable[string, seq[string]]()

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
            if contains(ruleExcludeFiletypes, rule_name):
                for ft in ruleExcludeFiletypes[rule_name]:
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

        if contains(ruleFiletypes, rule_name):
            for ft in ruleFiletypes[rule_name]:
                # if the filetype does not match the current extension proceed
                if ft != splFile.ext and ft != "":
                    continue
                # if we have a matching extension and a rule for that extenion,
                # append the rule in the rule to be run
                if contains(ftRules, ft) and contains(ftRules[ft], rule_name):
                    applicable_rules.add(rule_name)
                    break

    var line = ""
    var i = 0
    while strm.readLine(line):
        i += 1
        if detected[category][subCategory]:
            break

        for rule_name in applicable_rules:
            if headLimits[rule_name] < i:
                break

            if find(line, regexes[rule_name]) != -1:
                # trace(filePath & ": found match for regex " & rule_name & " in line \n" & $(line))
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

proc getLanguages(directory: string, langs: var HashSet[string]) =
    for filePath in walkDir(directory):
        if filePath.kind == pcFile:
            let splFile = splitFile(filePath.path)
            if splFile.ext == "":
                continue
            if not contains(languages, splFile.ext):
                continue
            langs.incl(languages[splFile.ext])
            continue
        if filePath.kind == pcDir:
            getLanguages(filePath.path, langs)
            continue

proc techStackGeneric*(self: Plugin, objs: seq[ChalkObj]):
    ChalkDict {.cdecl.} =

  result = ChalkDict()
  var final = newTable[string, seq[string]]()

  trace("Runtime detection of tech stacks")

  # FIXME break up into two functions
  trace("Detecting languages")
  var langs: HashSet[string]
  for item in getContextDirectories():
      let fpath = expandFilename(item)
      if fpath.dirExists():
          getLanguages(fpath, langs)
      else:
          let (head, _) = splitPath(fPath)
          if head.dirExists():
              getLanguages(head, langs)
  if len(langs) > 0:
    final["language"] = toSeq(langs)


  trace("Running scans of tech stack rules")
  var hasResults = false
  for category, subcategories in categories:
    for subcategory, _ in subcategories:
        # re-initialize to false again
        # XXX check the diff between load time and invocation state
        # does this need to be re-set upon every invocation here?
        detected[category][subCategory] = false
        for item in getContextDirectories():
            if detected[category][subCategory]:
                break
            let fpath = expandFilename(item)
            if fpath.dirExists():
                scanDirectory(fpath, category, subCategory)
            else:
                let (head, _) = splitPath(fPath)
                if head.dirExists():
                  scanDirectory(head, category, subCategory)
        if detected[category][subCategory]:
            hasResults = true

  if hasResults:
    for category, subcategories in categories:
        for subCategory, _ in subcategories:
            if not detected[category][subCategory]:
                continue
            if contains(final, category):
                final[category].add(subCategory)
            else:
                final[category] = @[subCategory]
  result["_INFERRED_TECH_STACKS"] = pack[TableRef[string, seq[string]]](final)

proc loadtechStackGeneric*() =
  for langName, val in chalkConfig.linguistLanguages:
    languages[val.getExtension()] = langName

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
        headLimits[key] = val.fileScope.getHead()
        let filetypes = val.fileScope.getFileTypes()
        if filetypes.isSome():
            let ftypes = filetypes.get()
            ruleFiletypes[key] = ftypes
            for ft in ftypes:
                if contains(ftRules, ft):
                    ftRules[ft].incl(key)
                else:
                    ftRules[ft] = toHashSet([key])
        else:
            # we only have exclude rules therefore we match by default
            # XXX move to a tempalate for looking things up and adding if
            # they don't exist
            if contains(ftRules, FT_ANY):
                ftRules[FT_ANY].incl(key)
            else:
                ftRules[FT_ANY] = toHashSet([key])
            let excludeFiletypes = val.fileScope.getExclude()
            if excludeFiletypes.isSome():
                let exclFtps = excludeFiletypes.get()
                ruleExcludeFiletypes[key] = exclFtps
                for ft in exclFtps:
                    if contains(excludeFtRules, ft):
                        excludeFtRules[ft].incl(key)
                    else:
                        excludeFtRules[ft] = toHashSet([key])
    else:
        # FIXME can I get the default somehow?
        headLimits[key] = 200
        if contains(ftRules, FT_ANY):
            ftRules[FT_ANY].incl(key)
        else:
            ftRules[FT_ANY] = toHashSet([key])
  newPlugin("techStackGeneric", rtHostCallback = RunTimeHostCb(techStackGeneric))
