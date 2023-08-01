## Conceptually, this is where ALL information about the configuration
## state lives.  A lot of our calls for accessing configuration state
## are auto-generated by this file though, and in c4autoconf.nim).
##
## This module does also handle loading configurations, including
## built-in ones and external ones.
##
## It also captures some environmental bits used by other modules.
## For instance, we collect some information about the build
## environment here.
##
## :Author: John Viega (john@crashoverride.com)
## :Copyright: 2022, 2023, Crash Override, Inc.

import config, selfextract, con4mfuncs
import macros except error

# Since these are system keys, we are the only one able to write them,
# and it's easier to do it directly here than in the system plugin.
proc stashFlags(winner: ArgResult) =
  var flagStrs: seq[string] = @[]

  for key, value in winner.stringizeFlags():
    if value == "": flagStrs.add("--" & key)
    else:           flagStrs.add("--" & key & "=" & value)

  hostInfo["_OP_CMD_FLAGS"] = pack(flagStrs)

# TODO: static code to validate loaded specs.

proc getEmbeddedConfig(): string =
  result         = defaultConfig
  let extraction = getSelfExtraction()
  if extraction.isSome():
    let
      selfChalk = extraction.get()
    if selfChalk.extract != nil and selfChalk.extract.contains("$CHALK_CONFIG"):
      trace("Found embedded config file in self-chalk.")
      return unpack[string](selfChalk.extract["$CHALK_CONFIG"])
    else:
      if selfChalk.marked:
        trace("Found an embedded chalk mark, but it did not contain a config.")
      else:
        trace("No embedded chalk mark.")
      trace("Using the default user config.  See 'chalk dump' to view.")
  else:
    trace("Since this binary can't be marked, using the default config.")

proc findOptionalConf(state: ConfigState): Option[(string, FileStream)] =
  result = none((string, FileStream))
  let
    path     = unpack[seq[string]](state.attrLookup("config_path").get())
    filename = unpack[string](state.attrLookup("config_filename").get())
  for dir in path:
    let fname = resolvePath(dir.joinPath(filename))
    trace("Looking for config file at: " & fname)
    if fname.fileExists():
      info(fname & ": Found config file")
      try:
        return some((fname, newFileStream(fname)))
      except:
        error(fname & ": Could not read configuration file")
        dumpExOnDebug()
        break
    else:
        trace(fname & ": No configuration file found.")

proc loadLocalStructs*(state: ConfigState) =
  chalkConfig = state.attrs.loadChalkConfig()
  if chalkConfig.color.isSome(): setShowColors(chalkConfig.color.get())
  setLogLevel(chalkConfig.logLevel)
  for i in 0 ..< len(chalkConfig.configPath):
    chalkConfig.configPath[i] = chalkConfig.configPath[i].resolvePath()
  var c4errLevel =  if chalkConfig.con4mPinpoint: c4vShowLoc else: c4vBasic

  if chalkConfig.chalkDebug:
    c4errLevel = if c4errLevel == c4vBasic: c4vTrace else: c4vMax

  setCon4mVerbosity(c4errLevel)

proc handleCon4mErrors(err, tb: string): bool =
  if chalkConfig == nil or chalkConfig.chalkDebug or true:
    error(err & "\n" & tb)
  else:
    error(err)
  return true

proc handleOtherErrors(err, tb: string): bool =
  error(getMyAppPath().splitPath().tail & ": " & err)
  quit(1)

template cmdlineStashTry() =
  if cmdSpec == nil:
    if stack.getOptOptions.len() > 1:
      commandName = "not_supplied"
    elif not resFound:
      res         = getArgResult(stack)
      commandName = res.command
      cmdSpec     = res.parseCtx.finalCmd
      autoHelp    = res.getHelpStr()
      setArgs(res.args[commandName])
      res.stashFlags()
      resFound = true

template doRun() =
  try:
    discard run(stack)
    cmdlineStashTry()
  except:
    error("Could not load configuration files. exiting.")
    dumpExOnDebug()
    quit(1)

proc loadAllConfigs*() =
  var
    params:   seq[string] = commandLineParams()
    res:      ArgResult # Used across macros above.
    resFound: bool


  let
    toStream = newStringStream
    stack    = newConfigStack()

  case getMyAppPath().splitPath().tail
  of "docker":
    if "docker" notin params:
      if len(params) != 0 and params[0] == "chalk":
        params = params[1 .. ^1]
      else:
        params = @["docker"] & params
  else: discard

  con4mRuntime = stack

  stack.addSystemBuiltins().
      addCustomBuiltins(chalkCon4mBuiltins).
      setErrorHandler(handleCon4mErrors).
      addGetoptSpecLoad().
      addSpecLoad(chalkSpecName, toStream(chalkC42Spec), notEvenDefaults).
      addConfLoad(baseConfName, toStream(baseConfig), checkNone).
      addCallback(loadLocalStructs).
      addConfLoad(getoptConfName, toStream(getoptConfig), checkNone).
      setErrorHandler(handleOtherErrors).
      addStartGetOpts(printAutoHelp = false, args=params).
      addCallback(loadLocalStructs).
      setErrorHandler(handleCon4mErrors)
  doRun()

  stack.addConfLoad(ioConfName, toStream(ioConfig), notEvenDefaults).
      addConfLoad(dockerConfName, toStream(dockerConfig), checkNone)

  if chalkConfig.getLoadDefaultSigning():
    stack.addConfLoad(signConfName, toStream(signConfig), checkNone)

  let chalkOps = chalkConfig.getValidChalkCommandNames()
  if commandName in chalkOps or (commandName == "not_supplied" and
    chalkConfig.defaultCommand.getOrElse("") in chalkOps):
    stack.addConfLoad(sbomConfName, toStream(sbomConfig), checkNone)
    stack.addConfLoad(sastConfName, toStream(sastConfig), checkNone)

  stack.addCallback(loadLocalStructs)
  doRun()

  # Next, do self extraction, and get the embedded config.
  # The embedded config has already been validated.
  let configFile = getEmbeddedConfig()

  if chalkConfig.getLoadEmbeddedConfig():
    stack.addConfLoad("<<embedded config>>", toStream(configFile)).
          addCallback(loadLocalStructs)
    doRun()

  if chalkConfig.getLoadExternalConfig():
    let optConf = stack.configState.findOptionalConf()
    if optConf.isSome():
      let (fName, stream) = optConf.get()
      var embed = stream.readAll()
      stack.addConfLoad(fName, toStream(embed)).addCallback(loadLocalStructs)
      doRun()
      hostInfo["_OP_CONFIG"] = pack(configFile)

  if commandName == "not_supplied" and chalkConfig.defaultCommand.isSome():
    setErrorHandler(stack, handleOtherErrors)
    addFinalizeGetOpts(stack, printAutoHelp = false)
    addCallback(stack, loadLocalStructs)
    doRun()