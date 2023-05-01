## :Author: John Viega, Brandon Edwards
## :Copyright: 2023, Crash Override, Inc.

import tables, strutils, json, nimutils, options, os, osproc, streams,
       posix_utils, std/tempfiles, ../config, ../plugins, ../dockerfile, con4m

when (NimMajor, NimMinor) < (1, 7): {.warning[LockLevel]: off.}

type
  CodecDocker* = ref object of Codec
  DockerFileSection = ref object
    image:        string
    alias:        string
    entryPoint:   EntryPointInfo
    cmd:          CmdInfo
    shell:        ShellInfo
  InspectedImage = tuple[entryArgv: seq[string],
                         cmdArgv:   seq[string],
                         shellArgv: seq[string]]
  DockerInfoCache = ref object of RootObj
    context:                string
    dockerFilePath:         string
    dockerFileContents:     string
    additionalInstructions: string
    tags:                   seq[string]
    platform:               string
    labels:                 Con4mDict[string, string]
    execNoArgs:             seq[string]
    execWithArgs:           seq[string]
    tmpDockerFile:          string
    tmpChalkMark:           string
    tmpEntryPoint:          string
    inspectOut:             JSonNode
    relativeEntry:          string

proc extractArgv(json: string): seq[string] {.inline.} =
  for item in parseJson(json).getElems():
    result.add(item.getStr())

method usesFStream*(self: CodecDocker): bool = false

method noPreArtifactHash*(self: CodecDocker): bool = true
method autoArtifactPath*(self: Codec): bool        = false

# In chalk, this is supposed to represent the artifact hash of the
# unchalked artifact. For the moment, we're not calculating this, and
# we are using a random chalk ID.
method getArtifactHash*(self: CodecDocker, chalk: ChalkObj): string =
  return ""

method getChalkId*(self: CodecDocker, chalk: ChalkObj): string =
  var
    b      = secureRand[array[32, char]]()
    preRes = newStringOfCap(32)
  for ch in b: preRes.add(ch)
  return preRes.idFormat()

# This codec is hard-wired to the docker command at the moment.
method scan*(self: CodecDocker, stream: FileStream, loc: string):
       Option[ChalkObj] = none(ChalkObj)

method getHashAsOnDisk*(self: CodecDocker, chalk: ChalkObj): Option[string] =
  return none(string)

var dockerPathOpt: Option[string] = none(string)

proc findDockerPath*(): Option[string] =
  once:
    dockerPathOpt = chalkConfig.getDockerExe()
    if dockerPathOpt.isSome():
      let potential = resolvePath(dockerPathOpt.get())
      if fileExists(potential):
        dockerPathOpt = some(potential)
        return dockerPathOpt
    let (mydir, me) = getAppFileName().splitPath()
    for path in getEnv("PATH").split(":"):
      if me == "docker" and path == mydir: continue # Don't find ourself.

      let candidate = joinPath(path, "docker")
      if fileExists(candidate):
        dockerPathOpt = some(candidate)
        return dockerPathOpt
    dockerPathOpt = none(string)

  return dockerPathOpt

proc dockerInspectEntryAndCmd(imageName: string,
                              errors:    var seq[string]): InspectedImage =
  # `docker inspect imageName`
  #FIXME another thing: this probably needs to be aware of if docker sock
  # or context or docker config is specified to the original docker command!
  #FIXME also needs to return `Shell`

  # Implicit default, don't need to uncomment.
  #result = InspectedImage(entryArgv: @[], cmdArgv: @[], shellArgv: @[])

  if imageName == "scratch": return

  let
    cmd  = findDockerPath().get()
    json = execProcess(cmd, args = ["inspect", imageName], options = {})
    arr  = json.parseJson().getElems()

  if len(arr) == 0: return

  if hasKey(arr[0], "ContainerConfig"):
    let containerConfig = arr[0]["ContainerConfig"]
    if containerConfig.hasKey("Cmd"):
      for i, item in containerConfig["Cmd"].getElems():
        let s = item.getStr()
        if s.startsWith("#(nop)"):
          break
        result.shellArgv.add(s)
  if hasKey(arr[0], "Config"):
    let config = arr[0]["Config"]
    if hasKey(config, "Entrypoint"):
      let items = config["Entrypoint"].getElems()
      for item in items:
        result.entryArgv.add(item.getStr())
    if hasKey(config, "Cmd"):
      let items = config["Cmd"]
      for item in items:
        result.cmdArgv.add(item.getStr())

proc dockerStringToArgv(cmd:   string,
                        shell: seq[string],
                        json:  bool): seq[string] =
  if json: return extractArgv(cmd)
  
  for value in shell: result.add(value)
  result.add(cmd)

method getChalkInfo*(self: CodecDocker, chalk: ChalkObj): ChalkDict =
  let cache = DockerInfoCache(chalk.cache)

  chalk.collectedData["DOCKER_TAGS"]     = pack(cache.tags)
  chalk.collectedData["ARTIFACT_PATH"]   = pack(cache.context)
  chalk.collectedData["DOCKERFILE_PATH"] = pack(cache.dockerFilePath) #TODO
  chalk.collectedData["DOCKER_FILE"]     = pack(cache.dockerFileContents)
  chalk.collectedData["DOCKER_CONTEXT"]  = pack(cache.context)
  chalk.collectedData["HASH"]            = pack("") # TMP KLUDGE

  if cache.platform != "":
    chalk.collectedData["DOCKER_PLATFORM"] = pack(cache.platform)

  if cache.labels.len() != 0:
    chalk.collectedData["DOCKER_LABELS"]   = pack(cache.labels)

method getPostChalkInfo*(self:  CodecDocker,
                         chalk: ChalkObj,
                         ins:   bool): ChalkDict =
  result  = ChalkDict()
  let
    cache = DockerInfoCache(chalk.cache)
    ascii = cache.inspectOut["Id"].getStr().split(":")[1].toLowerAscii()

  chalk.collectedData["_CURRENT_HASH"] = pack(ascii)

proc extractDockerInfo*(chalk:          ChalkObj,
                        flags:          OrderedTable[string, FlagSpec],
                        cmdlineContext: string): bool =
  ## This function evaluates the docker state, including environment
  ## variables, command-line flags and docker file.

  let
    env   = unpack[Con4mDict[string, string]](c4mEnvAll(@[]).get())
    cache = DockerInfoCache()

  var
    errors:         seq[string] = @[]
    rawArgs:        seq[string] = @[]
    fileArgs:       Table[string, string]
    labels        = Con4mDict[string, string]()

  chalk.cache = cache
  cache.labels = Con4mDict[string, string]()

  # Part 1: pull data from flags we care about.
  if "tag" in flags:
    let rawTags = unpack[seq[string]](flags["tag"].getValue())

    for tag in rawTags:
      if tag.contains(":"):
        cache.tags.add(tag)
      else:
        cache.tags.add(tag & ":latest")
  else:
    cache.tags = @["<none>:<none>"]

  chalk.fullPath = cache.tags[0]

  if "platform" in flags:
    cache.platform = (unpack[seq[string]](flags["platform"].getValue()))[0]
    if cache.platform != "linux/amd64":
      error("skipping unsupported platform: " & cache.platform)
      return false

  if "label" in flags:
    let rawLabels = unpack[seq[string]](flags["label"].getValue())
    for item in rawLabels:
      let arr = item.split("=")
      cache.labels[arr[0]] = arr[^1]

  if "build-arg" in flags:
    rawArgs = unpack[seq[string]](flags["build-arg"].getValue())

  for item in rawArgs:
    let n = item.find("=")
    if n == -1: continue
    fileArgs[item[0 ..< n]] = item[n+1 .. ^1]

  if cmdlineContext == "-":
    cache.context        = "/tmp/"
    cache.dockerFilePath = "-"
  else:
    let possibility = cmdLineContext.resolvePath()
    try:
      discard possibility.stat()
    except:
      error("Couldn't find local context. Remote is currently unsupported")
      return false
    cache.context = possibility

    if "file" in flags:
      cache.dockerFilePath = unpack[string](flags["file"].getValue())
      if cache.dockerFilePath == "-":
        #NOTE: this is distinct from `docker build -`,
        # this for cases like `docker build -f - .`
        cache.dockerFileContents = stdin.readAll()
        cache.dockerFilePath     = "-"
      else:
        if not cache.dockerFilePath.startsWith("/"):
          let unresolved       = cache.context.joinPath(cache.dockerFilePath)
          cache.dockerFilePath = unresolved.resolvePath()
    else:
      cache.dockerFilePath = cache.context.joinPath("Dockerfile")

  if cache.dockerFilePath == "-":
    cache.dockerFileContents = stdin.readAll()
  else:
    try:
      let s                    = newFileStream(cache.dockerFilePath, fmRead)
      cache.dockerFileContents = s.readAll()
      s.close()
    except:
      error(cache.dockerFilePath & ": docker build failed to read Dockerfile")
      return false

  # Part 3: Evaluate the docker file to the extent necessary.
  let stream        = newStringStream(cache.dockerFileContents)
  let (parse, cmds) = stream.parseAndEval(fileArgs, errors)
  for err in errors:
    error(chalk.fullPath & ": " & err)
  if len(errors) > 0:
    return false

  var
    section:    DockerFileSection
    curSection: DockerFileSection
    itemFrom:   FromInfo
    foundEntry: EntryPointInfo
    foundCmd:   CmdInfo
    foundShell: ShellInfo
    sectionTable = Table[string, DockerFileSection]()

  for item in cmds:
    if item of FromInfo:
      if section != nil:
        if len(section.alias) > 0:
          sectionTable[section.alias] = section
        else:
          # This is a leaf node section, it doesn't resolve to any tag name
          #TODO insert/chalk this layer in resulting Dockerfile prime
          error("skipping unreferenced discrete section in Dockerfile")
          discard
      section = DockerFileSection()
      itemFrom = FromInfo(item)
      section.image = parse.evalOrReturnEmptyString(itemFrom.image, errors)
      if itemFrom.tag.isSome():
        section.image &= ":" &
                 parse.evalSubstitutions(itemFrom.tag.get(), errors)
      section.alias = parse.evalOrReturnEmptyString(itemFrom.asArg, errors)
    elif item of EntryPointInfo:
      section.entryPoint = EntryPointInfo(item)
    elif item of CmdInfo:
      section.cmd = CmdInfo(item)
    elif item of ShellInfo:
      section.shell = ShellInfo(item)
    elif item of LabelInfo:
      for k, v in LabelInfo(item).labels:
        labels[k] = v
    # TODO: when we support CopyInfo, we need to add a case for it here
    # to save the source location as a hint for where to look for git info

  # might have had errors walking the Dockerfile commands
  if len(errors) > 0:
      return false

  # Command line flags replace what's in the docker file if there's a key
  # collision.
  for k, v in labels:
    if k notin cache.labels:
      cache.labels[k] = v

  # walk the sections from the most-recently-defined section.
  curSection = section
  while true:
    if foundCmd == nil:
      foundCmd = curSection.cmd
    if foundEntry == nil:
      foundEntry = curSection.entryPoint
    if foundShell == nil:
      foundShell = curSection.shell
    if curSection.image notin sectionTable:
      break
    curSection = sectionTable[curSection.image]

  var
    entryArgv:             seq[string]
    cmdArgv:               seq[string]
    shellArgv:             seq[string]
    inspected:             InspectedImage
    containerExecNoArgs:   seq[string]
    containerExecWithArgs: seq[string]

  if foundShell != nil:
    # shell is required to be specified in JSON, note that
    # here with ShellInfo the .json is a string not a bool :)
    shellArgv = extractArgv(foundShell.json)

  if foundEntry == nil or (foundEntry.json == false and foundShell == nil):
    # we need to inspect the ancestor image if:
    #   - we didn't find an entrypoint, as we need to know if there is one
    #     and if there's not, then we need to default to cmd, which we also
    #     might not have
    #   - we found the entrypoint but in shell-form and we didn't find a shell
    # if we don't have cmd, we should also populate that from inspect results
    inspected       = dockerInspectEntryAndCmd(curSection.image, errors)
    if len(errors) > 0:
      return false
    if foundEntry == nil:
      # we don't have entrypoint, so use the one from inspect, which might also
      # be nil but that's ok
      entryArgv = inspected.entryArgv
      if foundShell == nil:
        shellArgv = inspected.shellArgv
      # This dockerfile hasn't defined its own entrypoint, so we need
      # to honor the cmd if it is defined in the ancestor.
      if foundCmd == nil:
        cmdArgv = inspected.cmdArgv
      else:
        cmdArgv = dockerStringToArgv(foundCmd.contents,shellArgv,foundCmd.json)
    else:
      # we have an entry point, but it's not json and we didn't find shell
      shellArgv = inspected.shellArgv
      entryArgv = dockerStringToArgv(foundEntry.contents, shellArgv, false)
  else:
    # we had found entrypoint, and if it's not json we also have shell
    entryArgv = dockerStringToArgv(foundEntry.contents,
                                   shellArgv,
                                   foundEntry.json)
    if foundCmd != nil:
      # fun fact: from the docs you would think this should also
      # check that foundEntry.json == true, because entrypoints defined
      # in shellform supposedly discard cmd.. except that behavior is a
      # byproduct of `/bin/sh -c`, which treats the next argv entry as
      # the only command to execute.
      if foundShell == nil and not foundCmd.json:
        inspected = dockerInspectEntryAndCmd(curSection.image, errors)
        if len(errors) > 0:
          return false
        shellArgv = inspected.shellArgv
      cmdArgv = dockerStringToArgv(foundCmd.contents, shellArgv, foundCmd.json)

  if len(entryArgv) == 0:
    if len(cmdArgv) == 0:
      # TODO this should be configurable: if we don't have an entrypoint
      # and we don't have a cmd, if the user still wants us to embed an
      # entrypoint we can. Once we have a config option and thought about
      # what default should be then resume here to implement
      error("skipping currently unsupported case of !entrypoint && !cmd")
      return false

    # If cmd is specified in exec form, and the first item doesn't
    # have an explicitly defined /path/to/file, then we should be sure
    # that, if we wrap the entry point, we can find the command at
    # build time.  Sure, they might come in and slam the path, but if
    # they do something crazy like that, we'll just fail and re-build
    # the container without chalking.
    if cmdArgv[0][0] != '/':
      cache.relativeEntry = cmdArgv[0].split(" ")[0]

    cache.execNoArgs   = cmdArgv
    cache.execWithArgs = @[]
  else:
    cache.execNoArgs   = entryArgv & cmdArgv
    cache.execWithArgs = entryArgv

  stream.close()
  return true

proc writeChalkMark*(chalk: ChalkObj, mark: string) =
  var
    cache     = DockerInfoCache(chalk.cache)
    (f, path) = createTempFile(tmpFilePrefix, tmpFileSuffix, cache.context)
    ctx       = newFileStream(f)

  try:
    ctx.writeLine(mark)
    ctx.close()
    cache.tmpChalkMark = path
    cache.additionalInstructions = "COPY " & path.splitPath().tail & " /chalk.json\n"
  finally:
    if ctx != nil:
      try:
        ctx.close()
      except:
        removeFile(path)
        error("Could not write chalk mark (no permission)")
        raise

const
  hostDefault = "host_report_other_base"
  artDefault  = "artifact_report_extract_base"

proc profileToString(name: string): string =
  if name in ["", hostDefault, artDefault]: return ""

  result      = "profile " & name & " {\n"
  let profile = chalkConfig.profiles[name]

  for k, obj in profile.keys:
    let
      scope  = obj.getAttrScope()
      report = get[bool](scope, "report")
      order  = getOpt[int](scope, "order")

    result &= "  key." & k & ".report = " & $(report) & "\n"
    if order.isSome():
      result &= "  key." & k & ".order = " & $(order.get()) & "\n"

  result &= "}\n\n"

proc sinkConfToString(name: string): string =
  result     = "sink_config " & name & " {\n  filters: ["
  var frepr  = seq[string](@[])
  let
    config   = chalkConfig.sinkConfs[name]
    scope    = config.getAttrScope()

  for item in config.filters: frepr.add("\"" & item & "\"")

  result &= frepr.join(", ") & "]\n"
  result &= "  sink: \"" & config.sink & "\"\n"

  # copy out the config-specific variables.
  for k, v in scope.contents:
    if k in ["enabled", "filters", "loaded", "sink"]: continue
    if v.isA(AttrScope): continue
    let val = getOpt[string](scope, k).getOrElse("")
    result &= "  " & k & ": \"" & val & "\"\n"

  result &= "}\n\n"

proc prepEntryPointBinary*(chalk, selfChalk: ChalkObj) =
  # TODO: this and the template need to be massaged to work, and
  # we need to write the code to actually handle the 'entrypoint' command.
  # Similarly, need to have a flag to skip arg parsing altogether.

  var newCfg     = entryPtTemplate
  let
    cache        = DockerInfoCache(chalk.cache)
    noArgs       = $(%* cache.execNoArgs)
    withArgs     = $(%* cache.execWithArgs)
    dockerCfg    = chalkConfig.dockerConfig
    hostProfName = dockerCfg.getEntrypointHostReportProfile().get(hostDefault)
    artProfName  = dockerCfg.getEntrypointHostReportProfile().get(artDefault)
    sinkName     = dockerCfg.getEntrypointReportSink()
    hostProfile  = hostProfName.profileToString()
    artProfile   = artProfName.profileToString()
    sinkSpec     = sinkName.sinkConfToString()

  newCfg = newCfg.replace("$$$CHALKFILE$$$", dockerCfg.getChalkFileLocation())
  newCfg = newCfg.replace("$$$ENTRYPOINT$$$", "???")
  newCfg = newCfg.replace("$$$SINKNAME$$$", sinkName)
  newCfg = newCfg.replace("$$$HOSTPROFILE$$$", hostProfile)
  newCfg = newCfg.replace("$$$ARTIFACTPROFILE$$$", artProfile)
  newCfg = newCfg.replace("$$$ARTPROFILEREF$$$", hostProfName)
  newCfg = newCfg.replace("$$$HOSTPROFILEREF$$$", artProfName)
  newCfg = newCfg.replace("$$$CONTAINEREXECNOARGS$$$", noArgs)
  newCfg = newCfg.replace("$$$CONTAINEREXECWITHARGS$$$", withArgs)
  newCfg = newCfg.replace("$$$SINKCONFIG$$$", sinkSpec)

  selfChalk.collectedData["$CHALK_CONFIG"] = pack(newCfg)

proc writeEntryPointBinary*(chalk, selfChalk: ChalkObj, toWrite: string) =
  let
    cache     = DockerInfoCache(chalk.cache)
    (f, path) = createTempFile(tmpFilePrefix, tmpFileSuffix, cache.context)
    codec     = selfChalk.myCodec

  f.close() # Just needed the name...
  trace("Writing new entrypoint binary to: " & path)

  # If we cannot write to the file system, we should write the chalk
  # mark to a label (TODO)
  try:
    selfChalk.postHash  = codec.handleWrite(selfChalk, some(toWrite), false)
    info("New entrypoint binary written to: " & path)

    # If we saw a relative path for the entry point binary, we should make sure
    # that we're going to find it in the container, so that we don't silently
    # fail when running as an entry point.  If the 'which' command fails, the
    # build should fail, and the container should re-build without us.
    if cache.relativeEntry != "":
      cache.additionalInstructions &= "RUN which " & cache.relativeEntry & "\n"
      
    # Here's the rationale around the random string:
    # 1. Unlikely, but two builds could use the same context dir concurrently
    # 2. Docker caches layers from RUN commands, and possibly from COPY,
    #    so to ensure the binary is treated uniquely we use a random name
    #    (we could pass --no-cache to Docker, but this could have other
    #     side-effects we don't want, and also doesn't address #1)
    # 3. We don't copy directly to /chalk in container because there might
    #    already be a /chalk binary there, and we need to consume its contents
    #    if it's there
    if chalkConfig.getRecursive():
      cache.additionalInstructions &= "RUN /" & path & " insert\n"
      cache.additionalInstructions &= "COPY " & path & " /" & path & "\n"      
    else:
      cache.additionalInstructions &= "COPY " & path & " /chalk\n"
    cache.additionalInstructions &= "ENTRYPOINT [\"/chalk\"]\n"
  except:
    error("Writing entrypoint binary failed: " & getCurrentExceptionMsg())
    dumpExOnDebug()
    raise

  try:
    discard cache.context.joinPath(".dockerignore").stat()
    # really not sure the best approach here, they all feel racy
    # do we just write an exclusion (which begins with '!') in
    # the form of !{tmpFilePrefix} ? or !{generated-tmp-path}
    # but if we have concurrent accesses ... well it could get ugly
  except:
    discard

proc buildContainer*(chalk:  ChalkObj,
                     wrap:   bool,
                     flags:  OrderedTable[string, FlagSpec],
                     inargs: seq[string]): bool =
  # Going to reparse the original argument to lift out any -f/--file
  # but otherwise will pass through all arguments.
  let
    cache     = DockerInfoCache(chalk.cache)
    fullFile  = cache.dockerFileContents & "\n" & cache.additionalInstructions
    (f, path) = createTempFile(tmpFilePrefix, tmpFilesuffix, cache.context)
    reparse   = newSpecObj(maxArgs = high(int), unknownFlagsOk = true,
                           noColon = true)
    cmd       = findDockerPath().get()

  cache.tmpDockerFile = path
  f.write(fullFile)
  f.close()
  reparse.addFlagWithArg("file", ["f"], true, optArg = true)

  var args = reparse.parse(inargs).args[""]
  
  args = args[0 ..< ^1] & @["--file=" & path, args[^1]]

  let
    subp = startProcess(cmd, args = args, options = {poParentStreams})
    code = subp.waitForExit()

  if code != 0: return false
  
  let
    res   = execProcess(cmd, args = @["inspect", cache.tags[0]], options = {})
    items = res.parseJson().getElems()

  if len(items) == 0: return false
  cache.inspectOut = items[0]
  return true

proc cleanupTmpFiles*(chalk: ChalkObj) =
  let cache = DockerInfoCache(chalk.cache)

  if cache.tmpDockerFile != "": removeFile(cache.tmpDockerFile)
  if cache.tmpChalkMark  != "": removeFile(cache.tmpChalkMark)
  if cache.tmpEntryPoint != "": removeFile(cache.tmpEntryPoint)

  
# This stuff needs to get done somewhere...
#
# when we execute docker build (using user's original commandline):
#   - change/set -f/--file to /tmp/chalkdockerfileRandomString
#
# when chalk is executing from the RUN statement above, it will be in-container
# during build-time, it needs to :
#   - check for existing chalk at /chalk: consume that chalk metadata
#   - write to /chalk itself + any metadata consumed
#   - remove /chalkBinaryRandomString
#
# When we exec in container fo real!
#   - fork() --> child reports home (not parent!), with some timeout (< 1sec)
#   - in parent (pid 1 in theory):
#       - if len(argv) > 1:
#         exec(containerExecWithArgs + argv[1:^1])
#       - else
#         exec(containerExecNoArgs)
# TODO: not handling virtual chalking.
# TODO: report not being able to chalk.
# TODO: add chalk.postHash
# TODO: remove chalk and chalk.json from the context if they exist.
# TODO: report the image ID as the post-hash (needs appropriate formatting)

registerPlugin("docker", CodecDocker())