## Handle JAR, WAR and other ZIP-based formats.  Works fine w/ JAR
## signing, because it only signs what's in the manifest.
##
## :Author: John Viega (john@crashoverride.com)
## :Copyright: 2023, Crash Override, Inc.

import zippy/ziparchives_v1, streams, nimSHA2, tables, strutils, options, os,
       std/algorithm, std/tempfiles, ../config, ../chalkjson, ../plugins

const zipChalkFile = ".chalk.json"

type
  CodecZip = ref object of Codec
  ZipCache = ref object of RootObj
    onDisk:        ZipArchive
    embeddedChalk: Box
    tmpDir:        string

method cleanup*(self: CodecZip, obj: ChalkObj) =
  let cache = ZipCache(obj.cache)

  if cache.tmpDir != "":
    removeDir(cache.tmpDir)

var zipDir: string

proc postprocessContext(collectionCtx: CollectionCtx) =
  let
    origD = joinPath(zipDir, "contents") & "/"
    l     = len(origD)

  # Remove the temporary directory from the start of any
  # ARTIFACT_PATH fields and UNCHALKED items
  for mark in collectionCtx.allChalks:
    if "ARTIFACT_PATH" in mark.collectedData:
      let path = unpack[string](mark.collectedData["ARTIFACT_PATH"])
      if path.startsWith(origD):
        mark.collectedData["ARTIFACT_PATH"] = pack(path[l .. ^1])

  var newUnmarked: seq[string] = @[]
  for item in collectionCtx.unmarked:
    if item.startsWith(origD):
      newUnmarked.add(item[l .. ^1])
    else:
      newUnmarked.add(item)
  collectionCtx.unmarked = newUnmarked

proc hashZip(toHash: ZipArchive): string =
  var sha = initSHA[SHA256]()
  var keys: seq[string]

  for k, v in toHash.contents:
    if v.kind == ekFile:
      keys.add(k)

  keys.sort()

  for item in keys:
    sha.update($(len(item)))
    sha.update(item)
    let v = toHash.contents[item]
    sha.update($(len(v.contents)))
    sha.update(v.contents)

  result = hashFmt($(sha.final))

proc hashExtractedZip(dir: string): string =
  let toHash = ZipArchive()

  toHash.addDir(dir & "/")

  return toHash.hashZip()

method scan*(self:   CodecZip,
             stream: FileStream,
             loc:    string): Option[ChalkObj] =

  var
    ext = loc.splitFile().ext.strip()
    extractCtx: CollectionCtx

  if not ext.startsWith(".") or ext[1..^1] notin chalkConfig.getZipExtensions():
    return none(ChalkObj)

  let
    tmpDir   = createTempDir(tmpFilePrefix, tmpFileSuffix)
    chalk    = newChalk(stream, loc)
    cache    = ZipCache()
    origD    = tmpDir.joinPath("contents")
    hashD    = tmpDir.joinPath("hash")
    subscans = chalkConfig.getChalkContainedItems()

  chalk.cache   = cache
  cache.onDisk  = ZipArchive()
  cache.tmpDir  = tmpDir

  try:
    stream.setPosition(0)
    cache.onDisk.open(stream)
    info(chalk.fullPath & ": temporarily extracting into " & tmpDir)
    zipDir = tmpDir
    cache.onDisk.extractAll(origD)
    cache.onDisk.extractAll(hashD)

    # Even if subscans are off, we do this delete for the purposes of hashing.
    if not chalkConfig.getChalkDebug():  toggleLoggingEnabled()
    discard runChalkSubScan(hashD, "delete")
    if not chalkConfig.getChalkDebug():  toggleLoggingEnabled()

    if zipChalkFile in cache.onDisk.contents:
      removeFile(joinPath(hashD, zipChalkFile))
      let contents = cache.onDisk.contents[zipChalkFile].contents
      if contents.contains(magicUTF8):
        let
          s           = newStringStream(contents)
        chalk.extract = s.extractOneChalkJson(chalk.fullpath)
        chalk.marked  = true
      else:
        chalk.marked  = false

    chalk.cachedPreHash = hashExtractedZip(hashD)

    if subscans:
      extractCtx = runChalkSubScan(origD, "extract")
      if extractCtx.report.kind == MkSeq:
        if len(unpack[seq[Box]](extractCtx.report)) != 0:
          if chalk.extract == nil:
            warn(chalk.fullPath & ": contains chalked contents, but is not " &
                 "itself chalked.")
            chalk.extract = ChalkDict()
          chalk.extract["EMBEDDED_CHALK"] = extractCtx.report
      if getCommandName() != "extract":
        let collectionCtx = runChalkSubScan(origD, getCommandName(),
                                            postProcessContext)

        # Update the internal accounting for the sake of the post-op hash
        for k, v in cache.onDisk.contents:
          let tmpPath = os.joinPath(origD, k)
          if not tmpPath.fileExists():
            continue

          var newv = v
          let
            f = open(tmpPath, fmRead)
            c = f.readAll()
          f.close()
          newv.contents             = c
          cache.onDisk.contents[k]  = newV
        cache.embeddedChalk = collectionCtx.report

    return some(chalk)
  except:
    error(loc & ": " & getCurrentExceptionMsg())
    dumpExOnDebug()
    return some(chalk)

proc doWrite(self: CodecZip, chalk: ChalkObj, encoded: Option[string],
             virtual: bool) =
  let
    cache     = ZipCache(chalk.cache)
    chalkFile = joinPath(cache.tmpDir, "contents", zipChalkFile)

  var dirToUse: string

  chalk.closeFileStream()
  try:
    if encoded.isSome():
      let f = open(chalkfile, fmWrite)
      f.write(encoded.get())
      f.close()
      dirToUse = joinPath(cache.tmpDir, "contents")
    else:
      dirToUse = joinPath(cache.tmpDir, "hash")

    let newArchive = ZipArchive()
    newArchive.addDir(dirToUse & "/")
    if not virtual:
      newArchive.writeZipArchive(chalk.fullPath)
    chalk.cachedHash = newArchive.hashZip()

  except:
    error(chalk.fullPath & ": " & getCurrentExceptionMsg())
    dumpExOnDebug()

method handleWrite*(self: CodecZip, chalk: ChalkObj, encoded: Option[string]) =
  self.doWrite(chalk, encoded, virtual = false)

method getEndingHash*(self: CodecZip, chalk: ChalkObj): Option[string] =
  if chalk.cachedHash == "":
    # When true, --virtual was passed, so we skipped where we calculate
    # the hash post-write. Theoretically, the hash should be the same as
    # the unchalked hash, but there could be chalked files in there, so
    # we calculate by running our hashZip() function on the extracted
    # directory where we touched nothing.
    let
      cache = ZipCache(chalk.cache)
      path  = cache.tmpDir.joinPath("contents") & "/"

    chalk.cachedHash = hashExtractedZip(path)

  return some(chalk.cachedHash)

method getChalkInfo*(self: CodecZip, obj: ChalkObj): ChalkDict =
  let cache = ZipCache(obj.cache)
  result    = ChalkDict()

  if chalkConfig.getChalkContainedItems() and cache.embeddedChalk.kind != MkObj:
    result["EMBEDDED_CHALK"]  = cache.embeddedChalk
    result["EMBEDDED_TMPDIR"] = pack(cache.tmpDir)

  let extension = obj.fullPath.splitFile().ext.toLowerAscii()

  result["ARTIFACT_TYPE"] = case extension
                            of ".jar": artTypeJAR
                            of ".war": artTypeWAR
                            of ".ear": artTypeEAR
                            else:      artTypeZip

method getPostChalkInfo*(self: CodecZip, obj: ChalkObj, ins: bool): ChalkDict =
  result        = ChalkDict()
  let extension = obj.fullPath.splitFile().ext.toLowerAscii()

  result["_OP_ARTIFACT_TYPE"] = case extension
                            of ".jar": artTypeJAR
                            of ".war": artTypeWAR
                            of ".ear": artTypeEAR
                            else:      artTypeZip

registerPlugin("zip", CodecZip())
