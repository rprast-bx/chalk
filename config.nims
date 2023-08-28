import strutils, os

switch("d", "nimPreviewHashRef")
switch("d", "ssl")
switch("d", "useOpenSSL3")
# This will end up yielding lto warnings. Uncomment if you want to load in gdb
#switch("debugger", "native")


when (NimMajor, NimMinor) < (1, 7):
  # Locklevels never worked and are gone but older versions will complain.
  switch("warning", "LockLevel:off")
when (NimMajor, NimMinor, NimPatch) >= (1, 6, 12):
  # Someone made a move to deprecate, but they're undoing it.
  switch("warning", "BareExcept:off")

# Always take the release build unless -d:debug is explicitly passed.
when not defined(debug):
    switch("d", "release")
    switch("opt", "speed")

if defined(macosx):
  # -d:arch=amd64 will allow you to specifically cross-compile to intel.
  # The .strdefine. pragma sets the variable from the -d: flag w/ the same
  # name, overriding the value of the const.
  const arch {.strdefine.} = "detect"

  var
    targetArch = arch
    targetStr  = ""

  if arch == "detect":
    # On an x86 mac, the proc_translated OID doesn't exist. So if this
    # returns either 0 or 1, we know we're running on an arm. Right now,
    # nim will always use rosetta, so should always give us a '1', but
    # that might change in the future.
    let sysctlOut = staticExec("sysctl -n sysctl.proc_translated")

    if sysctlOut in ["0", "1"]:
      targetArch = "arm64"
    else:
      targetArch = "amd64"
  else:
    echo "Override: arch = " & arch

  if targetArch == "arm64":
    targetStr = "arm64-apple-macos11"
  elif targetArch == "amd64":
    targetStr = "x86_64-apple-macos11"
  else:
    echo "Invalid target architecture for MacOs: " & arch

  switch("cpu", targetArch)
  switch("passc", "-flto -w -target " & targetStr)
  switch("passl", "-flto -w -target " & targetStr &
        "-Wl,-object_path_lto,lto.o")

  let
     libs   = ["ssl", "crypto"]
     libDir = staticRead("/tmp/con4m-build-dir").strip() &
       "/deps/macos/" & targetArch & "/"

  for item in libs:
    let libFile = "lib" & item & ".a"
    switch("passL", libDir & libFile)
    switch("dynlibOverride", item)

elif defined(linux):
  exec "bin/ensure-static"
  let
    ## Specify libs to be statically linked here. They must appear in the order
    ## they should be on the link line.
    libs     = ["pcre", "ssl", "crypto"]
    depsDir  = getCurrentDir() & "/deps/" & hostCPU & "/"
    libDir   = depsDir & "lib/"
    muslPath = depsDir & "usr/musl/bin/musl-gcc"
  switch("passl", "-static")
  switch("gcc.exe", muslPath)
  switch("gcc.linkerexe", muslPath)

  for item in libs:
    let libFile = "lib" & item & ".a"
    switch("passL", libDir & libFile)
    switch("dynlibOverride", item)

discard staticExec("if [ -f /tmp/con4m-build-dir ] ; " &
                   "then rm /tmp/con4m-build-dir fi")
