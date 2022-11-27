import std/bitops, std/sugar, std/sequtils, std/algorithm
import common, strutils, winim

proc getThreadIds*(pid: int): seq[int] =
  var h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, DWORD(pid))
  if h != INVALID_HANDLE_VALUE:
    var te: THREADENTRY32
    te.dwSize = DWORD(sizeof(te))
    var valid = Thread32First(h, te.addr)
    while valid == 1:
      if te.th32OwnerProcessID == DWORD(pid):
        result.add te.th32ThreadID
      valid = Thread32Next(h, te.addr)

    CloseHandle(h)


proc getBaseAddresses*(pid: int): OrderedTableRef[uint64, string] =
  result = newOrderedTable[uint64, string]()
  var
    addresses = newTable[uint64, string]()
    h = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE or TH32CS_SNAPMODULE32, DWORD(pid))
  if h != INVALID_HANDLE_VALUE:
    var modEntry: MODULEENTRY32
    modEntry.dwSize = DWORD(sizeof(modEntry))
    var valid = Module32First(h, modEntry.addr)
    while valid == 1:
      let modEntryName = filter(modEntry.szModule, x => x > 0).map(x => chr(x)).join("")
      let address = cast[uint64](modEntry.modBaseAddr)
      addresses[address] = modEntryName
      valid = Module32Next(h, modEntry.addr)

    CloseHandle(h)

  for address in sorted(addresses.keys.toSeq):
    result[address] = addresses[address]


proc sample*(
  cpuHotAddresses: var CountTable[uint64],
  cpuHotStacks: var CountTable[string],
  externalHits: var CountTable[string],
  pid: int,
  threadIds: seq[int],
  dumpFile: DumpFile,
  stacks: bool,
  baseAddresses: OrderedTableRef[uint64, string],
  exeName: string
): bool =
  #for threadId in threadIds:
  block:
    let threadId = threadIds[0]
    var processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, pid.DWORD)
    var threadHandle = OpenThread(
      THREAD_ALL_ACCESS,
      false,
      threadId.DWORD
    )

    var context: CONTEXT
    context.ContextFlags = CONTEXT_ALL

    let hresult = SuspendThread(threadHandle).HRESULT
    if hresult == 0xffffffff:
        echo "Failed to suspend."
        return

    let prev_priority = GetThreadPriority(threadHandle)
    SetThreadPriority(threadHandle, THREAD_PRIORITY_TIME_CRITICAL)
    GetThreadContext(threadHandle, context.addr)
    SetThreadPriority(threadHandle, prev_priority)

    var stackTrace: string
    if stacks:
      var prevFun = ""
      block:
        var bytesRead: SIZE_T
        let startAddress = context.Rsp
        var i = 0
        let dl = dumpFile.frames.addressToDumpLine(context.Rip.uint64)
        prevFun = dl.text.split(" @ ")[0]
        stackTrace.add prevFun.split("__", 1)[0]
        stackTrace.add "<"
        while i < 10_000:
          var value: uint64
          ReadProcessMemory(
            hProcess = processHandle,
            lpBaseAddress = cast[LPCVOID](startAddress + i),
            lpBuffer = cast[LPCVOID](value.addr),
            nSize = 8,
            lpNumberOfBytesRead = bytesRead.addr)
          if bytesRead != 8:
            break
          let dl = dumpFile.frames.addressToDumpLine(value)
          if "stdlib_ioInit000" in dl.text or "NimMainModule" in dl.text:
            break
          if dl.text != "":
            let thisFun = dl.text.split(" @ ")[0]
            let canCall = prevFun in dumpFile.callGraph[thisFun]
            if canCall:
              if prevFun == thisFun:
                if not stackTrace.endsWith("*"):
                  stackTrace[^1] = '*'
              else:
                prevFun = thisFun
                stackTrace.add thisFun.split("__", 1)[0]
                stackTrace.add "<"
          i += 8

    ResumeThread(threadHandle)

    var
      module: string
      exeBaseAddress: uint64
    let address = context.Rip.uint64
    for baseAddress in baseAddresses.keys():
      # First time should miss, otherwise will be module == ""
      if address < baseAddress:
        break

      module = baseAddresses[baseAddress]
      if module == exeName:
        exeBaseAddress = baseAddress

    if module == exeName:
      echo address, " ", exeBaseAddress
      let imageBase = 0x140000000.uint64
      let relative = (address - exeBaseAddress) + imageBase
      cpuHotAddresses.inc(relative)
    else:
      externalHits.inc(module)

    if stacks:
      cpuHotStacks.inc(stackTrace)

    CloseHandle(threadHandle)
    CloseHandle(processHandle)

  return false
