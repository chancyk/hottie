import std/[enumerate, strutils, strformat]


proc read(f: var File, offset: int, valueType: typedesc): valueType =
    let numBytes = sizeof(valueType)
    var buffer: array[sizeof(valueType), uint8]
    f.setFilePos(offset, relativeTo=fspSet)
    if f.readBytes(buffer, start=0, len=numBytes) != numBytes:
        raise newException(Exception, "Could not read value at offset: " & $offset)

    result = cast[valueType](buffer)


proc asHex(v: SomeInteger): string =
    let hex = v.toHex().strip(leading=true, chars={'0'})
    if len(hex) == 1:
        result = "0x0" & hex
    else:
        result = "0x" & hex


template check_signature() =
    if signature[0] != 'P' or signature[1] != 'E':
        raise newException(Exception, "Expected 'PE' as the first two bytes of the signature at offset: " & $sig_offset)
    else:
        when defined(progress):
            echo fmt"Signature [{sig_offset.asHex()}]: OK"
        else:
            discard


proc parse(filepath: string) =
    var pe_file = open(filepath, fmRead)
    let sig_offset  =  pe_file.read(0x3C,        uint32).int
    let signature   =  pe_file.read(sig_offset,  array[4, char])
    check_signature()


parse("./examples/test2.exe")
