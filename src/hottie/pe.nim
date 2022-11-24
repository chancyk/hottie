import std/[enumerate, strutils, strformat]


const
    MAGIC_ROM: uint16 = 0x107
    MAGIC_PE32: uint16 = 0x10b
    MAGIC_PE32_PLUS: uint16 = 0x20b


proc read(f: var File, offset: int, valueType: typedesc): valueType =
    let numBytes = sizeof(valueType)
    var buffer: array[sizeof(valueType), uint8]
    f.setFilePos(offset, relativeTo=fspSet)
    if f.readBytes(buffer, start=0, len=numBytes) != numBytes:
        raise newException(Exception, "Could not read value at offset: " & $offset)

    result = cast[valueType](buffer)


proc asHex(v: SomeInteger, padWidth = 4): string =
    let hex = v.toHex().strip(leading=true, chars={'0'}).toLowerAscii()
    let numPaddedZeroes = padWidth - len(hex)
    if numPaddedZeroes > 0:
        result = "0x" & "0".repeat(numPaddedZeroes) & hex
    else:
        result = "0x" & hex


proc compare(src: openArray[char], target: openArray[char]): bool =
    if len(src) == len(target):
        for i, c in enumerate(src):
            if target[i] != c:
                return false

    return true


template progress_err(label: string) =
    when defined(peprogress):
        echo label & " [ERR]: "


template progress_ok(label: string, value: untyped) =
    when defined(peprogress):
        echo label & " [OK]: " & $value


template check_signature(should_be: untyped) =
    let label = fmt"[{sig_offset.asHex()}] Signature"
    if compare(signature, should_be) == false:
        progress_err(label)
        raise newException(Exception, "Expected 'PE' as the first two bytes of the signature at offset: " & $sig_offset)
    else:
        progress_ok(label, signature.join(""))


template check_optional_header_size(body: untyped) =
    let label = fmt"[{optional_header_size_pos.asHex()}] Optional Header Size"
    if body:
        progress_err(label)
        raise newException(Exception, "The optional header size should be greater than zero for an executable.")
    else:
        progress_ok(label, optional_header_size)


template check_optional_header_magic(body: untyped) =
    let label = fmt"[{optional_header_pos.asHex()}] Optional Header Magic"
    if not (body):
        progress_err(label)
        raise newException(Exception, fmt"<{optional_header_magic.asHex()} is not a valid Optional Header magic value.")
    else:
        progress_ok(label, optional_header_magic.asHex(0))


proc pe_parse(filepath: string) =
    ## Parser to find the Relocation Directory within an Windows PE Image.
    ##
    ## See for additional details: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
    var pe_file = open(filepath, fmRead)

    let sig_offset = pe_file.read(60, uint32).int    # Signature offset field is at fixed position of 0x3C bytes.
    let coff_header = sig_offset + 4                 # COFF Header immediately follows the 4 byte signature in Image files.
    let optional_header_pos = coff_header + 20       # Last COFF field "Characteristics" is at 18 bytes with a 2 byte width.
    let optional_header_size_pos = coff_header + 16  # Offset 16 bytes within the COFF header.

    let signature = pe_file.read(sig_offset,  array[4, char])
    check_signature:  ['P', 'E', '\0', '\0']

    let optional_header_size  = pe_file.read(optional_header_size_pos, uint16)
    check_optional_header_size:  optional_header_size == 0

    let optional_header_magic = pe_file.read(optional_header_pos, uint16)
    check_optional_header_magic:  optional_header_magic in [MAGIC_PE32, MAGIC_PE32_PLUS, MAGIC_ROM]


pe_parse("./examples/test2.exe")
