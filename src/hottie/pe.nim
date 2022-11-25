import std/[bitops, enumerate, strutils, strformat]


const
    # Optional Header magic types
    MAGIC_ROM: uint16 = 0x107
    MAGIC_PE32: uint16 = 0x10b
    MAGIC_PE32_PLUS: uint16 = 0x20b
    # Base Relocation types
    IMAGE_REL_BASED_ABSOLUTE: uint64 = 0
    IMAGE_REL_BASED_HIGH: uint64 = 1
    IMAGE_REL_BASED_LOW: uint64 = 2
    IMAGE_REL_BASED_HIGHLOW: uint64 = 3
    IMAGE_REL_BASED_HIGHADJ: uint64 = 4
    IMAGE_REL_BASED_MIPS_JMPADDR: uint64 = 5
    IMAGE_REL_BASED_ARM_MOV32: uint64 = 5
    IMAGE_REL_BASED_RISCV_HIGH20: uint64 = 5
    # RESERVED = 6
    IMAGE_REL_BASED_THUMB_MOV32: uint64 = 7
    IMAGE_REL_BASED_RISCV_LOW12I: uint64 = 7
    IMAGE_REL_BASED_RISCV_LOW12S: uint64 = 8
    IMAGE_REL_BASED_LOONGARCH32_MARK_LA: uint64 = 8
    IMAGE_REL_BASED_LOONGARCH64_MARK_LA: uint64 = 8
    IMAGE_REL_BASED_MIPS_JMPADDR16: uint64 = 9
    IMAGE_REL_BASED_DIR64: uint64 = 10


proc read(f: var File, offset: int, valueType: typedesc): valueType =
    let numBytes = sizeof(valueType)
    var buffer: array[sizeof(valueType), uint8]
    f.setFilePos(offset, relativeTo=fspSet)
    if f.readBytes(buffer, start=0, len=numBytes) != numBytes:
        raise newException(Exception, "Could not read value at offset: " & $offset)

    result = cast[valueType](buffer)


proc asHex(v: SomeInteger, padWidth = 4): string =
    let hex = v.toHex().strip(leading=true, trailing=false, chars={'0'}).toLowerAscii()
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

    var
        base_reloc_pos: int
        image_base_pos: int
        section_header_pos: int
        image_base: uint64

    if optional_header_magic == MAGIC_PE32:
        image_base_pos = optional_header_pos + 28       # PE32 has an extra 4-byte field (BaseOfData) over PE32+
        base_reloc_pos = optional_header_pos + 136      # Position of Base Relocation Table field in PE32
        section_header_pos = optional_header_pos + 224  # 8 bytes after final reserved entry in Optional Header
        image_base = cast[uint64](pe_file.read(image_base_pos, uint32))
    elif optional_header_magic == MAGIC_PE32_PLUS:
        image_base_pos = optional_header_pos + 24
        base_reloc_pos = optional_header_pos + 152      # Position of Base Relocation Table field in PE32+
        section_header_pos = optional_header_pos + 240  # 8 bytes after final reserved entry in Optional Header
        image_base = pe_file.read(image_base_pos, uint64)
    else:
        raise newException(Exception, fmt"Optional Header magic value ({optional_header_magic}.asHex()) is not supported.")

    let image_size_pos = optional_header_pos + 56
    let image_size = pe_file.read(image_size_pos, uint32)
    when defined(peprogress):
        echo fmt"[{image_base_pos.asHex()}] Image Base: {image_base}"
        echo fmt"[{image_size_pos.asHex()}] Image Size: {image_size}"
        echo fmt"[{section_header_pos.asHex()}] First Section Header"

    let base_reloc_virtual_address = pe_file.read(base_reloc_pos, uint32)
    let base_reloc_table_size = pe_file.read(base_reloc_pos + 4, uint32)

    when defined(peprogress):
        echo fmt"[{base_reloc_pos.asHex()}] Reloc Table Pos: {base_reloc_virtual_address}"
        echo fmt"[{(base_reloc_pos + 4).asHex()}] Reloc Table Size: {base_reloc_table_size}"

    var
        base_reloc_table_pos: int

    while true:
        let virtual_address = pe_file.read(section_header_pos + 12, uint32)
        let pointer_raw_data = pe_file.read(section_header_pos + 20, uint32)
        if virtual_address == base_reloc_virtual_address:
            base_reloc_table_pos = pointer_raw_data.int
            break

        section_header_pos += 40  # section headers are always 40 bytes

    # Iterate over each block.
    var table_pos = base_reloc_table_pos
    let table_end = base_reloc_table_pos + base_reloc_table_size.int
    while table_pos < table_end:
        when defined(peprogress):
            echo "\n[Image Base Relocation]"
        let reloc_rva = pe_file.read(table_pos, uint32)
        let reloc_block_size = pe_file.read(table_pos + 4, uint32)
        when defined(peprogress):
            echo fmt"[{table_pos.asHex()}] Virtual Address: {reloc_rva.asHex()}"
            echo fmt"[{(table_pos + 4).asHex()}] Block Size: {reloc_block_size}"

        # Iterate over each page.
        var next_reloc_pos = table_pos + 8
        let last_block_pos = next_reloc_pos + (reloc_block_size - 8).int  # block_size is inclusive of the rva an itself.
        while next_reloc_pos < last_block_pos:
            let 
                reloc_block = pe_file.read(next_reloc_pos.int, uint16)
                reloc_block_type = reloc_block.bitsliced(12 .. 15)    # 4 bits
                reloc_block_offset = reloc_block.bitsliced(0 ..< 12)  # 12 bits
                
            if not (reloc_block_type in [IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_DIR64]):
                raise newException(Exception, fmt"This reloc block type <{reloc_block_type}> is not currently supported.")
    
            when defined(peprogress):
                echo fmt"[{next_reloc_pos.asHex()}] Type: ", $reloc_block_type
                echo fmt"[{next_reloc_pos.asHex()}] Offset: ", reloc_block_offset.asHex(2)

            next_reloc_pos += 2  # move ahead 2 bytes

        table_pos = next_reloc_pos


pe_parse("./examples/test2.exe")
