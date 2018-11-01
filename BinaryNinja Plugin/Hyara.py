from binaryninja import *

import yara
import pefile
import binascii
import os
import re
import time
import hashlib


## ae3c7624cbe9c3fb0c1a18695dcffd07
try:
    pe = pefile.PE(bv.file.original_filename.decode("utf-8"))
except:
    pe = pefile.PE(bv.file.original_filename)

try:
    md5 = hashlib.md5(open(bv.file.original_filename.decode("utf-8"),"rb").read()).hexdigest()
except:
    md5 = hashlib.md5(open(bv.file.original_filename,"rb").read()).hexdigest()

print("MD5: {}".format(md5))
print("imphash: {}".format(pe.get_imphash()))
rich_header = pe.parse_rich_header()
print("Rich header cleardata: {}".format(hashlib.md5(rich_header['clear_data']).hexdigest()))

br = BinaryReader(bv, Endianness.BigEndian)
start_address = 0x402d30
end_address = 0x402d51

def pretty_hex(data):
    return ' '.join(data[i:i+2] for i in range(0, len(data), 2))

# byte mode
if start_address < end_address:
    length = end_address - start_address
    br.seek(start_address)
    print(pretty_hex(binascii.hexlify(br.read(length))))

start_address = 0x402e6b
end_address = 0x402e9b
# start_address = 0x414474
# end_address = 0x4144d8
if bv.is_offset_code_semantics(start_address): # strings mode (assembly code)
    while start_address < end_address:
        get_disass = bv.get_disassembly(start_address)
        if ", 0x" in get_disass:
            addr = int(get_disass[get_disass.find(", 0x")+len(", 0x"):], 16)
            print(bv.get_strings(addr)[0].value.replace("\x00",""))
            length = bv.get_instruction_length(start_address)
            start_address += length
        else:
            length = bv.get_instruction_length(start_address)
            start_address += length
else: # strings mode (strings code)
    get_string = bv.get_strings(start_address)
    for i in get_string:
        start_address = int(re.search("(0x[a-z0-9])\w+", str(i)).group(),16)
        if start_address < end_address:
            print(i.value.replace("\x00",""), hex(start_address))
        else:
            break

## YaraIcon
section_list = {}
for section in pe.sections:
    section_list[section.Name.decode("utf-8").replace("\x00","")] = [hex(section.VirtualAddress), hex(section.SizeOfRawData), hex(section.PointerToRawData)]
for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    resource_type = entry.name
    if resource_type is None:
        resource_type = pefile.RESOURCE_TYPE.get(entry.struct.Id)
    for directory in entry.directory.entries:
        for resource in directory.directory.entries:
            name = str(resource_type)
            if name in "RT_ICON":
                name = str(resource_type)
                offset = resource.data.struct.OffsetToData
                size = resource.data.struct.Size
                RVA_ = int(section_list['.rsrc'][0],16) - int(section_list['.rsrc'][2],16) # VirtualAddress - PointerToRawData
                real_offset = offset - RVA_
                img_size = hex(size)[2:]
                if len(img_size) % 2 == 1:
                    img_size = "0"+img_size
                img_ = "\x00\x00\x01\x00\x01\x00\x30\x30\x00\x00\x01\x00\x08\x00" + bytearray.fromhex(img_size)[::-1] + "\x00\x00\x16\x00\x00\x00"
                try:
                    f = open(bv.file.original_filename.decode("utf-8"),"rb")
                except:
                    f = open(bv.file.original_filename, "rb")
                f.seek(real_offset)
                img_ += f.read(size)
                f.close()

## YaraDetector
## rule = yara.compile(source=rule)
