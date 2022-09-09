from ..ui.settings import HyaraGUI
import binascii
import hashlib
import pefile
import java.io

from ghidra.program.util import DefinedDataIterator
from ghidra.util import MD5Utilities

class HyaraGhidra(HyaraGUI):
    def __init__(self):
        super(HyaraGhidra, self).__init__()

    def get_disasm(self, start_address, end_address) -> list:
        result = []
        current_address = toAddr(start_address)
        while int(current_address.toString(), 16) < end_address:
            data = getInstructionAt(current_address)
            result.append(data.toString())
            current_address = data.getNext().getMinAddress()
        return result

    # https://www.mandiant.com/resources/blog/ghidrathon-snaking-ghidra-python-3-scripting
    def get_hex(self, start_address, end_address) -> str:
        min_addr = toAddr(start_address)
        max_addr = toAddr(end_address)
        code = bytes(map(lambda b: b & 0xff, getBytes(min_addr, max_addr.subtract(min_addr))))
        return binascii.hexlify(code).decode()

    def get_comment_hex(self, start_address, end_address) -> list:
        result = []
        current_address = toAddr(start_address)
        while int(current_address.toString(), 16) < end_address:
            end = getInstructionAt(current_address).getNext().getMinAddress()
            result.append(
                self.get_hex(
                    int(current_address.toString(), 16), 
                    int(end.toString(), 16)
                )
            )
            current_address = end
        return result

    # https://gist.github.com/nstarke/ea83d6e8aba9a8b028a94cc14f5ff00d
    def get_string(self, start_address, end_address) -> list:
        result = []
        for i in DefinedDataIterator.definedStrings(getState().getCurrentProgram()):
            addr = int(i.getMinAddress().toString(), 16)

            if addr >= start_address and addr < end_address:
                result.append(i.getValue())

        return result

    def get_filepath(self) -> str:
        filepath = getState().getCurrentProgram().getExecutablePath()
        return filepath[1:]

    def get_md5(self) -> str:
        return MD5Utilities.getMD5Hash(java.io.File(self.get_filepath()))

    def get_imphash(self) -> str:
        return pefile.PE(self.get_filepath()).get_imphash()

    def get_rich_header(self) -> str:
        rich_header = pefile.PE(self.get_filepath()).parse_rich_header()
        # TODO: using MD5Utilities.hexDump(byte[] data)
        return hashlib.md5(rich_header["clear_data"]).hexdigest()

    def get_pdb_path(self) -> str:
        # https://github.com/VirusTotal/yara/blob/master/docs/modules/pe.rst
        pe = pefile.PE(self.get_filepath())
        rva = pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].VirtualAddress
        size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].Size
        return (
            pe.parse_debug_directory(rva, size)[0]
            .entry.PdbFileName.split(b"\x00", 1)[0]
            .decode()
            .replace("\\", "\\\\")
        )

    def jump_to(self, addr):
        return goTo(toAddr(addr))