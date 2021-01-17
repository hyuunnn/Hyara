from ..ui.settings import HyaraGUI

import ida_ida
import ida_bytes
import ida_nalt
import idautils
import idc
import binascii
import pefile
import hashlib


class HyaraIDA(HyaraGUI):
    def __init__(self):
        super(HyaraIDA, self).__init__()

    def get_disasm(self, start_address, end_address) -> list:
        result = []
        start = int(start_address, 16)
        end = int(end_address, 16)
        while start <= end:
            # https://github.com/idapython/src/blob/master/python/idautils.py#L202
            next_start = ida_bytes.next_head(start, ida_ida.cvar.inf.max_ea)
            result.append(idc.GetDisasm(start))
            start = next_start
        return result

    def get_hex(self, start_address, end_address) -> list:
        result = []
        start = int(start_address, 16)
        end = int(end_address, 16)
        while start <= end:
            # https://github.com/idapython/src/blob/master/python/idautils.py#L202
            next_start = ida_bytes.next_head(start, ida_ida.cvar.inf.max_ea)
            result.append(binascii.hexlify(ida_bytes.get_bytes(start, next_start - start)).decode())
            start = next_start
        return result

    def get_string(self, start_address, end_address) -> list:
        result = []
        start = int(start_address, 16)
        end = int(end_address, 16)
        while start <= end:
            # https://github.com/idapython/src/blob/master/python/idautils.py#L202
            next_start = ida_bytes.next_head(start, ida_ida.cvar.inf.max_ea)
            if ida_nalt.get_str_type(start) < 4294967295:
                result.append(
                    ida_bytes.get_strlit_contents(start, -1, ida_nalt.get_str_type(start)).decode()
                )
            start = next_start
        return result

    def get_filepath(self) -> str:
        return ida_nalt.get_input_file_path()

    def get_md5(self) -> str:
        return idautils.GetInputFileMD5().hex()

    def get_imphash(self) -> str:
        return pefile.PE(self.get_filepath()).get_imphash()

    def get_rich_header(self) -> str:
        rich_header = pefile.PE(self.get_filepath()).parse_rich_header()
        return hashlib.md5(rich_header["clear_data"]).hexdigest()

    def get_pdb_path(self) -> str:
        pe = pefile.PE(self.get_filepath())
        rva = pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].VirtualAddress
        size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].Size
        return (
            pe.parse_debug_directory(rva, size)[0].entry.PdbFileName.split(b"\x00", 1)[0].decode()
        )

    def jump_to(self, addr):
        idc.jumpto(addr)