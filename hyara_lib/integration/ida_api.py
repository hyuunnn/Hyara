import hashlib
import logging

import ida_bytes
import ida_nalt
import pefile
from ida_domain import Database

from ..ui.settings import HyaraGUI

logger = logging.getLogger(__name__)


class HyaraIDA(HyaraGUI):
    def __init__(self):
        super().__init__()
        # GUI mode: handle to the database already open in IDA. Do not close it.
        self._db = Database.open()

    def set_start_address(self, text: str) -> None:
        self._start_address.setText(text)

    def set_end_address(self, text: str) -> None:
        self._end_address.setText(text)

    def _iter_heads(self, start_address: int, end_address: int):
        ea = start_address
        while ea < end_address:
            nxt = self._db.heads.get_next(ea)
            yield ea, nxt
            if nxt is None or nxt <= ea:
                break
            ea = nxt

    def get_disasm(self, start_address, end_address) -> list:
        if start_address >= end_address:
            return []
        return [
            self._db.bytes.get_disassembly_at(ea) or ""
            for ea, _nxt in self._iter_heads(start_address, end_address)
        ]

    def get_hex(self, start_address, end_address) -> str:
        length = end_address - start_address
        if length <= 0:
            return ""
        data = self._db.bytes.get_bytes_at(start_address, length)
        if not data:
            logger.warning("failed to read %s bytes at %s", length, hex(start_address))
            return ""
        return data.hex()

    def get_comment_hex(self, start_address, end_address) -> list:
        if start_address >= end_address:
            return []
        result = []
        for ea, nxt in self._iter_heads(start_address, end_address):
            item_end = end_address if nxt is None else nxt
            result.append(self.get_hex(ea, item_end))
        return result

    def get_string(self, start_address, end_address) -> list:
        if start_address >= end_address:
            return []

        result = []
        for ea, _nxt in self._iter_heads(start_address, end_address):
            strtype = ida_nalt.get_str_type(ea)
            if strtype >= 0xFFFFFFFF:
                continue
            contents = ida_bytes.get_strlit_contents(ea, -1, strtype)
            if contents:
                result.append(contents.decode())
        return result

    def get_filepath(self) -> str:
        return self._db.path or ""

    def get_md5(self) -> str:
        return self._db.md5 or ""

    def get_imphash(self) -> str:
        return pefile.PE(self.get_filepath()).get_imphash()

    def get_rich_header(self) -> str:
        rich_header = pefile.PE(self.get_filepath()).parse_rich_header()
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
        self._db.current_ea = int(addr)
