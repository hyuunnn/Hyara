from ..ui.settings import HyaraGUI
import pefile
import binascii

from binaryninjaui import DockHandler
from binaryninja.transform import Transform


# https://github.com/gaasedelen/lighthouse/blob/master/plugins/lighthouse/util/disassembler/binja_api.py#L181
def binja_get_bv_from_dock():
    dh = DockHandler.getActiveDockHandler()
    if not dh:
        return None
    vf = dh.getViewFrame()
    if not vf:
        return None
    vi = vf.getCurrentViewInterface()
    bv = vi.getData()
    return bv


class HyaraBinaryNinja(HyaraGUI):
    def __init__(self):
        super(HyaraBinaryNinja, self).__init__()

    @property
    def bv(self):
        return binja_get_bv_from_dock()

    def get_disasm(self, start_address, end_address) -> list:
        result = []
        bv = self.bv
        bv.next_address = start_address
        while bv.next_address < end_address:
            result.append(bv.get_next_disassembly())
        return result

    def get_hex(self, start_address, end_address) -> str:
        start = start_address
        return binascii.hexlify(self.bv.read(start, end_address - start)).decode()

    def get_comment_hex(self, start_address, end_address) -> list:
        result = []
        bv = self.bv
        bv.next_address = start_address
        while bv.next_address < end_address:
            start = bv.next_address
            bv.get_next_disassembly()
            end = bv.next_address
            result.append(self.get_hex(start, end))
        return result

    def get_string(self, start_address, end_address) -> list:
        start = start_address
        length = end_address - start
        return [i.value for i in self.bv.get_strings(start, length)]

    def get_filepath(self) -> str:
        return self.bv.file.original_filename

    def get_md5(self) -> str:
        with open(self.get_filepath(), "rb") as f:
            return Transform["RawHex"].encode(Transform["MD5"].encode(f.read()))

    def get_imphash(self) -> str:
        return pefile.PE(self.get_filepath()).get_imphash()

    def get_rich_header(self) -> str:
        rich_header = pefile.PE(self.get_filepath()).parse_rich_header()
        return Transform["RawHex"].encode(Transform["MD5"].encode(rich_header["clear_data"]))

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
        bv = self.bv
        bv.navigate(bv.view, addr)