from ...ui.settings import HyaraGUI
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
        while start_address < end_address:
            disas_text, length = next(bv.disassembly_text(start_address))
            result.append(disas_text)
            start_address += length
        return result

    def get_hex(self, start_address, end_address) -> str:
        return binascii.hexlify(self.bv.read(start_address, end_address - start_address)).decode()

    def get_comment_hex(self, start_address, end_address) -> list:
        result = []
        bv = self.bv
        while start_address < end_address:
            disas_text, length = next(bv.disassembly_text(start_address))
            end = start_address + length
            result.append(self.get_hex(start_address, end))
            start_address = end
        return result

    def get_string(self, start_address, end_address) -> list:
        return [i.value for i in self.bv.get_strings(start_address, end_address - start_address)]

    def get_filepath(self) -> str:
        return self.bv.file.original_filename

    def get_md5(self) -> str:
        bv = self.bv
        return Transform["RawHex"].encode(
            Transform["MD5"].encode(bv.file.raw.read(0, len(bv.file.raw)))
        ).decode()

    def get_imphash(self) -> str:
        return pefile.PE(self.get_filepath()).get_imphash()

    def get_rich_header(self) -> str:
        rich_header = pefile.PE(self.get_filepath()).parse_rich_header()
        return Transform["RawHex"].encode(Transform["MD5"].encode(rich_header["clear_data"])).decode()

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
