from ..ui.settings import HyaraGUI
import cutter
import hashlib
import pefile
import base64


class HyaraCutter(HyaraGUI):
    def __init__(self):
        super(HyaraCutter, self).__init__()

    def get_disasm(self, start_address, end_address) -> list:
        length = end_address - start_address
        return cutter.cmd(f"pI {length} @ {start_address}").split("\n")

    def get_hex(self, start_address, end_address) -> str:
        length = end_address - start_address
        return cutter.cmd(f"p8 {length} @ {start_address}").strip()

    def get_comment_hex(self, start_address, end_address) -> list:
        result = []
        data = cutter.cmdj("pdj")
        for i in data:
            if i["offset"] >= start_address and i["offset"] < end_address:
                result.append(i["bytes"])
        return result

    def get_string(self, start_address, end_address) -> list:
        result = []
        data = cutter.cmdj("Cslj")  # get single line strings : C*.@addr
        for i in data:
            if i["offset"] >= start_address and i["offset"] <= end_address:
                result.append(base64.b64decode(i["name"]).decode())
        return result

    def get_filepath(self) -> str:
        return cutter.cmdj("ij")['core']['file']

    def get_md5(self) -> str:
        return cutter.cmdj("itj").get("md5", None)

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
        return cutter.cmd(f"s {addr}")
