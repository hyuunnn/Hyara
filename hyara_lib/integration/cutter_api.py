from ..ui.settings import HyaraGUI
import cutter
import hashlib
import pefile
import base64


class HyaraCutter(HyaraGUI):
    def __init__(self):
        super(HyaraCutter, self).__init__()

    def get_disasm(self, start_address, end_address) -> list:
        result = []
        start = int(start_address, 16)
        end = int(end_address, 16)
        while start <= end:
            cutter_data = cutter.cmdj("aoj @ " + str(start))
            result.append(cutter_data[0]["disasm"])
            start += cutter_data[0]["size"]
        return result

    def get_hex(self, start_address, end_address) -> list:
        result = []
        start = int(start_address, 16)
        end = int(end_address, 16)
        while start <= end:
            cutter_data = cutter.cmdj("aoj @ " + str(start))
            result.append(cutter_data[0]["bytes"])
            start += cutter_data[0]["size"]
        return result

    def get_string(self, start_address, end_address) -> list:
        result = []
        start = int(start_address, 16)
        end = int(end_address, 16)
        data = cutter.cmdj("Csj")
        for i in data:
            if i["offset"] >= start and i["offset"] <= end:
                result.append(base64.b64decode(i["name"]).decode())
        return result

    def get_filepath(self) -> str:
        return cutter.cmdj("ij")["core"]["file"]

    def get_md5(self) -> str:
        return hashlib.md5(open(self.get_filepath(), "rb").read()).hexdigest()

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
        return cutter.cmd("s " + str(addr))