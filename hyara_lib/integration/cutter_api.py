from ..ui.settings import HyaraGUI
import cutter
import hashlib


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

    def get_md5(self) -> str:
        filepath = cutter.cmdj("ij")["core"]["file"]
        return hashlib.md5(open(filepath, "rb").read()).hexdigest()
