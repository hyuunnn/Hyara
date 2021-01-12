from ..ui.settings import HyaraGUI

import ida_ida
import ida_bytes
import idautils
import idc
import binascii

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
            result.append(
                binascii.hexlify(ida_bytes.get_bytes(start, next_start - start)).decode()
            )
            start = next_start
        return result

    def get_md5(self) -> str:
        return idautils.GetInputFileMD5().hex()