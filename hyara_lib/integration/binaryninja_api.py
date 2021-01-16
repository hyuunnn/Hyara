from ..ui.settings import HyaraGUI


class HyaraBinaryNinja(HyaraGUI):
    def __init__(self):
        super(HyaraBinaryNinja, self).__init__()

    def get_disasm(self, start_address, end_address) -> list:
        pass

    def get_hex(self, start_address, end_address) -> list:
        pass

    def get_string(self, start_address, end_address) -> list:
        pass

    def get_filepath(self) -> str:
        pass

    def get_md5(self) -> str:
        pass

    def get_imphash(self) -> str:
        pass

    def get_rich_header(self) -> str:
        pass

    def jump_to(self, addr):
        pass