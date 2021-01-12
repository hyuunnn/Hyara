from hyara_lib.integration.ida_api import HyaraIDA
import ida_kernwin
import idaapi


class Hyara(ida_kernwin.PluginForm):
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)

        self.HyaraIDA = HyaraIDA()
        self.parent.setLayout(self.HyaraIDA.layout)

    def OnClose(self, form):
        pass


class HyaraPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Hyara"
    help = "help"
    wanted_name = "Hyara"
    wanted_hotkey = "Ctrl+Shift+Y"

    def init(self):
        idaapi.msg("[*] Hyara Plugin\n")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        plg = Hyara()
        plg.Show("Hyara")
        try:
            widget_a = ida_kernwin.find_widget("IDA View-A")
            widget_Hyara = ida_kernwin.find_widget("Hyara")
            if widget_Hyara and widget_a:
                ida_kernwin.set_dock_pos("Hyara", "IDA View-A", ida_kernwin.DP_RIGHT)
        except:
            print("find_widget option is available version 7.0 or later")

    def term(self):
        pass


def PLUGIN_ENTRY():
    return HyaraPlugin()