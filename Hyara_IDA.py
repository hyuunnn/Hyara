from hyara_lib.integration.ida_api import HyaraIDA
import ida_kernwin
import idaapi


class Hyara_action_handler_t(idaapi.action_handler_t):
    def __init__(self, widget):
        idaapi.action_handler_t.__init__(self)
        self.widget = widget

    def activate(self, ctx):
        self.widget.setText(hex(idaapi.get_screen_ea()))
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class Hooks(ida_kernwin.UI_Hooks):
    def __init__(self):
        ida_kernwin.UI_Hooks.__init__(self)

    def finish_populating_widget_popup(self, widget, popup):
        ida_kernwin.attach_action_to_popup(widget, popup, "Hyara:select_start_address", None)
        ida_kernwin.attach_action_to_popup(widget, popup, "Hyara:select_end_address", None)


class HyaraWidget(ida_kernwin.PluginForm):
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.HyaraIDA = HyaraIDA()
        self.parent.setLayout(self.HyaraIDA.layout)

        idaapi.register_action(
            ida_kernwin.action_desc_t(
                "Hyara:select_start_address",
                "Hyara - Select Start Address",
                Hyara_action_handler_t(self.HyaraIDA._start_address),
                "Ctrl+Shift+S",
                "Hyara - Select Start Address",
            )
        ),

        idaapi.register_action(
            ida_kernwin.action_desc_t(
                "Hyara:select_end_address",
                "Hyara - Select End Address",
                Hyara_action_handler_t(self.HyaraIDA._end_address),
                "Ctrl+Shift+E",
                "Hyara - Select End Address",
            )
        ),

    def OnClose(self, form):
        idaapi.unregister_action("Hyara:select_start_address")
        idaapi.unregister_action("Hyara:select_end_address")
        hooks.unhook()


class HyaraPlugin(idaapi.plugin_t):
    # https://www.hex-rays.com/products/ida/support/sdkdoc/group___p_l_u_g_i_n__.html
    flags = idaapi.PLUGIN_UNL
    comment = "Hyara"
    help = "help"
    wanted_name = "Hyara"
    wanted_hotkey = "Ctrl+Shift+Y"

    def init(self):
        global hooks
        idaapi.msg("[*] Hyara Plugin\n")
        hooks = Hooks()
        hooks.hook()
        return idaapi.PLUGIN_OK

    def run(self, arg):
        plg = HyaraWidget()
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
