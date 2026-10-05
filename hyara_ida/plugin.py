import logging

import ida_idaapi
import ida_kernwin
from ida_domain.base import DatabaseError

from hyara_lib.integration.ida_api import HyaraIDA

logger = logging.getLogger(__name__)

ADDRESS_WIDGETS = (
    ida_kernwin.BWN_DISASM,
    ida_kernwin.BWN_HEXVIEW,
)


def _address_viewer_active() -> bool:
    viewer = ida_kernwin.get_current_viewer()
    if viewer is None:
        return False
    return ida_kernwin.get_widget_type(viewer) in ADDRESS_WIDGETS


class OpenHyaraHandler(ida_kernwin.action_handler_t):
    def __init__(self, plugmod: "hyara_plugmod_t") -> None:
        super().__init__()
        self.plugmod = plugmod

    def activate(self, ctx):
        self.plugmod.run(0)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class SelectAddressHandler(ida_kernwin.action_handler_t):
    def __init__(self, plugmod: "hyara_plugmod_t", setter_name: str) -> None:
        super().__init__()
        self.plugmod = plugmod
        self.setter_name = setter_name

    def activate(self, ctx):
        hyara = self.plugmod.hyara
        if hyara is None:
            return 0
        getattr(hyara, self.setter_name)(hex(ida_kernwin.get_screen_ea()))
        return 1

    def update(self, ctx):
        if self.plugmod.hyara is None or not _address_viewer_active():
            return ida_kernwin.AST_DISABLE
        return ida_kernwin.AST_ENABLE


class HyaraUIHooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup, ctx=None):
        if ida_kernwin.get_widget_type(widget) not in ADDRESS_WIDGETS:
            return
        ida_kernwin.attach_action_to_popup(
            widget, popup, hyara_plugmod_t.START_ACTION, None
        )
        ida_kernwin.attach_action_to_popup(
            widget, popup, hyara_plugmod_t.END_ACTION, None
        )


class HyaraForm(ida_kernwin.PluginForm):
    TITLE = "Hyara"

    def __init__(self, plugmod: "hyara_plugmod_t", hyara: HyaraIDA) -> None:
        super().__init__()
        self.plugmod = plugmod
        self.hyara = hyara

    def OnCreate(self, form):
        # IDA 9.2+ names this FormToPyQtWidget, but the implementation wraps PySide6.
        parent = self.FormToPyQtWidget(form)
        parent.setLayout(self.hyara.layout)

    def OnClose(self, form):
        if self.plugmod.form is self:
            self.plugmod.form = None
            self.plugmod.hyara = None


class hyara_plugmod_t(ida_idaapi.plugmod_t):
    OPEN_ACTION = "Hyara:open"
    START_ACTION = "Hyara:select_start_address"
    END_ACTION = "Hyara:select_end_address"
    MENU_PATH = "View/Open subviews/Strings"

    def __init__(self) -> None:
        super().__init__()
        self.form: HyaraForm | None = None
        self.hyara: HyaraIDA | None = None
        self.ui_hooks: HyaraUIHooks | None = None
        self.init()

    def register_actions(self) -> None:
        actions = (
            ida_kernwin.action_desc_t(
                self.OPEN_ACTION,
                "Hyara",
                OpenHyaraHandler(self),
                None,
                "Open the Hyara YARA rule view",
                -1,
            ),
            ida_kernwin.action_desc_t(
                self.START_ACTION,
                "Hyara - Select Start Address",
                SelectAddressHandler(self, "set_start_address"),
                "Ctrl+Shift+S",
                "Use the current address as the Hyara start address",
                -1,
            ),
            ida_kernwin.action_desc_t(
                self.END_ACTION,
                "Hyara - Select End Address",
                SelectAddressHandler(self, "set_end_address"),
                "Ctrl+Shift+E",
                "Use the current address as the Hyara end address",
                -1,
            ),
        )
        open_action, start_action, end_action = actions
        if not ida_kernwin.register_action(open_action):
            logger.warning("failed to register action %s", open_action.name)
        elif not ida_kernwin.attach_action_to_menu(
            self.MENU_PATH, self.OPEN_ACTION, ida_kernwin.SETMENU_APP
        ):
            logger.warning(
                "failed to attach %s after %s", self.OPEN_ACTION, self.MENU_PATH
            )

        for action in (start_action, end_action):
            if not ida_kernwin.register_action(action):
                logger.warning("failed to register action %s", action.name)

    def unregister_actions(self) -> None:
        ida_kernwin.detach_action_from_menu(self.MENU_PATH, self.OPEN_ACTION)
        ida_kernwin.unregister_action(self.OPEN_ACTION)
        ida_kernwin.unregister_action(self.START_ACTION)
        ida_kernwin.unregister_action(self.END_ACTION)

    def register_ui_hooks(self) -> None:
        self.ui_hooks = HyaraUIHooks()
        self.ui_hooks.hook()

    def unregister_ui_hooks(self) -> None:
        if self.ui_hooks is not None:
            self.ui_hooks.unhook()
            self.ui_hooks = None

    def init(self) -> None:
        self.register_actions()
        self.register_ui_hooks()

    def _dock_form(self) -> None:
        if ida_kernwin.find_widget("IDA View-A") is None:
            return
        if ida_kernwin.find_widget(HyaraForm.TITLE) is None:
            return
        try:
            ida_kernwin.set_dock_pos(
                HyaraForm.TITLE, "IDA View-A", ida_kernwin.DP_RIGHT
            )
        except Exception:
            logger.exception("failed to dock Hyara beside IDA View-A")

    def run(self, arg) -> None:
        existing = ida_kernwin.find_widget(HyaraForm.TITLE)
        if self.form is not None and existing is not None:
            ida_kernwin.activate_widget(existing, True)
            return

        try:
            hyara = HyaraIDA()
        except DatabaseError:
            logger.warning("Hyara requires an open database")
            ida_kernwin.warning("Hyara requires an open database.")
            return

        self.hyara = hyara
        self.form = HyaraForm(self, hyara)
        if not self.form.Show(HyaraForm.TITLE):
            logger.warning("failed to open the Hyara widget")
            self.form = None
            self.hyara = None
            return
        self._dock_form()

    def __del__(self) -> None:
        try:
            self.unregister_ui_hooks()
            self.unregister_actions()
        except Exception:
            logger.exception("failed to unload Hyara")


class hyara_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI
    help = "Create YARA rules from the current address range"
    comment = "Hyara"
    wanted_name = "Hyara"
    wanted_hotkey = "Ctrl+Shift+Y"

    def init(self):
        return hyara_plugmod_t()
