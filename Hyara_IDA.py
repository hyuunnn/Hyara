import logging
import os

import ida_kernwin

logger = logging.getLogger(__name__)


def should_load() -> bool:
    """Return True when IDA 9.2+ is running interactively."""
    if not ida_kernwin.is_idaq():
        return False

    if os.environ.get("IDA_IS_INTERACTIVE") != "1":
        return False

    kernel_version: tuple[int, ...] = tuple(
        int(part)
        for part in ida_kernwin.get_kernel_version().split(".")
        if part.isdigit()
    ) or (0,)
    if kernel_version < (9, 2):
        logger.warning("IDA too old (must be 9.2+): %s", ida_kernwin.get_kernel_version())
        return False

    return True


_load_plugin = False
if should_load():
    try:
        from hyara_ida.plugin import hyara_plugin_t
    except Exception:
        logger.exception("failed to load Hyara")
        ida_kernwin.warning(
            "Hyara failed to load. Install ida-domain, yara-python, pefile, and Pillow into IDA's Python environment."
        )
    else:
        _load_plugin = True


if _load_plugin:

    def PLUGIN_ENTRY():
        return hyara_plugin_t()

else:
    try:
        import ida_idaapi
    except ImportError:
        import idaapi as ida_idaapi

    class hyara_nop_plugin_t(ida_idaapi.plugin_t):
        flags = ida_idaapi.PLUGIN_HIDE | ida_idaapi.PLUGIN_UNL
        wanted_name = "Hyara disabled"
        comment = "Hyara is disabled for this IDA version"
        help = ""
        wanted_hotkey = ""

        def init(self):
            return ida_idaapi.PLUGIN_SKIP

    def PLUGIN_ENTRY():
        return hyara_nop_plugin_t()
