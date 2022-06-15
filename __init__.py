import imp
try:
    imp.find_module('cutter')
    cutter_found = True
except ImportError:
    cutter_found = False

if cutter_found:
    import cutter
    from . import Hyara_Cutter

    def create_cutter_plugin():
        return Hyara_Cutter.HyaraPlugin()
