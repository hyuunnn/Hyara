try:
    from . import Hyara_Cutter
    cutter_found = True
except ImportError:
    cutter_found = False

if cutter_found:
    def create_cutter_plugin():
        return Hyara_Cutter.HyaraPlugin()