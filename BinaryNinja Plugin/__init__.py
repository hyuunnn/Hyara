from binaryninja import *

def do_nothing(bv,function):
	show_message_box("title", "content", MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)

PluginCommand.register_for_address("Hyara", "Basically does nothing", do_nothing)
