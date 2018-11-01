from binaryninja import *
#from PyQt5.QtCore import *
#from PyQt5.QtGui import *
#from PyQt5.QtWidgets import *

import pefile
import binascii
import os
import re
import time
import hashlib

class Hyara():
	def __init__(self, bv):
		self.bv = bv
		try:
			self.filename = self.bv.file.original_filename.decode("utf-8")
		except:
			self.filename = self.bv.file.original_filename
		self.br = BinaryReader(self.bv, Endianness.BigEndian)

	def init(self):
		c = ChoiceField("Select Mode",['binary mode','strings mode'])
		startAddress = AddressField("Start Address : ")
		endAddress = AddressField("End Address : ")
		rulename = TextLineField("Variable name : ")
		option = ChoiceField("Select Option",['Imphash','Rich header', "Imphash & Rich header", "None"])
		# result = MultilineTextField("result")
		get_form_input([c,option, startAddress,endAddress,rulename],"Hyara")
		return c.result, startAddress.result, endAddress.result, option.result, rulename.result

	def run(self):
		
		def pretty_hex(data):
   			return ' '.join(data[i:i+2] for i in range(0, len(data), 2))

		self.c_, self.start_, self.end_, self.option, self.rulename_ = self.init()

		self.pe = pefile.PE(self.filename)
		self.imphash = self.pe.get_imphash()
		self.rich_header = hashlib.md5(self.pe.parse_rich_header()['clear_data']).hexdigest()
		self.md5 = hashlib.md5(open(self.filename,"rb").read()).hexdigest()

		if self.c_ == 0 and self.start_ < self.end_:
			length = self.end_ - self.start_
			self.br.seek(self.start_)
			self.code_ = pretty_hex(binascii.hexlify(self.br.read(length)))

		elif self.c_ == 1 and self.start_ < self.end_:
			self.code_ = []
			if self.bv.is_offset_code_semantics(self.start_): # strings mode (assembly code)
				while self.start_ < self.end_:
					get_disass = self.bv.get_disassembly(self.start_)
					if ", 0x" in get_disass:
						addr = int(get_disass[get_disass.find(", 0x")+len(", 0x"):], 16)
						self.code_.append(self.bv.get_strings(addr)[0].value.replace("\x00",""))
						length = self.bv.get_instruction_length(self.start_)
						self.start_ += length
					else:
						length = self.bv.get_instruction_length(self.start_)
						self.start_ += length
			else: # strings mode (strings code)
				get_string = self.bv.get_strings(self.start_)
				for i in get_string:
					self.start_ = int(re.search("(0x[a-z0-9])\w+", str(i)).group(),16)
					if sself.tart_ < self.end_:
						self.code_.append(i.value.replace("\x00",""))
					else:
						break

	def convert_yara_rule(self):
		result = "import \"hash\"\n"
		result += "import \"pe\"\n\n"
		result += "rule " + self.rulename_ + "\n{\n"
		result += "  meta:\n"
		result += "      tool = \"https://github.com/hy00un/Hyara\"\n"
		result += "      version = \"" + "1.6" + "\"\n"
		result += "      date = \"" + time.strftime("%Y-%m-%d") + "\"\n"
		result += "      MD5 = \"" + self.md5 + "\"\n"
		result += "  strings:\n"
		if self.c_ == 0:
			result += "      $a = {" + self.code_.upper() +"}\n"
		elif self.c_ == 1:
			for idx, i in enumerate(self.code_):
				result += "      $a" + str(idx) + " = \"" + i + "\"" + " nocase wide ascii" + "\n"
		result += "  condition:\n"
		result += "      all of them"
		if self.option == 0:
			result += " and pe.imphash() == \"" + self.imphash + "\""
		elif self.option == 1:
			result += " and hash.md5(pe.rich_signature.clear_data) == \"" + self.rich_header + "\""
		elif self.option == 2:
			result += " and pe.imphash() == \"" + self.imphash + "\""
			result += " and hash.md5(pe.rich_signature.clear_data) == \"" + self.rich_header + "\""
		result += "\n}"
		return result

def start(bv,function):
	a = Hyara(bv)
	a.run()
	print(a.convert_yara_rule())
	# show_message_box("title", "content", MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)

PluginCommand.register_for_address("Hyara", "Hyara", start)