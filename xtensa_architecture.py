from typing import List, Dict

from binaryninja import log, log_error, Architecture, RegisterInfo, IntrinsicInfo, InstructionInfo, BinaryViewType, CallingConvention, FunctionRecognizer
from binaryninja.enums import Endianness, FlagRole, LowLevelILFlagCondition
from binaryninja.types import Type

from .xtensa_instruction import XtensaInstruction, LOOKUP
from .xtensa_register import get_regs

import traceback

# from .arithmetic_instructions import *

__all__ = ['Xtensa']


class Xtensa(Architecture):
    name = 'xtensa'
    endianness = Endianness.LittleEndian
    address_size = 4
    default_int_size = 4
    instr_alignment = 1
    max_instr_length = 3

    stack_pointer = 'a1'

    regs = get_regs()

    # instructions: List[XtensaInstruction] = [ABS]

    def decode_instruction(self, data: bytes, addr: int):
        """
        Iterates through all the decoders that we have defined and attempts
        to decode the current data.
        If nothing returns, we have not implemented
        the instruction. If

         2 or more return, then we have done something wrong,
        resulting in ambiguous behavior. If only one returns, we are good to go!
        """
        # decode_results = []
        # for a in self.instructions:
        #     decode_result = a.decode(data, addr)
        #     if decode_result is None:
        #         continue
        #     decode_results.append(decode_result)
        # if len(decode_results) > 1:
        #     log_error(f"Ambiguous decoding: {decode_result}")
        #     return None
        # elif len(decode_results) == 0:
        #     log_error(
        #         f"No implementation found for instruction at {hex(addr)}")
        #     return None
        # return decode_results[0]

        # We want to do table lookups to find our specific instruction instead of trying every possible decoding
        # First we want to get our generic "lookup" class
        if len(data) < 2:
            return None

        lookup = LOOKUP(data, addr)

        try:
            instr_type = lookup.find_instr()
        except KeyError:
            # TODO Hacky way to surpress issues with the current instr list
            return None

        if instr_type is None:
            return None

        return instr_type.decode(data, addr)


    def get_instruction_text(self, data, addr):
        """Pull tokenization from implementing class"""
        # print("Decoding instruction at : 0x{:X} - {}".format(addr, data))
        decode_result = self.decode_instruction(data, addr)
        # print("Decoded instruction at : 0x{:X} - {}".format(addr, decode_result))
        if decode_result is None:
            return [[], 1]
        return decode_result.get_instruction_text(data, addr)

    def get_instruction_info(self, data, addr):
        """Pull instruction info from implementing class"""
        decode_result = self.decode_instruction(data, addr)
        if decode_result is None:
            i = InstructionInfo()
            i.length = 1
            return i
        return decode_result.get_instruction_info(data, addr)

    def get_instruction_low_level_il(self, data, addr, il):
        """Pull LLIL from implementing class"""
        decode_result = self.decode_instruction(data, addr)
        if decode_result is None:
            return 1
        else:
            return decode_result.get_instruction_low_level_il(data, addr, il)

# Taken from previous xtensa disassembler
# https://github.com/allanlw/binja-xtensa
class XtensaFunctionRecognizer(FunctionRecognizer):
	def recognize_low_level_il(self, data, func, il):
		first_inst = func.instructions.__next__()
		res = first_inst[0][0].text == "entry"
		if res and not func.name.startswith("XTFUNC_"):
			func.name = "XTFUNC_" + func.name
		# look for 0x36 (Entry instruction) immediately following the bottom of this function
		try:
			end = max(b.end for b in func.basic_blocks)
			for i in range(4):
				ei = end+i
				b = data.read(ei, 1)
				if b == '\x36':
					if data.get_function_at(ei) is not None: break
					data.add_function(ei)
					break
				if b != '\x00': break
		except Exception as e:
			log.log_error(traceback.format_exc())
		return res

# Taken from previous xtensa disassembler
# https://github.com/allanlw/binja-xtensa
class XtensaWindowedCallingConvention(CallingConvention):
	int_arg_regs = ["a2", "a3", "a4", "a5", "a6", "a7"]
	int_return_reg = "a2"
	stack_adjusted_on_return = False

Xtensa.register()
arch = Architecture['xtensa']
arch.register_calling_convention(XtensaWindowedCallingConvention(arch, 'Windowed'))
BinaryViewType['ELF'].register_arch(94, Endianness.LittleEndian, arch)
XtensaFunctionRecognizer.register_arch(arch)
