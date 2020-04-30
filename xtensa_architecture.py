from typing import List, Dict

from binaryninja import log, log_error, Architecture, RegisterInfo, IntrinsicInfo, InstructionInfo, BinaryViewType
from binaryninja.enums import Endianness, FlagRole, LowLevelILFlagCondition
from binaryninja.types import Type

from .xtensa_instruction import XtensaInstruction
from .xtensa_register import get_regs

from .arithmetic_instructions import *

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

    instructions: List[XtensaInstruction] = [ABS]

    def decode_instruction(self, data: bytes, addr: int):
        """
        Iterates through all the decoders that we have defined and attempts
        to decode the current data.
        If nothing returns, we have not implemented
        the instruction. If

         2 or more return, then we have done something wrong,
        resulting in ambiguous behavior. If only one returns, we are good to go!
        """
        decode_results = []
        for a in self.instructions:
            decode_result = a.decode(data, addr)
            if decode_result is None:
                continue
            decode_results.append(decode_result)
        if len(decode_results) > 1:
            log_error(f"Ambiguous decoding: {decode_result}")
            return None
        elif len(decode_results) == 0:
            log_error(
                f"No implementation found for instruction at {hex(addr)}")
            return None
        return decode_results[0]

    def get_instruction_text(self, data, addr):
        """Pull tokenization from implementing class"""
        print("Decoding instruction at : 0x{:X} - {}".format(addr, data))
        decode_result = self.decode_instruction(data, addr)
        print("Decoded instruction at : 0x{:X} - {}".format(addr, decode_result))
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


Xtensa.register()
arch = Architecture['xtensa']
BinaryViewType['ELF'].register_arch(94, Endianness.LittleEndian, arch)
