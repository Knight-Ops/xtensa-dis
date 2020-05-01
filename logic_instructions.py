from .xtensa_instruction import RRR, RRRN, RRI8
from .xtensa_register import GPR

from binaryninja import LLIL_TEMP, LowLevelILLabel, InstructionTextTokenType, InstructionTextToken


class AND(RRR):
    mnemonic = "and"

    def get_instruction_low_level_il(self, data, addr, il):

        il.append(il.set_reg(4, self.r, il.and_expr(4, il.reg(4, self.s), il.reg(4, self.t))))

        return self.length