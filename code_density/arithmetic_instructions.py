from ..xtensa_instruction import RRR, RRRN, RRI8
from ..xtensa_register import GPR
from ..utils import *

from binaryninja import LLIL_TEMP, LowLevelILLabel, InstructionTextTokenType, InstructionTextToken

class ADDN(RRRN):
    mnemonic = "add.n"

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.set_reg(4, GPR[self.r], il.add(
            4, il.reg(4, GPR[self.s]), il.reg(4, GPR[self.t]))))

        return self.length

class ADDIN(RRRN):
    mnemonic = "addi.n"

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        register = InstructionTextTokenType.RegisterToken
        filler = InstructionTextTokenType.TextToken
        sep = InstructionTextTokenType.OperandSeparatorToken
        imm = InstructionTextTokenType.IntegerToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(register, GPR[self.t]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(register, GPR[self.s]))
        tokens.append(InstructionTextToken(sep, ','))
        
        if self.t == 0:
            imm_prep = -1
        else:
            imm_prep = self.t
        tokens.append(InstructionTextToken(imm, "{}".format(imm_prep)))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        if self.t == 0:
            imm_prep = -1
        else:
            imm_prep = self.t
        il.append(il.set_reg(4, GPR[self.t], il.add(4, il.reg(4, GPR[self.s]),
                                               il.sign_extend(4, il.const(1, imm_prep)))))

        return self.length
