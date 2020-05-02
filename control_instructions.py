from .xtensa_instruction import RRR, RRRN, RRI8, CALLX, BRI12, RI6
from .xtensa_register import GPR
from .utils import *

from binaryninja import LLIL_TEMP, LowLevelILLabel, InstructionTextTokenType, InstructionTextToken, InstructionInfo, BranchType


class BEQZN(RI6):
    mnemonic = "beqz.n"

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr + self.imm6 + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        true_label = LowLevelILLabel()
        false_label = LowLevelILLabel()

        cmp_expr = il.compare_equal(4, il.reg(4, self.s), il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        il.mark_label(true_label)
        when_true_expr = il.add(4, il.const(1, self.imm6), il.const(4, 4))
        il.append(il.set_reg(4, "pc", il.add(
            4, il.reg(4, "pc"), when_true_expr)))

        il.mark_label(false_label)

        return self.length


class RET(CALLX):
    mnemonic = "ret"

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        filler = InstructionTextTokenType.TextToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.FunctionReturn)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.ret(il.reg(4, 0)))

        return self.length
