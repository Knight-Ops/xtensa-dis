from ..xtensa_instruction import RRR, RRRN, RRI8, RI6
from ..xtensa_register import GPR
from ..utils import *

from binaryninja import LLIL_TEMP, LowLevelILLabel, InstructionTextTokenType, InstructionTextToken, InstructionInfo, BranchType

class BEQZN(RI6):
    mnemonic = "beqz.n"

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr +
                        self.imm6 + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        true_label = LowLevelILLabel()
        false_label = LowLevelILLabel()

        cmp_expr = il.compare_equal(4, il.reg(4, GPR[self.s]), il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        il.mark_label(true_label)
        addr_target = addr + self.imm6 + 4
        il.append(il.set_reg(4, "pc", il.const(4, addr_target)))

        il.mark_label(false_label)

        return self.length

class BNEZN(RI6):
    mnemonic = "bnez.n"

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr +
                        self.imm6 + 4)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        true_label = LowLevelILLabel()
        false_label = LowLevelILLabel()

        cmp_expr = il.compare_not_equal(4, il.reg(4, GPR[self.s]), il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        il.mark_label(true_label)
        addr_target = addr + self.imm6 + 4
        il.append(il.set_reg(4, "pc", il.const(4, addr_target)))

        il.mark_label(false_label)

        return self.length