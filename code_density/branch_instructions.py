from ..xtensa_instruction import RRR, RRRN, RRI8, RI6
from ..xtensa_register import GPR
from ..utils import *

from binaryninja import LLIL_TEMP, LowLevelILLabel, InstructionTextTokenType, InstructionTextToken, InstructionInfo, BranchType, Architecture

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
        false = addr + self.length
        false_label = il.get_label_for_address(Architecture['xtensa'], false)
        if false_label is None:
            il.add_label_for_address(Architecture['xtensa'], false)
            false_label = il.get_label_for_address(Architecture['xtensa'], false)

        true = addr + self.imm6 + 4
        true_label = il.get_label_for_address(Architecture['xtensa'], true)
        if true_label is None:
            il.add_label_for_address(Architecture['xtensa'], true)
            true_label = il.get_label_for_address(Architecture['xtensa'], true)

        cmp_expr = il.compare_equal(4, il.reg(4, GPR[self.s]), il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

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
        false = addr + self.length
        false_label = il.get_label_for_address(Architecture['xtensa'], false)
        if false_label is None:
            il.add_label_for_address(Architecture['xtensa'], false)
            false_label = il.get_label_for_address(Architecture['xtensa'], false)

        true = addr + self.imm6 + 4
        true_label = il.get_label_for_address(Architecture['xtensa'], true)
        if true_label is None:
            il.add_label_for_address(Architecture['xtensa'], true)
            true_label = il.get_label_for_address(Architecture['xtensa'], true)

        cmp_expr = il.compare_not_equal(4, il.reg(4, GPR[self.s]), il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, true_label, false_label)
        il.append(if_expr)

        return self.length