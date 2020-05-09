from ..xtensa_instruction import RRR, RRRN, RRI8, RI6, BRI8
from ..xtensa_register import GPR
from ..utils import *

from binaryninja import LLIL_TEMP, LowLevelILLabel, InstructionTextTokenType, InstructionTextToken, InstructionInfo, BranchType, Architecture

class LOOP(BRI8):
    mnemonic = "loop"

    # def get_instruction_info(self, data, addr):
    #     info = InstructionInfo()
    #     info.add_branch(BranchType.TrueBranch, addr +
    #                     self.imm6 + 4)
    #     info.add_branch(BranchType.FalseBranch, addr + self.length)
    #     info.length = self.length
    #     return info

    def get_instruction_low_level_il(self, data, addr, il):
        # false = addr + self.length
        # false_label = il.get_label_for_address(Architecture['xtensa'], false)
        # if false_label is None:
        #     il.add_label_for_address(Architecture['xtensa'], false)
        #     false_label = il.get_label_for_address(Architecture['xtensa'], false)

        # true = addr + self.imm6 + 4
        # true_label = il.get_label_for_address(Architecture['xtensa'], true)
        # if true_label is None:
        #     il.add_label_for_address(Architecture['xtensa'], true)
        #     true_label = il.get_label_for_address(Architecture['xtensa'], true)

        # cmp_expr = il.compare_equal(4, il.reg(4, GPR[self.s]), il.const(4, 0))
        # if_expr = il.if_expr(cmp_expr, true_label, false_label)
        # il.append(if_expr)

        lend = addr + self.imm8 + 4
        lbeg = addr + self.length

        lend_label = il.get_label_for_address(Architecture['xtensa'], lend)
        if lend_label is None:
            il.add_label_for_address(Architecture['xtensa'], lend)
            lend_label = il.get_label_for_address(Architecture['xtensa'], lend)

        lbeg_label = il.get_label_for_address(Architecture['xtensa'], lbeg)
        if lbeg_label is None:
            il.add_label_for_address(Architecture['xtensa'], lbeg)
            lbeg_label = il.get_label_for_address(Architecture['xtensa'], lbeg)

        il.append(il.set_reg(4, "lcount", il.sub(4, il.reg(4, self.s), il.const(4, 1))))
        il.append(il.set_reg(4, "lend", il.const(4, lend)))
        il.append(il.set_reg(4, "lbeg", il.const(4, lbeg)))

        # TODO This needs work on how we implement this loop in the IL

        return self.length

class LOOPGTZ(BRI8):
    mnemonic = "loopgtz"

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr + self.length)
        info.add_branch(BranchType.FalseBranch, addr + self.imm8 + 4)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        # false = addr + self.length
        # false_label = il.get_label_for_address(Architecture['xtensa'], false)
        # if false_label is None:
        #     il.add_label_for_address(Architecture['xtensa'], false)
        #     false_label = il.get_label_for_address(Architecture['xtensa'], false)

        # true = addr + self.imm6 + 4
        # true_label = il.get_label_for_address(Architecture['xtensa'], true)
        # if true_label is None:
        #     il.add_label_for_address(Architecture['xtensa'], true)
        #     true_label = il.get_label_for_address(Architecture['xtensa'], true)

        # cmp_expr = il.compare_equal(4, il.reg(4, GPR[self.s]), il.const(4, 0))
        # if_expr = il.if_expr(cmp_expr, true_label, false_label)
        # il.append(if_expr)

        lend = addr + self.imm8 + 4
        lbeg = addr + self.length

        lend_label = il.get_label_for_address(Architecture['xtensa'], lend)
        if lend_label is None:
            il.add_label_for_address(Architecture['xtensa'], lend)
            lend_label = il.get_label_for_address(Architecture['xtensa'], lend)

        lbeg_label = il.get_label_for_address(Architecture['xtensa'], lbeg)
        if lbeg_label is None:
            il.add_label_for_address(Architecture['xtensa'], lbeg)
            lbeg_label = il.get_label_for_address(Architecture['xtensa'], lbeg)

        il.append(il.set_reg(4, "lcount", il.sub(4, il.reg(4, self.s), il.const(4, 1))))
        il.append(il.set_reg(4, "lend", il.const(4, lend)))
        il.append(il.set_reg(4, "lbeg", il.const(4, lbeg)))

        cmp_expr = il.compare_signed_greater_than(4, il.reg(4, GPR[self.s]), il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, lbeg_label, lend_label)
        il.append(if_expr)

        # TODO This needs work on how we implement this loop in the IL

        return self.length

class LOOPNEZ(BRI8):
    mnemonic = "loopnez"

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.TrueBranch, addr + self.length)
        info.add_branch(BranchType.FalseBranch, addr + self.imm8 + 4)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        # false = addr + self.length
        # false_label = il.get_label_for_address(Architecture['xtensa'], false)
        # if false_label is None:
        #     il.add_label_for_address(Architecture['xtensa'], false)
        #     false_label = il.get_label_for_address(Architecture['xtensa'], false)

        # true = addr + self.imm6 + 4
        # true_label = il.get_label_for_address(Architecture['xtensa'], true)
        # if true_label is None:
        #     il.add_label_for_address(Architecture['xtensa'], true)
        #     true_label = il.get_label_for_address(Architecture['xtensa'], true)

        # cmp_expr = il.compare_equal(4, il.reg(4, GPR[self.s]), il.const(4, 0))
        # if_expr = il.if_expr(cmp_expr, true_label, false_label)
        # il.append(if_expr)

        lend = addr + self.imm8 + 4
        lbeg = addr + self.length

        lend_label = il.get_label_for_address(Architecture['xtensa'], lend)
        if lend_label is None:
            il.add_label_for_address(Architecture['xtensa'], lend)
            lend_label = il.get_label_for_address(Architecture['xtensa'], lend)

        lbeg_label = il.get_label_for_address(Architecture['xtensa'], lbeg)
        if lbeg_label is None:
            il.add_label_for_address(Architecture['xtensa'], lbeg)
            lbeg_label = il.get_label_for_address(Architecture['xtensa'], lbeg)

        il.append(il.set_reg(4, "lcount", il.sub(4, il.reg(4, self.s), il.const(4, 1))))
        il.append(il.set_reg(4, "lend", il.const(4, lend)))
        il.append(il.set_reg(4, "lbeg", il.const(4, lbeg)))

        cmp_expr = il.compare_not_equal(4, il.reg(4, GPR[self.s]), il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, lbeg_label, lend_label)
        il.append(if_expr)
        
        # TODO This needs work on how we implement this loop in the IL

        return self.length