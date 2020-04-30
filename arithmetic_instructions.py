from .xtensa_instruction import RRR

from binaryninja import LLIL_TEMP, LowLevelILLabel


class ABS(RRR):
    opcode = 0
    mnemonic = "abs"

    def get_instruction_low_level_il(self, data, addr, il):
        negative_label = LowLevelILLabel()
        positive_label = LowLevelILLabel()
        # Check if we have a positive or negative number
        cmp_expr = il.compare_signed_greater_equal(4, il.reg(4, self.s), il.const(4, 0))
        if_expr = il.if_expr(cmp_expr, positive_label, negative_label)
        il.append(if_expr)

        # if it is negative, we want to negate it
        il.mark_label(negative_label)
        il.append(il.set_reg(4, self.r, il.neg_expr(4, il.reg(4, self.s))))

        # otherwise, just move the value
        il.mark_label(positive_label)
        il.append(il.set_reg(4, self.r, il.reg(4, self.s)))

        return self.length
