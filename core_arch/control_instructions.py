from ..xtensa_instruction import RRR, RRRN, RRI8, CALLX, BRI12, RI6, BRI8, CALL
from ..xtensa_register import GPR
from ..utils import *

from binaryninja import LLIL_TEMP, LowLevelILLabel, InstructionTextTokenType, InstructionTextToken, InstructionInfo, BranchType


class CALL0(CALL):
    mnemonic = "call0"

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.CallDestination)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):

        # address_prep = il.and_expr(4, il.const(4, addr), il.const(4, 0xFFFFFFFC))
        address_prep = addr & 0xFFFFFFFC
        # immediate_prep = il.shift_left(4, il.const(4, twos_comp(self.offset, 18)), il.const(4, 2))
        imm_prep = twos_comp(self.offset, 18) << 2
        # add_prep = il.add(4, il.add(4, address_prep, immediate_prep), il.const(4, 4))
        add_prep = address_prep + imm_prep + 4
        il.append(il.set_reg(4, GPR[0], il.const(4, addr + self.length)))
        il.append(il.call(il.const(4, add_prep)))
        # TODO : Do we really need to pop this, I don't want the stack going crazy if we aren't using it
        # il.append(il.pop(4))

        return self.length

class CALLX0(CALLX):
    mnemonic = "callx0"

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.CallDestination)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):

        il.append(il.set_reg(4, GPR[0], il.const(4, addr + self.length)))
        il.append(il.call(il.reg(4, GPR[self.s])))
        # TODO : Do we really need to pop this, I don't want the stack going crazy if we aren't using it
        # il.append(il.pop(4))

        return self.length


class J(CALL):
    mnemonic = "j"

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        filler = InstructionTextTokenType.TextToken
        call_loc = InstructionTextTokenType.CodeRelativeAddressToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        addr_calc = addr + twos_comp(self.offset, 18) + 4
        tokens.append(InstructionTextToken(call_loc, hex(addr_calc), value=addr_calc))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        addr_calc = addr + twos_comp(self.offset, 18) + 4
        info.add_branch(BranchType.UnconditionalBranch, addr_calc)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        addr_calc = addr + twos_comp(self.offset, 18) + 4
        il.append(il.jump(il.const(4, addr_calc)))
        return self.length

class JX(CALLX):
    mnemonic = "jx"

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.UnconditionalBranch)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):

        il.append(il.jump(il.reg(4, GPR[self.s])))

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
        il.append(il.ret(il.reg(4, GPR[0])))

        return self.length