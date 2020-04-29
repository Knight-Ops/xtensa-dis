from binaryninja import log, Architecture, RegisterInfo, IntrinsicInfo, InstructionInfo, BinaryViewType
from binaryninja.enums import Endianness, FlagRole, LowLevelILFlagCondition
from binaryninja.types import Type


__all__ = ['Xtensa']


class Xtensa(Architecture):
    name = 'xtensa'
    endianness = Endianness.LittleEndian
    address_size = 4
    default_int_size = 4
    instr_alignment = 1
    max_instr_length = 3

    stack_pointer = 'a1'


    regs = {
        'pc' : RegisterInfo('pc', 4),
        'sar' : RegisterInfo('sar', 1), # 6 bits?
        'lbeg': RegisterInfo('lbeg', 4),
        'lend': RegisterInfo('lend', 4),
        'lcount': RegisterInfo('lcount', 4),
        'acclo': RegisterInfo('acclo', 4),
        'acchi': RegisterInfo('acchi', 4),
        'm0': RegisterInfo('m0', 4),
        'm1': RegisterInfo('m1', 4),
        'm2': RegisterInfo('m2', 4),
        'm3': RegisterInfo('m3', 4),
        'br': RegisterInfo('br', 2),
        'litbase': RegisterInfo('litbase', 3), # 21 bits?
        'scompare1': RegisterInfo('scompare1', 4),
        'ps': RegisterInfo('ps', 2), # 15 bits?
        # Could do like ps.intlevel here too?
        # There are a bunch of other "Special registers" that we could implement here
    }

    for i in range(16):
        n = "a{}".format(i)
        regs[n] = RegisterInfo(n, 4)


    def get_instruction_info(self, data, addr):
        return

    def get_instruction_text(self, data, addr):
        return

    def get_instruction_low_level_il(self, data, addr, il):
        return

    def is_always_branch_patch_available(self, data, addr):
        return

    def always_branch(self, data, addr):
        return

    def is_invert_branch_patch_available(self, data, addr):
        return

    def invert_branch(self, data, addr):
        return


Xtensa.register()
arch = Architecture['xtensa']
BinaryViewType['ELF'].register_arch(94, Endianness.LittleEndian, arch)
