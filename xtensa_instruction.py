from struct import unpack

from binaryninja import InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType


class XtensaInstruction:
    """
    Our base type for decoding instructions. Implements the decoding functions,
    and the necessary get_instruction_text, get_instruction_info, and
    get_instruction_low_level_il, which are all called from their respective
    functions in our architecture.
    """
    opcode: int = None
    mnemonic: str = ""
    justify: int = 10
    length: int = 0

    @classmethod
    def decode(cls, data, addr):
        """
        Our default decoder. Written so that THIS particular one will never return an object
        but classes with defined opcodes and mnemonics can inherit this and use it.
        """
        if len(data) < cls.length:
            return None
        # if cls.op0 is None:
        #     return None
        # if data[0] & 0xf0 != cls.opcode & 0xf0:
        #     return None
        return cls(data, addr)

    def __init__(self, data, addr):
        """
        We never actually use this one, so it is empty
        :param data:
        :param addr:
        """
        pass

    def get_instruction_info(self, data, addr):
        """
        Default get_instruction_info, which sets up the InstructionInfo object and does not
        add a branch.
        :param data:
        :param addr:
        :return:
        """
        info = InstructionInfo()
        info.length = self.length
        return info

    def get_instruction_text(self, data, addr):
        """
        Default (empty) tokenization
        :param data:
        :param addr:
        :return:
        """
        return ['', self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        """
        Default Low Level IL
        :param data:
        :param addr:
        :param il:
        :return:
        """
        return self.length


class RRR(XtensaInstruction):
    length = 3
    op0 = None
    t = None
    s = None
    r = None
    op1 = None
    op2 = None

    def __init__(self, data, addr):
        print("Constructing RRR")
        self.op0 = self.get_op0(data)
        self.t = self.get_t(data)
        self.s = self.get_s(data)
        self.r = self.get_r(data)
        self.op1 = self.get_op1(data)
        self.op2 = self.get_op2(data)

    def get_op0(self, data):
        return data[0] & 0xF

    def get_t(self, data):
        return (data[0] >> 4) & 0xF

    def get_s(self, data):
        return data[1] & 0xF

    def get_r(self, data):
        return (data[1] >> 4) & 0xF

    def get_op1(self, data):
        return data[2] & 0xF

    def get_op2(self, data):
        return (data[2] >> 4) & 0xF

    def get_instruction_text(self, data, addr):
        print("get_instruction_text")

        tokens = []
        opcode = InstructionTextTokenType.TextToken
        register = InstructionTextTokenType.RegisterToken
        filler = InstructionTextTokenType.TextToken
        sep = InstructionTextTokenType.OperandSeparatorToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(register, self.args[0]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(register, self.args[1]))
        return [tokens, self.length]
