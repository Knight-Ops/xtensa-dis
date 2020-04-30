from .xtensa_instruction import RRR


class ABS(RRR):
    mnemonic = "abs"

    # def __init__(self, data, addr):
    #     print("Constructing ABS")
    #     super().__init__(data, addr)

    #     print(self.op0, self.t, self.s, self.r, self.op1, self.op2)
