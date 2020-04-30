from .xtensa_instruction import RRR


class ABS(RRR):
    op1 = 0
    mnemonic = "abs"

    def __init__(self, data, addr):
        super().__init__(data, addr)
        print("Constructing ABS")
