
# Lazy : https://stackoverflow.com/questions/1604464/twos-complement-in-python
def twos_comp(val, bits):
    """compute the 2's complement of int value val"""
    if (val & (1 << (bits - 1))) != 0:
        val = val - (1 << bits)
    return val 

B4CONST_TABLE = {
    0: 0,
    1: 1,
    2: 2,
    3: 3,
    4: 4,
    5: 5,
    6: 6,
    7: 7,
    8: 8,
    9: 0xA,
    10: 0xC,
    11: 0x10,
    12: 0x20,
    13: 0x40,
    14: 0x80,
    15: 0x100,
}