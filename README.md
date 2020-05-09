# Xtensa Disassembler

## State of the Disassembler (and lifter)

This is a major work in progress. The internals of the disassembler are complete, the addition of all of the instructions is now the limiting factor. A few instructions have been implemented both disassembly and lifting and the idea is to build every instruction with lifting from the start. In order to place some ordering to the instruction implementation, After the inital set of instructions implemented, I will be moving in order of section 4.3 for additional instructions

- [X] 4.2 - Core Architecture (This needs the IL optimized significantly)
- [X] 4.3.1 - Code Density Option (break.n isn't implemented for now)
- [ ] 4.3.2 - Loop Option (Instructions are implemented, but lifting is incomplete here due to having to look forward for loop ends and then insert jumps backwards)
- [ ] 4.3.3 - Extended L32R Option
- [ ] 4.3.4 - 16-bit Integer Multiply Option
- [ ] 4.3.5 - 32-bit Integer Multiply Option
- [ ] 4.3.6 - 32-bit Integer Divide Option
- [ ] 4.3.7 - MAC16 Option
- [ ] 4.3.8 - Miscellaneous Operations Option
- [ ] 4.3.9 - Coprocessor Option
- [ ] 4.3.10 - Boolean Option
- [ ] 4.3.11 - Floating-Point Coprocessor Option
- [ ] 4.3.12 - Multiprocessor Synchronization Option
- [ ] 4.3.13 - Conditional Store Option

## Open Questions



## Resources

- https://0x04.net/~mwk/doc/xtensa.pdf
- https://github.com/whitequark/binja-i8086
- https://github.com/allanlw/binja-xtensa