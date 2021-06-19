# Not-A-Virus.Win64.Polytest

Work-in-progress self-modifying crypter.


## Brief: 

This assembly file contains code for a polymorphic encryption
engine. The structure of the program is as follows:

0. Macros and structures.
1. Program entry point which immediatley invokes the chosen 
   cipher.
2. The permutation engine. Algorithm description is below.
3. Function definitions for tasks that need to be repeated.

 ## Permutation Engine Algorithm:

 The permutation engine works by simply shuffling registers and 
 generating semantically equivalent instructions for known 
 operations. In this case, the permutation engine relies heavily
 on knowledge of the 0th generation cipher function to mutate
 and morph successive generations. There is no extra code insertion 
 as of now. The actual algorithm is the following:

 1. Control flow is received by permutation engine. At this point,
    the entire program has been decrypted in memory. 
 2. The engine uses a static offset to locate the cipher function. 
    Since the cipher function may grow or shrink in size, it is 
    located at the end of the program.
 3. The engine chooses a random ordering of registers to fulfill
    the semantic roles of the registers in the 0th generation cipher.
 4. Stepping through each instruction in the 0th generation cipher,
    the engine will select a semantically equivalent variant of 
    that instruction, populate mod r/m and any immediates from the
    0th generation code. The generation function doesn't change 
    the order of semantic operations. If it were to, it would also
    need to maintain awareness of the positional dependencies of
    each operation.

 To facilitate this meta-awareness of the 0th generation code, this
 program makes use of data structures describing the original
 cipher. They are the following:

 a. Registers Table: a table of registers, where each
    position indicates a semantic purpose in the original cipher.
 c. Register Index Table: a table of indexes into the actual 
    Registers Table.
 c. Skeleton Instruction Table: a table containing opcodes and
    other information needed to generate valid instructions.

 To achieve the purposes of the algorithm in a clear way, the 
 engine makes use of the following functions:

 f. ShuffleRegisterTable: given a register table index data
    structure, create a random ordering of phyiscal registers
 j. RandRange: Get a random number in a specific range.

   Notes:

       - In many cases simplicity is favored over completeness

## References:
[1] http://www.terraspace.co.uk/uasm248_ext.pdf
[2] https://bit.ly/39q4vyj
[3] https://vx-underground.org/archive/VxHeaven/lib/vmn04.html
