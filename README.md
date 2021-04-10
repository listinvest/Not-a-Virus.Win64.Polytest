```asm
;  <poly.asm>   -    polymorphism test program
;                         April 2020
;
;   Brief: 
;
;      This assembly file contains code for a polymorphic encryption
;      engine. The structure of the program is as follows:
;       
;      0. Macros and structures.
;      1. Program entry point which immediatley invokes the chosen 
;         cipher.
;      2. The permutation engine. Algorithm description is below.
;      3. Function definitions for tasks that need to be repeated.
;
;   Permutation Engine Algorithm:
;
;       The permutation engine works by simply shuffling registers and 
;       generating semantically equivalent instructions for known 
;       operations. In this case, the permutation engine relies heavily
;       on knowledge of the 0th generation cipher function to mutate
;       and morph successive generations. There is no extra code insertion 
;       as of now. The actual algorithm is the following:
;   
;       1. Control flow is received by permutation engine. At this point,
;          the entire program has been decrypted in memory. 
;       2. The engine uses a static offset to locate the cipher function. 
;          Since the cipher function may grow or shrink in size, it is 
;          located at the end of the program.
;       3. The engine chooses a random ordering of registers to fulfill
;          the semantic roles of the registers in the 0th generation cipher.
;       4. Stepping through each instruction in the 0th generation cipher,
;          the engine will select a semantically equivalent variant of 
;          that instruction, populate mod r/m and any immediates from the
;          0th generation code. The loop maintains awareness of runtime
;          dependencies when placing instructions in positions.
;
;       To facilitate this meta-awareness of the 0th generation code, this
;       program makes use of data structures describing the original
;       cipher. They are the following:
;   
;       a. Semantic Registers Table: a table of registers, where each
;          position indicates a semantic purpose in the original cipher.
;       b. Semantic Instruction Table: a table of instruction sequences
;          delimeted by magic values where position indicates semantic
;          purpose in the original cipher. Indexes dont match 1:1 with
;          original cipher semantic operations.
;       c. Cipher Semantics Table: a table who's ordinals indicate 
;          semantic operations in the 0th generation cipher.
;       
;       To achieve the purposes of the algorithm in a clear way, the 
;       engine makes use of the following functions:
;   
;       f. ShuffleRegisterTable: given a semantic register table data
;          structure, create a random ordering of phyiscal registers
;       j. SelectInstruction: given an index into the cipher semantics
;          table, choose a corresponding intruction sequence from the 
;          semantic instruction table and populate it with the given
;          register that corresponds with the index.
;       k. RandRange: Get a random number in a specific range.
;
;   Notes:
;
;       - This program uses its data section to store the semantic 
;         instruction table. For an infector this would need to be 
;         moved.
;       - In many cases simplicity is favored over completeness
;
;   References:
;       [1] http://www.terraspace.co.uk/uasm248_ext.pdf
;       [2] https://bit.ly/39q4vyj
;       [3] https://vx-underground.org/archive/VxHeaven/lib/vmn04.html
;
```
