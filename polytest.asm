;  <polytest.asm>   -   polytest source
;                         December 2020
;
;  ToDo:
;    - Recode the basic ciphers without lodsw and stosw
;    - Continue exploring the logic of permuting using two random 
;        registers (e.g. BlackBat)
;
;  ---------------------------- abstract ----------------------------
;  This file contains a discussion of polymorphic engines, written
;  as an individual learning exercise that may be shared with others
;  for educational purposes.
;  ------------------------------------------------------------------
;
;           I. Introduction - the Components of the Engine
;
;  Distilling the poly engine into three components according to [1]:
;  the first component of the engine is a random number generator. 
;  Easy enough. The second is a junk code generator. Slightly harder.
;  The last component is a decryptor generator. Enough said.
;
;  Focusing on the last of the three first - the decryptor generator -
;  According to [1] the algorithm is as follows:
;       1. Select random set of registers
;       2. Choose a compressed pre-coded decryptor 
;       3. Enter a loop where junk code is added to the real decryptor
;           (potentially uneccesary [10])
;
;               II. Instruction Encoding In-Depth
;
;  Before even adding junk code, how is the pre-coded decryptor made 
;  compatible with the random selection of registers? From what I 
;  understand from [1], it appears that the polymorphic vxer will 
;  take advantage of patterns in opcodes related to registers/addres-
;  sing modes. This is not a trivial detail but in my experience most 
;  other sources see to gloss overer it. I could be wrong. Regardless,
;  the basics are this:
;
;  Each basic instruction in (for example) x86 64-bit mode has
;  different bits set for different addressing modes. Take XOR
;  for example [5]:
;
;       hex      bin       mode operand 1   mode operand 2
;       0x30     110000    r/m8             r8
;       0x31     110001    r/m16/32/64      r16/32/64
;       0x32     110010    r8               r/m8
;       0x33     110011    r16/32/64        r/m16/32/64
;       0x34     110100    AL               imm8
;       0x35     110101    rAX              imm16/32       fig. 1
;   
;  The commonality between all six instructions is they begin with
;  the first two bits set and the third unset. What differs between
;  them is the last three bits, each apparently indicating a different
;  addressing mode.
;
;  In [1], the author mentions building a 'skeleton instruction table'.
;  Cursory internet searches don't turn up anything like this. To
;  start off with some quick wins in creating one, we can see that its 
;  readily apparent from [5] that ADD, OR, ADC, SBB, AND, SUB, XOR,
;  and CMP share close opcode values for each addressing mode, 
;  (off by 1). But to build a skeleton table, we need only pick out
;  the first examples of these. To make things easier, these groups of  
;  different opcodes for each operation are aligned nicely (0x00-0x08, 
;  0x1-=0x0d). Other opcodes aren't as neatly organized (e.g. PUSH, POP). 
;  Regardless, just by using [5] we can simply pick out the skeleton  
;  instructions we need:
;
;       hex      opcode
;       0x00     ADD    
;       0x08     OR
;       0x10     ADC
;       0x18     SBB
;       0x20     AND
;       0x28     SUB
;       0x30     XOR
;       0x38     CMP        fig. 2
;
;  But if we look at the encoding of real instructions from an assembl-
;  ed encryption loop, we can quickly see that theres much more going
;  on than the addressing mode variations between each instruction:
;
;       a) 48 C7 C3 9A 02 00    // mov rbx, 29Ah  
;       b) 48 2B CB             // sub rcx, rbx 
;
;  Why do both instructions begin with a 48? We can assume that C7 is
;  an opcode for MOV since 2B is an opcode for SUB. What does the
;  third byte do, and why does the assembler use four bytes to repres-
;  ent an integer that fits in a word?
;
;  It took some effort to track down useful resources and make sense
;  of all the different interpretation of the data describing these
;  encodings, but between [5, 12, 13, and 14], I think I was able to
;  understand it. If we take the following instruction as an example, 
;  we can decode the meanings of the bit positions [5] [12]:
;
;   -----------------------------------------------------------------------
;       hex            
;                       __REX.W  
;                      /   ____MOV r/m16/32/64
;                     /  /  ______________Mod-Reg-R/M Byte
;                    /  /  /  ,______,____________________QWORD immediate
;                a) 48 C7 C3 9A 02 00 
;                b) 48 2B CB
;                c) 89 05 B9 1F 00 00
;                   \   
;                    \
;                     \__MOV r/m16/32/64
;       instruction         
;                a) mov rbx, 29Ah              
;                b) sub rcx, rbx           
;                c) mov dword ptr ds:0x1fb9,eax               
;
;       binary                         
;                                      ______0x29a_____
;       a)                            /                \
;         01001000 11000111 11000011 [10011010 00000010] 00000000 000000000  
;         \_____/  \_____/       \/   \__________________________________/
;           |          |         |                     |    
;   rex prefix      MOV           register             quad word  
;               
;       b)         
;                   01001000         01010110        11001011
;                   \__/wrxb         \_____/           \/ \/
;            fixed___/  \_/            |               |   \             
;                        |         sub immediate       rcx   rbx
;           64-bit operand ('W' bit set) 
;
;       c) 
;        10001001 00000101 10111001 00011111 00000000 000000000
;                                                                    fig. 3
;   -----------------------------------------------------------------------
;
;  The ModR/M byte
;            rbx := 011, r8 := 1000
;                           ____r8
;                          / \,__,__rbx
;           mov r8, rbx ; 11000011
;           mov rbx, r8 ; 11011000
;                   rbx____\/ \_/____r8 = src
;   i. Note on Quick Visualization of Binary with Python
;
;       # One off
;       ... data = "48 C7 C3 9A 02 00 00"
;       ... bytes = bytearray.fromhex((data))
;       ... [print(bin(bytes[i]), end=" ") for i in range(len(bytes))]
;       ...
;       # As a function
;       ... def bin_from_bytes(data):
;       ...   bytes = bytearray.fromhex(data)
;       ...   [print(bin(bytes[i]), end=" ") for i in range(len(bytes))]
;   
;                   III. Encryption Primitives                        
;  
;  Before the poly engine comes the encryption primitives. One mistake
;  I seem to have made is in seeking out to understand the concepts in
;  section I. without understanding how to perform the basic encryption
;  operations in assembler. I now see that I need to have some mastery
;  over that subject to move forward.
;
;  In [6, 8-9], the author 'MidNyte' discusses the fundamentals of 
;  encryption/enciphering in the context of the virus or poly engine.
;  In Part I, four x86 assembly techniques (or as I like to think of
;  them, 'primitives') are presented. In Part II, they then present
;  four methods of 'armouring' the encryption. These articles seem
;  to have everything necessary to understand the basics.
;
;  The four ciphers presented in [6] are the following:
;       - substitution
;       - sliding key
;       - long key
;       - transposition
;   
;  In [8], the following armoring techniques are presented:
;       - variable length transposition
;       - boundary scrambling
;       - integrity-dependent decryption
;       - date-dependent decryption
;
;  While they're important, I'm going to avoid the latter four
;  techniques for the time being as I'm trying to focus on the
;  basics.
;
;       ii. A Note on Generating Garbage and Simple Ciphers
;
;  Garbage code generation is still code generation. At that, the
;  quality of the garbage matters [10]. It is even suggested that
;  it is more worthwhile to use stronger and more complicated 
;  encryption than to add junk code at all [10]. Since generating
;  garbage does not seem reward the time investment at the moment,
;  I will revisit this later.
;
;  One contesting idea regarding this however is the benefits of
;  the sheer simplicity of XOR, ADD, and SUB ciphers. For example,
;  in [18] one of the most advanced cyber attacks in history, a s-
;  liding XOR cipher was employed to decent success. 

;                   V: Random Registers
; 
;  Now that we know what logical operations must be included and 
;  have an idea of how what bit-level characteristics each instru-
;  ction might have (fig 3.), the next fundamental characteristic
;  of the polymorphic engine to understand is the random selection
;  of registers. Take the following:
;
;                  [rax, rbx, rcx, rdx, rdi, rsi]
;
;  To get a random register from this list, one need only to gene-
;  rate a random number in the range and use it as an index. This
;  is a good starting point for the discussion on randomness in
;  general. Fortunately for the poly-engine author, there are so-
;  me extremely simple algorithms that are 'good-enough' for now.
;  The following code is lifted straight from [16]:
;
;      __uint128_t g_lehmer64_state;
;      
;      uint64_t lehmer64() {
;        g_lehmer64_state *= 0xda942042e4dd58b5;
;        return g_lehmer64_state >> 64;
;      }
;
;  This could be implemented in asm as follows:
;   
;      get_lehmer:
;        mov     rax, rcx
;        mov     rcx, 0da942042e4dd58b5h
;        mul     rax, rcx
;        shr     rax, 64
;        ret
;
;  And after invocation, an index for a register can simply be
;  derivied by taking the generated random, shifting right 59 bits
;  (max value is now 0b11111 or 31 in base-10). From there, calc-
;  ulating the modulo 10. This should be sufficient for an index.
;  This is just my off-handed way of deriving a number within a
;  range from another larger number. I'm sure there's other and 
;  better ways to do it. In assembly:
;
;       get_rand_reg:
;         call  get_random
;         shr   rax, 59
;         xor   rdx, rdx
;         mov   rcx, 10
;         div   rcx
;         mov   rax, rcx
;
;  The above code has been adapted to be more general and can be
;  found in the source code below.
;
;  Given the time elapsed between this writing and the introduct-
;  ion of the RDRAND instruction, its a good bet that it will be
;  available in most target environments, however it is a magic
;  black box that in my opinion is better left untouched. 
;  Entropy can be collected in other ways. For future
;  reference, [17] is a good introduction to understanding and
;  calculating entropy.
;
;  The last bit to do is to go about shuffling the list of regi-
;  sters. The initial list can be described as follows:
;
;           [length_reg, source_reg, dest_reg, key_reg]
;
;                   VI. Generating Code
;
;  Finally, now that all of the pieces have been laid out, the
;  fun begins: generating code. To reiterate, the idea is to take
;  the implementation of the cipher and reconstruct it using code
;  that is logically equivalent, but different in encoding. Take 
;  the following: 
;
;  simple_substitution_cipher:                             ; Adapted from [6]
;      simple_substitution_cipher_setup:
;          mov     rcx, (offset virus_body_ends - offset virus_body) / 2
;                                                          ;  Calculate payload body size in words                         
;          mov     rbx, offset virus_body                                                                                                
;          mov     rsi, rbx                                ;  source = start of encrypted code                             
;          mov     rdi, rsi                                ;  destination = same as the source                             
;          mov     rbx, 029Ah                              ;  rbx = key                                                                                                                                              
;                                                                                                                          
;      simple_substitution_cipher_loop_begin:                                                                              
;          mov     ax, word ptr [rsi]                      ;  Essentially lodsw but better able to permutate
;          xor     ax, bx                                  ;  The fundamental cipher operation          
;          mov     word ptr [rsi], ax                            
;          ;  Notice the segment must be marked RWX to modify the code.
;          ;  Wouldn't it be cool if the permutated decryptor made a VirtualProtect
;          ;  call before executing the encryption operations?
;          inc     rsi
;          inc     rsi   
;          dec     rcx
;          test    rcx, rcx
;          jnz     simple_substitution_cipher_loop_begin    
;      simple_substitution_cipher_end:
;          ret
;
;  One way that this could be reconstucted to be logically equival-
;  ent but slightly different in encoding is by simply changing up
;  the registers. For example, the first instruction could be cha-
;  nged from:
;
;       mov rcx, (sizeof payload in words (immediate value))
;       mov rdx, (sizeof payload in words (immediate value))
;  
;  This is exactly what a lot of 'poly' engines do, but it is 
;  really a trivial change:
;
;       :  48 c7 c1 04 00 00 00    mov    rcx,0x4 ; version a - assume the payload is only 4 bytes long
;       :  48 c7 c2 04 00 00 00    mov    rdx,0x4 ; version b
;
;  And if we were to do the same simple operation for the first
;  two lines, they would look like this:
;
;       :  48 c7 c1 04 00 00 00    mov    rcx,0x4 \__ version a
;       :  48 c7 c3 00 ?? ?? ??    mov    rbx,0x0 /
;       :  48 c7 c2 04 00 00 00    mov    rdx,0x4 \__ version b
;       :  48 c7 c0 00 ?? ?? ??    mov    rax,0x0 /
;
;  A malware analyst would just look at this and write something
;  like this to identify the binary pattern:
;
;       2 ( 48 c7 c? ?? 00 00 00 )
; 
;  This is a simplified example, but apply the concept to the rest
;  of the code. Register permutation is not nearly enough. That b-
;  eing said, what other parts of this could we permutate? One go-
;  od starting place would be adding the capability to the engine
;  to generate instructions that use different addressing modes.
;  For example, if we were to permute the first two lines as such:
;
;       mov rcx, 4 -> mov ax, 4
;
;  The resulting bytecode changes much more dramatically:
;
;       :  48 c7 c1 04 00 00 00    mov    rcx,0x4
;       :  66 b8 04 00             mov    ax,0x4 
;
;  But making this dramatic of a change has two consequences: first,
;  the code now only addresses the low 16 bits of RAX. Any bits set
;  n the upper portions of the register will be erroneously operat-
;  ed on if the RAX register is used anywhere else. Dealing with 
;  this is simple enough - just make sure to continue using AX ins-
;  tead of rcx. The second consequence is, however, is more problematic;
;  the overall size of the decryptor has changed. If not dealt with,
;  this will destroy the ability of labels to describe the code's
;  logical components correctly. I can envision a couple of ways of
;  dealing with this. One is to simply keep track of changes in 
;  the size to different parts of the decryptor stub and fixup 
;  any jump locations accordingly. The other is to track the change
;  in bytes between sections of the code and insert junk code. Each
;  has its pros and cons.
; 
;  Either solution will take some engineering to accomplish. Regard-
;  less, the binary representation of the code is now completely 
;  different. Still, there are more advanced ways to permutate these
;  instructions. For example, instead of moving an immediate into
;  the destination register, an immediate could be loaded into
;  the another register and then moved into the target destination
;  register. But for now, simply changing the register mode should
;  be enough.
;
;  With a concept for permutating individual instructions in hand,
;  we can go about describing the actual logic of the decryptor. 
;  The initial ideas for this came from [11].
;
;  First, in English:
;
;   1. Set the length register to the size of the code
;   2. Set the source register to the start of the payload code
;       (destination is the same as the source, so in the simplest
;       case, just use that single register for both loading and storing)
;   3. Set the key register to the value of the key
;   4. Set the encryption register to the value of the data pointed to by 
;       the source register
;   5. Perform the encryption/decryption operation
;   6. Store the result of the encryption operation at the address held in
;       the source register
;   7. Increment the source register by the size of the data to enc/decrypt
;   8. Decrement the length register by the size of the data that was
;       encrypted/decrypted. 
;   9. Return to four if the length register is greater than zero
;   10. Return from subroutine
;
;  This is a much more general description of the code than the code 
;  itself. Notice that while this description condenses thirteen
;  lines into ten and generalizes the registers that are used for
;  specific operations, it is still logically eqivalent to the actual
;  impleentation. The actual x86_64 register opcodes that are used
;  can be interchanged, the size of the encryption operand is gener-
;  alized, and the method of testing the counter and jumping is also
;  generalzied. Finally, the encryption operation is generalized.
;
;  Another way we can generalize the cipher stub is to break it down
;  by dependency. For example, 1-3 can be performed in any order, 
;  4. must come after 1-3 and before 5-7 (aka it cannot be moved), 
;  5. must precede 6., 7 must follow 6, and 8. can be placed either
;  before or after 4., depending on where the jump label is set.
;  9. cannot be moved; 10. also cannot be moved.
;
;   In a list form 
;   -----------------------------------------------------------------------
;      decrypt proc near  
;        1) can be placed anywhere before 4
;        2) can be placed anywhere before 4
;        3) can be placed anywhere before 5
;        4) cannot be moved
;        5) must precede 6
;        6) anywhere after 5 and before 7
;        7) anywhere after 7
;        8) anywhere after jump target around 4
;        9) cannot be moved
;   -----------------------------------------------------------------------
;
;  In this list, the symbols 1-9 dont necessarilly indicate 
;  anything other than the logical operation, so to make 
;  this list less confusing we can just replace those symbols
;
;   -----------------------------------------------------------------------
;       data -> the offset of the data to perform the encryption on
;     decrypt proc near
;       sl -> set length register; can be placed anywhere before lod
;       ss -> set source register; can be placed anywhere before lod
;       sk -> set the key register; can be placed anywhere before enc
;       lod -> set encryption register to the data to encrypt; not permutable
;       enc -> perform the encryption operation; must proceed lod and preceed stor
;       stor -> set the memory refernced by ss to result of enc; must prceed enc and precede sinc
;       sdelta -> set source register new offset of source; must proceed stor
;       ldelta -> set the length register to the new offset of source; can be placed anywhere around 4
;       jnext -> jump to lod if not finished
;       fin -> return or continue to separate logic block
;
;  By assigning these symbols to each logical instruction, we can
;  pick out some interesting characteristics of the algorithm. First,
;  while the actions of sl and ss must precede lod, the data to describe
;  these actions need not precede the lod instruction. The second
;  is that there is an important relationship between sdelta nd ldelta;
;  anytime the first changes, the other must also change. Therefore
;  it does not matter if sdelta == ldelta or whether sdelta ~ ldelta.
;  This means that we can simplify sdelta and ldelta to cdelta,
;  meaning the change in value with respect to either the source
;  beginning or end. Finally, generalizing the test + jmp to jnext
;  allows us to think about the comparison operation independent 
;  of whether we're interpreting cdelta as sdelta == ldelta.
;  Since we have simplified sdelta and ldelta to cdelta, we can
;  imagine that the expression jnext is dependent on the expression
;  of cdelta.

;  At this point, we have the following information:
;       
;     - what operations are included in the cipher,
;     - their dependencies to each other,
;     - the relationship between the source register and the length
;       register
;     - the relationship between cdelta and jnext                 
;
;  In terms of actual code, we can represent the operations as
;  a matrix of bytes just as in [11] and can code our permutation
;  to mutate with respect to dependencies:
;                                    ___ after stor.   ____ not perm.
;  default)                         /                 /
;     [1,  2,  3,  4,   5,   6,    7,      8,      9,     10]
;     [sl, ss, sk, lod, enc, stor, sdelta, ldelta, jnext, fin]
;      \_______/    \_   \______ \_________    \______      \_____
;         |           \         \          \          \           \
; permutable   not perm.    before stor  after enc   after lod   not perm.
;
;  permutation a)
;     [ss, sl, sk, lod, ldelta, enc, stor, sdelta, jnext, fin]
;
;  permutation b)
;     [sk, sl, ss, lod, ldelta, enc, stor, sdelta, jnex, fin]
;
;  The engine will create a matrix of bytes with random orders
;  of values (except for the impermutable enc, jnext, and fin).
;  The algorithm is something like this (in this case we'll
;  revert to notating them by number):
;
;    1) create a variable that will hold the matrix of bytes
;    2) set the impermutable indexes to themselves
;    3) in a loop, fill in the first three (or four, depending
;       on where you're decrementing lreg) in a random order
;    4) call the code generation routine for each routine in 
;       the order
;
;  Just as in [11], this general description of the algorithm with 
;  permutation rules can be used to "make a matrix of bytes". In
;  this case, since the algorithm is slightly different. We can n-
;  ow describe permutations of the same algorithm that are logica-
;  lly equivalent but different in signature, for example:
;
;   matrix a)
;       permutation: [4, 1, 2, 3, 5, 6, 8, 9, 7, 10, 11, 12]
;       place:       [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
;
;   matrix b)
;       permutation: [3, 1, 2, 4, 5, 6, 7, 10, 8, 9, 11, 12]
;       place:       [1, 2, 3, 4, 5, 6, 7, 8,  9, 10, 11, 12]
;

;
;  References:
;   [1] https://vx-underground.org/archive/VxHeaven/lib/vbb01.html
;   [2] https://vx-underground.org/archive/VxHeaven/lib/vda01.html
;   [3] https://paul.bone.id.au/blog/2018/09/05/x86-addressing/
;   [4] https://www.agner.org/optimize/instruction_tables.pdf
;   [5] http://ref.x86asm.net/coder64.html
;   [6] https://vx-underground.org/archive/VxHeaven/lib/vmn04.html
;   [7] https://harrisonwl.github.io/assets/courses/malware/spring2017/slides/FinalWeeks/EncryptedOligomorphic.pdf
;   [8] https://vx-underground.org/archive/VxHeaven/lib/vmn05.html
;   [9] https://vx-underground.org/archive/VxHeaven/lib/vmn06.html
;   [10] https://vx-underground.org/archive/VxHeaven/lib/vts01.html
;   [11] https://vx-underground.org/archive/VxHeaven/lib/vlj04.html
;   [12] https://software.intel.com/content/www/us/en/develop/download/intel-64-and-ia-32-architectures-sdm-combined-volumes-1-2a-2b-2c-2d-3a-3b-3c-3d-and-4.html
;   [13] https://wiki.osdev.org/X86-64_Instruction_Encoding
;   [14] http://www.c-jump.com/CIS77/CPU/x86/X77_0060_mod_reg_r_m_byte.htm
;   [15] https://github.com/vxunderground/MalwareSourceCode/blob/6919f569b56cdbf91fad247753571673b1eac083/LegacyWindows/Win98/Win98.BlackBat.asm
;   [16] https://lemire.me/blog/2019/03/19/the-fastest-conventional-random-number-generator-that-can-pass-big-crush/
;   [17] https://machinelearningmasteyr.com/what-is-informatin-entropy
;   [18] https://vxug.fakedoma.in/samples/Exotic/UNC2452/SolarWinds%20Breach/
;   [19] https://github.com/vxunderground/MalwareSourceCode/blob/6919f569b56cdbf91fad247753571673b1eac083/LegacyWindows/Win98/Win98.BlackBat.asm
;
;  Not directly related but still relevant:
;   [i] https://github.com/Battelle/sandsifter
;   [ii] https://en.wikipedia.org/wiki/Hexspeak#Notable_magic_numbers

option win64:3      ; init shadow space, reserve stack at PROC level

include .\polytest.inc
;-----------------------------------------------------------------------------
;  Operating Mode Constants, Structs, and Macros
;-----------------------------------------------------------------------------

; Constants
; 
ENC_CIPHER_XOR              EQU 0
ENC_CIPHER_XOR_SLIDING      EQU 1
ENC_CIPHER_XOR_LONG_KEY     EQU 2

; Structs
;
REG_TABLE struct
    source_reg BYTE REG_AX
    dest_reg   BYTE REG_BX
    length_reg BYTE REG_CX
    key_reg    BYTE REG_DX
    base_reg   BYTE REG_SP
    junk_reg_1 BYTE REG_BP
    junk_reg_2 BYTE REG_SI
    junk_reg_3 BYTE REG_DI
REG_TABLE ends

; Macros
;

; Get the current instruction pointer [19]
GET_DELTA macro reg:REQ
    local   GetIP
    call    GetIP
GetIP:
    pop     reg
    sub     reg, offset GetIP
endm

; Get the true offset of the specified address [19]
GET_OFFSET macro reg:REQ, expr:REQ
    local   GetIP
    call    GetIP
GetIP:
    pop     reg 
    add     reg, offset expr - offset GetIP
endm

DATA$00 SEGMENT PAGE 'DATA'

DATA$00 ENDS

TEXT$00 SEGMENT ALIGN(10h) 'CODE' READ WRITE EXECUTE

    Main PROC	
        call TransformCipher
        ret
    Main ENDP

virus_body:
;-----------------------------------------------------------------------------
;  Poly Engine
;-----------------------------------------------------------------------------

    TransformCipher PROC   
        local   dwCipherIndex:DWORD          
        local   qwCipherStart:QWORD
        local   qwCipherEnd:QWORD
        local   dwCipherLen:DWORD
        local   RegTable:REG_TABLE
        local   SkeletonTable:SKELETON_TABLE
        mov     rcx, 2                                  ;  
        call    get_rand_from_range                     ;  Get a random number in the range
        call    get_rand_reg_2  

        mov     rax, offset simple_substitution_cipher
        mov     qwCipherStart, rbx
        mov     rbx, offset simple_substitution_cipher_end
        mov     qwCipherEnd, rbx
        sub     rbx, rax
        mov     dwCipherLen, ebx

        ;  Get the first random register
        call    get_rand_reg

        

    _regenerate_end:
        ret
    TransformCipher ENDP
;-----------------------------------------------------------------------------
;  Encryption Primitives
;-----------------------------------------------------------------------------
    
;  Simple substition encryptor [6]
;
simple_substitution_cipher:
    simple_substitution_cipher_setup:
        mov     rcx, (offset virus_body_ends - offset virus_body) / 2
                                                        ;  Calculate payload body size in words                         
        mov     rbx, offset virus_body                                                                                                
        mov     rsi, rbx                                ;  source = start of encrypted code                             
        mov     rdi, rsi                                ;  destination = same as the source                             
        mov     rbx, 029Ah                              ;  rbx = key                                                                                                                                              
                                                                                                                        
    simple_substitution_cipher_loop_begin:                                                                              
        mov     ax, word ptr [rsi]                      ;  Essentially lodsw but better able to permutate
        ;inc     rsi
        ;inc     rsi         
        xor     ax, bx                                  ;  The fundamental cipher operation          
        mov     word ptr [rsi], ax                      ;  Could also be RDI  
        inc     rsi
        inc     rsi      
        ;  Notice the segment must be marked RWX to modify the code.
        ;  Wouldn't it be cool if the permutated decryptor made a VirtualProtect
        ;  call before executing the encryption operations?
        dec     rcx
        test    rcx, rcx
        jnz     simple_substitution_cipher_loop_begin    
    simple_substitution_cipher_end:
        ret

;   Sliding key cipher [6]
;
sliding_key_cipher:
    sliding_key_cipher_setup:
        mov     rcx, (offset virus_body_ends - offset virus_body) / 2
        mov     rbx, offset virus_body
        mov     rsi, rbx                                ;  source = start of encrypted code
        mov     rdi, rsi                                ;  destination = same as source
        mov     rbx, 02828h                             ;  bx = decryption key
    sliding_key_cipher_loop_begin:
        lodsw                                           ;  MOV's word from [si] to ax, and increases si by 2
        xor     rax, rbx                                ;  The actual decryption
        inc     rbx                                     ;  Increment the loop
        stosw                                           ;  MOV's word from ax to [di], and increases rdi by 2
        loop    sliding_key_cipher_loop_begin           ;  DEC's cx, and jumps to looop head if CX > 0
    sliding_key_cipher_end:
        ret

;   Long key encryption [6]
;
long_key_cipher:
    long_key_cipher_setup:
        mov     rbx, offset virus_body
        mov     rcx, offset virus_body_ends
        sub     rcx, rbx
        shr     cx, 1                                   ;  Calculate payload body size in words 

        mov     rsi, rbx                                ;  source = start of the encrypted code
        mov     rdi, rsi                                ;  dest = same as source
        mov     rbx, offset long_key                    ;  bx = key indexing register
        mov     rdx, long_key_ends - long_key           ;  Length of key (even sized key)

    long_key_cipher_loop_begin:
        lodsw                                           ;  MOV's the word from [si] to ax, and increases si by 2
        xor     rax, [rbx]                              ;  The actual cryption
        add     rbx, 2                                  ;  Moves the key register to the next word in the key
        cmp     bx, dx                                  ;  Compare index to key length
        jb      long_key_cipher_loop_next               ;  Skip next instruction if not yet reached

    long_key_cipher_loop_next:
        stosw                                           ;  MOV's word from ax to [di], and increases di by 2
        loop    long_key_cipher_loop_begin              ;  DEC'c cx, and jumpts to start_loop if CX > 0

    long_key_cipher_loop_end:
        ret    

    long_key:
        dq      0FEADDEADBEEFh
    long_key_ends:

;   Transposition (Order) Encryption [6] (TODO: Make this work)
;
transposition_cipher:
    transposition_cipher_setup:
        mov     rcx, (offset virus_body_ends - offset virus_body) / 2
        mov     rsi, offset virus_body                ;  source = start of encrypted code
        mov     rdi, rsi                                ;  dest = same as source

    transposition_cipher_loop_start:
        lodsw                                           ;  Load first word from source
        mov     bx, ax                                  ;  Stores first word in bx
        lodsw                                           ;  Loads second word from source
        stosw                                           ;  Puts the second word into the first word's place in dest
        mov     ax, bx                                  ;  Restores first word from bx to ax
        stosw                                           ;  Puts first word in second word's place in dset
        loop transposition_cipher_loop_start            ;  Decrements cx and jumps to loop head if cx > 0

    transposition_cipher_loop_end:
        ret

;  Get random seed
;
get_rand_seed:
    mov     rax, 0FEEDDEADBEEFh                         ;  Just return a test seed for now
    ret


; qword get_lehmer64(ecx=lehmer_state);
;
; __uint128_t g_lehmer64_state;
; 
; uint64_t lehmer64() {
;   g_lehmer64_state *= 
;
;   return g_lehmer64_state >> 64;
; }
;
get_rand:
    mov     rax, rcx
    mov     rcx, 0da942042e4dd58b5h
    imul    rax, rcx
    shr     rax, 64
    ret

; Get a register index from a random uint64
;
get_rand_reg:
    mov     rcx, 7
    call    get_rand_from_range
    cmp     rax, 4
    je      get_rand_reg
    cmp     rax, 5
    je      get_rand_reg
    ret

get_rand_reg_2:
    call  get_rand
    shr   rax, 59
    xor   rdx, rdx
    mov   rcx, 10
    div   rcx
    mov   rax, rcx

; Get a random number from a range
; uint64 RandFromRange(rcx=max)
get_rand_from_range:
    push    rcx                                        ;  Store the max value
    call    get_rand_seed                              ;  Get a uint64 seed
    mov     rcx, rax                                   ;  Move the seed to param_1
    call    get_rand                                   ;  Get a random uint6
_rand_range_loop:
    shr     rcx, 1                                     ;  Remove one bit place
    test    rcx, rcx                                   ;  Did that shift zero it?
    jnz     _rand_range_loop                           ;  No, there's more data. 
    mov     r8, 64                                     ;  Max number of places
    sub     r8, rcx                                    ;  Subtract our number of places
    xchg    r8, rcx
    shr     rax, cl                                    ;  Shift the random down into our range
    pop     rcx                                        ;  Get the max value back
    xor     rdx, rdx                                   ;  Clear for division
    div     rcx                                        ;  Get the random's representation within the max value by modulo
    mov     rax, rcx                                   ;  
    ret                                                ;

;-----------------------------------------------------------------------------
;  Payload Code
;-----------------------------------------------------------------------------

virus_body_ends:

TEXT$00 ENDS

END
