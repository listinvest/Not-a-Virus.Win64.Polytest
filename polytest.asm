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
;
;                   IV. Permuting the Decryptor
;
;  [11] Provides a notation and description for a decryption algor-
;  ithm very similar to the ones provided by [6]. The following is
;  an adaptation of the described algorithm and the permutation ru-
;  les provided:
;
;   -----------------------------------------------------------------------
;     decrypt proc near
;       1)  mov length_register, length         ; get the code length       
;       2)  mov pointer_register, startcode     ; load pointer register     
;       3)  mov destination_register, startcode ; load the destination reg. 
;       4)  mov key_register, key               ; get the key               
;     main_loop
;       5)  mov code_register, pointer_register ; take an encrypted word    
;       6)  call unscramble                     ; decrypt it (*)            
;       7)  mov destination_register, code_reg. ; write the decrypted word  
;       8)  add key_register, key_increment     ; increment the key         
;       9)  dec length_register                 ; decrement length          
;       10) inc pointer_register                ; increment pointer (x2)    
;       11) jnz main_loop                       ; loop until length=0       
;       12) ret                                 ; return pc                 
;     decrypt endp                                                  fig. 4
;   -----------------------------------------------------------------------
;       1) permutable, can be placed anywhere
;       2) permutable, can be placed anywhere
;       3) permutable, can be placed anywhere
;       4) permutable, can be placed anywhere
;       5) not permutable
;       6) not permutable
;       7) permutable, can be placed anywhere after [6]
;       8) permutable, can be placed anywhere after [6]
;       9) permutable, can be placed anywhere after [6]
;       10) permutable, can be placed anywhere after [6]
;       11) not permutable
;       12) not permutable                                          fig. 5                    
;   -----------------------------------------------------------------------
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
;                   V: Random Registers
; 
;  Now that we know what logical operations must be included and 
;  have an idea of how what bit-level characteristics each instru-
;  ction might have (fig 3.), the next fundamental characteristic
;  of the polymorphic engine to understand is the random selection
;  of registers.
;
;       [rax, rbx, rcx, rdx, r8, r9, r11, r12, r13, r14, r15]
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
;  This is just my off-handed way of deriving a number withing a
;  range from another larger number. I'm sure there's other and 
;  better ways to do it. In assembly:
;
;       get_rand_reg:
;         shr   rax, 59
;         xor   rdx, rdx
;         mov   rcx, 10
;         div   rcx
;         mov   rax, rcx
;
;  Given the time elapsed between this writing and the introduct-
;  ion of the RDRAND instruction, its a good bet that it will be
;  available in most target environments, however it is a magic
;  black box that in my opinion is better left untouched. 
;  Instead, entropy an be collected in other ways. For future
;  reference, [17] is a good introduction to understanding and
;  calculating entropy.
;
;            rbx := 011, r8 := 1000
;                           ____r8
;                          / \,__,__rbx
;           mov r8, rbx ; 11000011
;           mov rbx, r8 ; 11011000
;                   rbx____\/ \_/____r8 = src
;
;  The last bit to do is to go about shuffling the list of regi-
;  sters. The initial list can be described as follows:
;
;           [length_reg, source_reg, dest_reg, key_reg]
;
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
;
;  Not directly related but still relevant:
;   [i] https://github.com/Battelle/sandsifter
;   [ii] https://en.wikipedia.org/wiki/Hexspeak#Notable_magic_numbers

option win64:3      ; init shadow space, reserve stack at PROC level

;-----------------------------------------------------------------------------
;  Operating Mode Constants and Structs
;-----------------------------------------------------------------------------

ENC_CIPHER_XOR              EQU 0
ENC_CIPHER_XOR_SLIDING      EQU 1
ENC_CIPHER_XOR_LONG_KEY     EQU 2

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

;-----------------------------------------------------------------------------
;  Skeleton Opcode Table
;-----------------------------------------------------------------------------
; Notes:
;   - Registers encodings for r8-r15 operands not yet supported
;

; MOD (mode) encodings
;
MOD_REG     EQU 11000000b
MOD_DISP_4B EQU 10000000b
MOD_DISP_1B EQU 01000000b
MOD_REG_IND EQU 00000000b

; SIB (scale) encodings
;
SIB_SCALE_1 EQU 00000000b
SIB_SCALE_2 EQU 01000000b
SIB_SCALE_3 EQU 10000000b
SIB_SCALE_4 EQU 11000000b

; Register encodings
;
REG_AX EQU 00000000b
REG_BX EQU 00011000b
REG_CX EQU 00001000b
REG_DX EQU 00010000b
REG_SP EQU 00100000b
REG_BP EQU 00101000b
REG_DI EQU 00111000b
REG_SI EQU 00110000b

;  r/m16/32/64 operands
;               |SRCDST|
REG_AX_SRC EQU 00000000b
REG_BX_SRC EQU 00011000b
REG_CX_SRC EQU 00001000b
REG_DX_SRC EQU 00010000b
REG_SP_SRC EQU 00100000b
REG_BP_SRC EQU 00101000b
REG_DI_SRC EQU 00111000b
REG_SI_SRC EQU 00110000b

REG_AX_DST EQU 00000000b
REG_BX_DST EQU 00000011b
REG_CX_DST EQU 00000001b
REG_DX_DST EQU 00000010b
REG_SP_DST EQU 00000100b
REG_BP_DST EQU 00000101b
REG_SI_DST EQU 00000110b
REG_DI_DST EQU 00000111b

; REX byte for normal operations
;
REX_W       EQU 01001000b
REX_WB      EQU 01001001b

; Non-64 bit prefixes
;
PREFIX_OP_8  EQU 10001000b
PREFIX_OP_16 EQU 00010110b
PREFIX_OP_32 EQU 00101001b

; r8-r15 registers are encoded using a different REX prefix
; this should be implemented in later revisions

DATA$00 SEGMENT PAGE 'DATA'

DATA$00 ENDS

TEXT$00 SEGMENT ALIGN(10h) 'CODE' READ WRITE EXECUTE

    Main PROC	
        call    simple_substitution_cipher
        call    simple_substitution_cipher
        call    sliding_key_cipher
        call    sliding_key_cipher
        call    long_key_cipher
        call    long_key_cipher
        call    transposition_cipher
        call    transposition_cipher
        ret
    Main ENDP

;-----------------------------------------------------------------------------
;  Poly Engine
;-----------------------------------------------------------------------------

    Regenerate PROC
        ; Combining polymorphism and oligomorphism - get a random number to
        ; choose the cipher proc      
        local   dwCipherIndex:DWORD          
        local   qwCipherStart:QWORD
        local   qwCipherEnd:QWORD
        local   dwCipherLen:DWORD
        local   RegTable:REG_TABLE
        mov     rcx, 2                                  ;  Start with the more-simple ciphers
        call    get_rand_from_range                     ;  Get a random number in the range
        mov     [dwCipherIndex], eax                    ;  Save the index
        test    rax, rax                                ;  Is it 0?
        jz      _case_cipher_0
        cmp     rax, 1
        je      _case_cipher_1
        jmp     _case_cipher_2
    _case_cipher_0:
        mov     rax, offset simple_substitution_cipher
        mov     qwCipherStart, rbx
        mov     rbx, offset simple_substitution_cipher_end
        mov     qwCipherEnd, rbx
        sub     rbx, rax
        mov     dwCipherLen, ebx

        ; Initialize the members of RegTable to random values
        
    ; ToDo
    _case_cipher_1:
    jmp _regenerate_end

    ;ToDo
    _case_cipher_2:
    jmp _regenerate_end

    _regenerate_end:
        ret
    Regenerate ENDP
;-----------------------------------------------------------------------------
;  Encryption Primitives
;-----------------------------------------------------------------------------
    
;  Simple substition encryptor [6]
;
simple_substitution_cipher:
    simple_substitution_cipher_setup:
        mov     rcx, (offset payload_code_ends - offset payload_code) / 2
                                                        ;  Calculate payload body size in words                         
        mov     rbx, offset payload_code                                                                                                
        mov     rsi, rbx                                ;  source = start of encrypted code                             
        mov     rdi, rsi                                ;  destination = same as the source                             
        mov     rbx, 029Ah                              ;  rbx = key                                                                                                                                              
                                                                                                                        
    simple_substitution_cipher_loop_begin:                                                                              
        lodsw                                           ;  MOV's word from [si] to ax, and increases si by 2            
        xor     ax, bx                                  ;  The actual decryption                                        
        stosw                                           ;  MOV's word from ax to [di], and increases di by 2            
                                                        ;  Notice the segment must be marked RWX to modify the code     
        loop    simple_substitution_cipher_loop_begin   ;  DEC's cx, and jumps to start_loop if CX > 0                  
    simple_substitution_cipher_end:
        ret

;   Sliding key cipher [6]
;
sliding_key_cipher:
    sliding_key_cipher_setup:
        mov     rcx, (offset payload_code_ends - offset payload_code) / 2
        mov     rbx, offset payload_code
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
        mov     rbx, offset payload_code
        mov     rcx, offset payload_code_ends
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
        dq      0FEEDDEADBEEFh
    long_key_ends:

;   Transposition (Order) Encryption [6] (TODO: Make this work)
;
transposition_cipher:
    transposition_cipher_setup:
        mov     rcx, (offset payload_code_ends - offset payload_code) / 2
        mov     rsi, offset payload_code                ;  source = start of encrypted code
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

; Get a random number from a range
; uint64 RandFromRange(rcx=max)
get_rand_from_range:
    push    rcx                                        ;  Store the max value
    call    get_rand_seed                              ;  Get a uint64 seed
    mov     rcx, rax                                   ;  Move the seed to param_1
    call    get_rand                                   ;  Get a random uint64
    xor     rcx, rcx                                   ;  Create a counter
_rand_range_loop:
    shr     rcx, 1                                     ;  Remove one bit place
    inc     rcx                                        ;  Increment the counter
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

payload_code:
    mov     rax, 1
    ret
    nop

payload_code_ends:

TEXT$00 ENDS

END
