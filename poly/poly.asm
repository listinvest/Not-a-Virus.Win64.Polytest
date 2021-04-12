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
;          0th generation code. The generation function doesn't change 
;          the order of semantic operations. If it were to, it would also
;          need to maintain awareness of the positional dependencies of
;          each operation.
;
;       To facilitate this meta-awareness of the 0th generation code, this
;       program makes use of data structures describing the original
;       cipher. They are the following:
;   
;       a. Registers Table: a table of registers, where each
;          position indicates a semantic purpose in the original cipher.
;       c. Register Index Table: a table of indexes into the actual 
;          Registers Table.
;       c. Skeleton Instruction Table: a table containing opcodes and
;          other information needed to generate valid instructions.
;       
;       To achieve the purposes of the algorithm in a clear way, the 
;       engine makes use of the following functions:
;   
;       f. ShuffleRegisterTable: given a register table index data
;          structure, create a random ordering of phyiscal registers
;       j. RandRange: Get a random number in a specific range.
;
;   Notes:
;
;       - In many cases simplicity is favored over completeness
;
;   References:
;       [1] http://www.terraspace.co.uk/uasm248_ext.pdf
;       [2] https://bit.ly/39q4vyj
;       [3] https://vx-underground.org/archive/VxHeaven/lib/vmn04.html
;
option win64:0x08   ; init shadow space, reserve stack at PROC level

include .\poly.inc

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
poly_begin:
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
        xor     rbx, rbx                    ; byte index
    permute_op0:
        lea     rcx, offset simple_substitution_cipher
        mov     edx, (offset poly_end - offset poly_begin) / 2 
        lea     r8, regTable
        mov     r8d, [r8].REG_TABLE.LengthReg
        call    GenMovImm64

    permute_op1:
        add     ebx, eax                    ; Add the address offset of the modified code
        mov     rcx, offset simple_substitution_cipher
        add     rcx, rbx                    ; Move to the next offset of the cipher
        mov     edx, offset poly_begin      ; Pass the immediate to encode
        lea     r8, regTable                ; Get the regTable
        mov     r8d, [r8].REG_TABLE.SourceReg
                                            ; Get the source register index from regTable
        call    GenMovImm64                 ; Generate a MOV instruction at the target
        add     ebx, eax                    ; Add the offset to the offset counter
        mov     rcx, simple_substitution_cipher
        add     rcx, rbx                    ; Get the next offset to generate at
        lea     rdx, regTable               ; Get pointer to regTable
        mov     r8d, [rdx].REG_TABLE.DestReg
                                            ; Get dest register index in r8d
        mov     edx, [rdx].REG_TABLE.SourceReg
                                            ; Get source register index in edx
        call    GenMovReg64                 ; Generate a MOV instruction for Src/Dst

    permute_op2:
        add     ebx, eax                    ; Add the offset to the offset counter
        mov     rcx, simple_substitution_cipher
        add     rcx, rbx                    ; Get the next offset to generate at
        lea     rdx, regTable               ; Get pointer to regTable
        mov     r8d, [rdx].REG_TABLE.KeyReg
                                            ; Get dest register index in r8d
        mov     edx, [rdx].REG_TABLE.SourceReg
                                            ; Get source register index in edx
        mov     r9, 3
        ; fastcall GenXor(rcx=address, edx=src_index, r8d=dest_index, r9=variant);
        call    GenXor                      ; Generate a MOV instruction for Src/Dst

        add     ebx, eax                                   
    epilog:
        call    simple_substitution_cipher
        pop     rsi
        pop     rbx
        ret
    PermutationEngine ENDP

    ; fastcall GenMov32(rcx=address, edx=value, r8d=index)
    GenMovImm32 PROC
        push    rbx
        mov     al, byte ptr s_mov_reg
                                            ; Load the opcode into al
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
        mov     al, byte ptr s_rex_prefix
        mov     byte ptr [rcx], al          ; Set the REX prefix at address + 0
        mov     al, byte ptr s_mov64_imm
        mov     byte ptr [rcx + 1], al      ; Set the MOV opcode at address + 1
        mov     al, byte ptr s_modrm        ; Get a Mod/RM byte
        lea     rbx, offset s_regtable        
        or      al, byte ptr [rbx + r8]     ; OR the Mod RM byte with the proper register
        mov     byte ptr [rcx + 2], al      ; Set the Mod/RM byte at address + 2
        mov     dword ptr [rcx + 3], edx    ; Set the immediate value at address + 3
        pop     rbx
        mov     eax, 7
        ret
    GenMovImm64 ENDP

    ; fastcall GenMovReg32(rcx=address, rdx=src_index, r8=dest_index)
    GenMovReg32 PROC
        push    rbx
        mov     al, byte ptr s_mov_reg      ; Set al to 0x89
        mov     byte ptr [rcx], al          ; Set the opcode
        mov     al, byte ptr s_modrm        ; Get the modrm default byte
        lea     rbx, offset s_regtable      ; Get the register value table
        mov     bl, byte ptr [rbx + r8]     ; Get the dest register encoding by index
        shl     bl, 3                       ; Shift the dest into the dest bits of mod/rm
        or      al, bl                      ; OR the dest into the mod/rm variable
        lea     rbx, offset s_regtable      ; Get the register value table again
        mov     bl, byte ptr [rbx + rdx]    ; Get the source by index
        or      al, bl                      ; OR the source into the Mod/RM
        mov     byte ptr [rcx + 1], al      ; Set the newly generated Mod/RM byte
        mov     eax, 2                      ; This operation wrote two bytes
        pop     rbx                 
        ret
    GenMovReg32 ENDP

    ; fastcall GenMovReg32(rcx=address, rdx=src_index, r8=dest_index)
    GenMovReg64 PROC
        mov     al, byte ptr s_rex_prefix   ; Get the REX prefix value
        mov     byte ptr [rcx], al          ; Set the REX prefix
        inc     rcx                         ; Increment RCX for function call
        call    GenMovReg32                 ; Generate the MOV instruction
        inc     eax                         ; Count the REX prefix            
        ret
    GenMovReg64 ENDP

    ; fastcall GenMovRegPtr32(rcx=address, rdx=src_index, r8=dest_index, r9=bool_direction)
    GenMovRegPtr32 PROC
        push    rbx
        test    r9, r9
        jz     _dir_mov_src_mem
    _dir_mov_dest_mem:                      ; r9 = 1
        mov     al, byte ptr s_mov_reg      ; Set al to 0x89
        jmp     _set_opcode
    _dir_mov_src_mem:                       ; r9 = 0
        mov     al, byte ptr s_mov_reg      ; Set al to 0x8B
    _set_opcode:
        mov     byte ptr [rcx], al          ; Set the opcode
        xor     eax, eax                    ; Clear the second byte of instruction
        lea     rbx, offset s_regtable      ; Get the register value table
        mov     bl, byte ptr [rbx + r8]     ; Get the dest register encoding by index
        shl     bl, 3                       ; Shift the dest into the dest bits of mod/rm
        or      al, bl                      ; OR the dest into the mod/rm variable
        lea     rbx, offset s_regtable      ; Get the register value table again
        mov     bl, byte ptr [rbx + rdx]    ; Get the source by index
        or      al, bl                      ; OR the source into the Mod/RM
        mov     byte ptr [rcx + 1], al      ; Set the newly generated Mod/RM byte
        mov     eax, 2                      ; This operation wrote two bytes
        pop     rbx                 
        ret
    GenMovRegPtr32 ENDP

    ; fastcall GenMovRegPtr32(rcx=address, rdx=src_index, r8=dest_index, r9=bool_direction)
    GenMovRegPtr64 PROC
        mov     al, byte ptr s_rex_prefix   ; Get the REX prefix value
        mov     byte ptr [rcx], al          ; Set the REX prefix
        inc     rcx                         ; Increment RCX for function call
        call    GenMovRegPtr32              ; Invoke the code generator for the MOV
        inc     eax                         ; Count the added REX prefix
        ret
    GenMovRegPtr64 ENDP

    ; fastcall GenMovReg32(rcx=address, rdx=src_index, r8=dest_index)
    GenMovReg16 PROC
        mov     al, byte ptr s_16b_prefix   ; Get the 16-bit mode prefix
        mov     byte ptr [rcx], al          ; Set the mode prefix
        inc     rcx                         ; Move address pointer to next byte
        call    GenMovReg32                 ; Generate the MOV
        inc     eax                         ; Count the added prefix
        ret
    GenMovReg16 ENDP

    ; fastcall GenMovRegPtr16(rcx=address, rdx=src_index, r8=dest_index, r9=bool_direction)
    GenMovRegPtr16 PROC
        mov     al, byte ptr s_16b_prefix   ; Get the 16-bit mode prefix
        mov     byte ptr [rcx], al          ; Set the mode prefix
        inc     rcx                         ; Move address pointer to next byte
        call    GenMovRegPtr32              ; Gen the MOV
        Inc     eax                         ; Count the added prefix
    GenMovRegPtr16 ENDP

    ; fastcall GenMovRegPtr8(rcx=address, rdx=src_index, r8=dest_index)
    GenMovReg8 PROC
        mov     al, byte ptr s_8b_prefix    ; Get the 16-bit mode prefix
        mov     byte ptr [rcx], al          ; Set the mode prefix
        inc     rcx                         ; Move address pointer to next byte
        call    GenMovReg32                 ; Generate the MOV
        inc     eax                         ; Count the added prefix
        ret
    GenMovReg8 ENDP

    ; fastcall GenMovRegPtr8(rcx=address, rdx=src_index, r8=dest_index, r9=bool_direction)
    GenMovRegPtr8 PROC
        mov     al, byte ptr s_8b_prefix    ; Get the 16-bit mode prefix
        mov     byte ptr [rcx], al          ; Set the mode prefix
        inc     rcx                         ; Move address pointer to next byte
        call    GenMovRegPtr32              ; Gen the MOV
        inc     eax                         ; Count the added prefix
        ret
    GenMovRegPtr8 ENDP

    ; fastcall GenPushReg(rcx=address, edx=reg_index)
    GenPushReg PROC
        push    rbx         
        lea     rax, offset s_push_reg      ; Get the PUSH opcode
        lea     rbx, offset s_regtable      ; Get the regtable offset
        or      al, byte ptr [rbx + rdx]    ; Or the the push opcode with [regtable + index]
        mov     byte ptr [rcx], al          ; Overwrite the original byte        
        pop     rbx             
        inc     eax                         ; Count the added prefix
        ret
    GenPushReg ENDP

    ; fastcall GenPushReg(rcx=address, edx=reg_index)
    GenPopReg PROC
        push    rbx         
        lea     rax, offset s_pop_reg       ; Get the POP opcode
        lea     rbx, offset s_regtable      ; Get the regtable offset
        or      al, byte ptr [rbx + rdx]    ; Or the the POP opcode with [regtable + index]
        mov     byte ptr [rcx], al          ; Overwrite the original byte        
        pop     rbx
        mov     eax, 1
        ret
    GenPopReg ENDP

    ; fastcall GenXor(rcx=address, edx=src_index, r8d=dest_index, r9=variant);
    ;   r9=0 -> gen 32 bit XOR
    ;   r9=1 -> gen 64 bit XOR
    ;   r9=2 -> gen 16 bit XOR 
    ;   r9=3 -> gen 8 bit XOR
    GenXor PROC
        push    rbx
        test    r9, r9
        jz      xor_32
        cmp     r9, 1
        je      xor_64
        cmp     r9, 2
        je      xor_8
    xor_16:
        mov     al, byte ptr s_16b_prefix   ;
        mov     byte ptr [rcx], al          ; Set the 16-bit prefix
        mov     rax, 1                      ; Set the XOR mode to add to 0x31
        push    rax                         ; Save the byte count
        inc     rcx                         ; Set the pointer to the next byte to write
        jmp     xor_32                      ; Jump to the standard routine
    xor_8:
        xor     rax, rax                    ; Clear RAX so that the count is correct
        push    rax                         ; Save the byte count
        jmp     xor_32                      ; 8 bits is easy for XOR
    xor_64:
        mov     al, byte ptr s_rex_prefix   ;
        mov     byte ptr [rcx], al          ; Set the REX prefix
        mov     rax, 1                      ; Set XOR mode to add to 0x31
        push    rax                         ; Save this number of bytes written for later
        inc     rcx
    xor_32:
        add     al, byte ptr s_xor_reg      ; Add 0x30. This will account for bits set in other modes
        mov     byte ptr [rcx], al          ; Set the opcode
        mov     al, byte ptr s_modrm        ; Get the MOD/RM default byte
        lea     rbx, offset s_regtable
        mov     bl, byte ptr [rbx + r8]     ; Get the dest register encoding by index
        shl     bl, 3                       ; Shift the dest reg into the dest bits of MOD/RM
        or      al, bl                      ; OR the dest into the MOD?RM
        lea     rbx, offset s_regtable      ; Get the register value table again
        mov     bl, byte ptr [rbx + rdx]    ; Get the source by index
        or      al, bl                      ; OR the source into MOD/RM
        mov     byte ptr [rcx + 1], al      ; Set the new MOD/RM byte
        pop     rax                         ; Get the byte count
        add     eax, 2                      ; Add the count of bytes just written
        pop     rbx
        ret
    GenXor ENDP
    
; b. Skeleton instruction table is implemented as a binary blob
;    in the code section
stable_begin:
    s_modrm:
        db 11000000b    ; 0xC0 Mod/RM byte. Least significant bits are dest in reg mode
    s_rex_prefix:
        db 01001000b    ; 0x48 REX prefix
    s_16b_prefix:
        db 01100110b    ; 0x66 16-bit addressing prefix
    s_8b_prefix:
        db 10001000b    ; 0x88 8-bit addressing prefix
    s_mov64_imm:
        db 11000111b    ; 0xC7 ( +4 bytes for imm)
    s_mov_reg:
        db 10001001b    ; 0x89 ( +1 byte for mem/reg), works for 32 and 64 bit. 
                        ; Add REX for 64 bit. Inc Mod/RM to iterate through regs
    s_mov_rmem:
        db 10001011b;   ; 0x8B ( +1 byte for register code)
    s_mov32_imm:
        db 10111000b    ; 0xB8 ( +4 bytes for imm)
    s_push_reg:
        db 01001000b    ; 0x50 (PUSH reg)
    s_push_imm:
        db 01101010b    ; 0x6A (PUSH imm)
    s_pop_reg:
        db 01011000b    ; 0x58 (POP reg)
    s_xor_reg:
        db 00110000b    ; 0x30 (XOR). For 16 bit, add 16-bit prefix and inc 0x30.

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
poly_end:

    ; semantic description of cipher
    ; 1. Set the length register to the size of the code
    ; 2. Set the source register to the start of the payload code
    ; 3. Set the key register to the value of the key
    ; 4. Load data for encryption operation
    ; 5. Perform encryption operation
    ; 6. Store the result of the encryption operation
    ; 7. Increment the source register of the cipher operation size
    ; 8. Decrement the length register by the cipher operation size
    ; 9. Return to four if the length register is not zero
    simple_substitution_cipher:
        mov     rcx, (offset poly_end - offset poly_begin) / 2 
                                                            ;  op0. Calculate payload body size in words                         
        mov     rbx, offset poly_begin                       ;  op1  Set source register. Source = start of encrypted code                                                                  
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