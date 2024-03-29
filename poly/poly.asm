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

;-- Macros --;

; Generate an opcode and Mod/RM byte for the given 
; label of an opcode
GenOpModRM MACRO opcode_label:REQ
    add     al, byte ptr opcode_label   ; Get the opcode
    mov     byte ptr [rcx], al          ; Set the opcode         
    mov     al, byte ptr s_modrm        ; Get the Mod/RM default byte
    lea     rbx, offset s_regtable      ; Get the ragister value table address
    mov     bl, byte ptr [rbx + r8]     ; Get the dest register encoding by index
    shl     bl, 3                       ; Shift the dest reg into the dest bits
    or      al, bl                      ; OR the dest into the MOD?RM
    lea     rbx, offset s_regtable      ; Get the register value table again
    mov     bl, byte ptr [rbx + rdx]    ; Get the source by index
    or      al, bl                      ; OR the source into Mod/RM
    mov     byte ptr [rcx + 1], al      ; Set the new Mod/RM byte
    pop     rax                         ; Get the byte count
    add     eax, 2                      ; Add the count of bytes just written
ENDM

; Generate an opcode and Mod/RM byte for ops that
; use only a src reg
GenOpModRMSourceReg MACRO opcode_label:REQ
    add     al, byte ptr opcode_label   ; Get the opcode
    mov     byte ptr [rcx], al          ; Set the opcode         
    mov     al, byte ptr s_modrm        ; Get the Mod/RM default byte
    lea     rbx, offset s_regtable      ; Get the register value table
    mov     bl, byte ptr [rbx + rdx]    ; Get the source by index
    or      al, bl                      ; OR the source into Mod/RM
    mov     byte ptr [rcx + 1], al      ; Set the new Mod/RM byte
    pop     rax                         ; Get the byte count
    add     eax, 2                      ; Add the count of bytes just written
ENDM

; Generate an opcode and Mod/RM byte for ops that
; use only a dst reg
GenOpModRMDestReg MACRO opcode_label:REQ
    add     al, byte ptr opcode_label   ; Get the opcode
    mov     byte ptr [rcx], al          ; Set the opcode         
    mov     al, byte ptr s_modrm        ; Get the Mod/RM default byte
    lea     rbx, offset s_regtable      ; Get the register value table
    mov     bl, byte ptr [rbx + rdx]    ; Get the dest register by index
    shl     bl, 3                       ; Shift the reg value into dest
    or      al, bl                      ; OR the source into Mod/RM
    mov     byte ptr [rcx + 1], al      ; Set the new Mod/RM byte
    pop     rax                         ; Get the byte count
    add     eax, 2                      ; Add the count of bytes just written
ENDM

; Same as GenOpModRM, except instead of adding a Mod/RM byte,
; use an empty byte where addressing modes are needed
GenOpAddress MACRO opcode_label:REQ
        add     al, byte ptr opcode_label   ; Add 0x88 to the previously set mode
        mov     byte ptr [rcx], al          ; Set the opcode
        xor     al, al                      ; Clear the register (no Mod/RM needed)
        lea     rbx, offset s_regtable      ; Load the register value table
        mov     bl, byte ptr [rbx + rdx]    ; Get the source register encoding by index
        shl     bl, 3                       ; Shift the dest into the dest bits of the
        or      al, bl                      ; Set those bits in AL
        lea     rbx, offset s_regtable      ; Get the register value table again
        mov     bl, byte ptr [rbx + r8]     ; Get the dest register
        or      al, bl                      ; OR it into the dest
        mov     byte ptr [rcx +1], al       ; Set the new mov target byte
        pop     rax                         ; Retrieve the byte count
        add     eax, 2                      ; Add the count of bytes just written
ENDM

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
; --- 0th Generation Cipher ---
; 48 C7 C1 E0 01 00 00
; 48 BB 16 10 B1 00 00 00 00 00
; 48 8B F3
; 48 8B FE
; 48 C7 C3 9A 02 00 00
; 66 8B 06
; 66 33 C3
; 66 89 06
; 48 FF C6
; 48 FF C9
; 48 85 C9
; 75 E9
poly_begin:
    PermutationEngine PROC
        local cipherOffset:qword
        local regTable:REG_TABLE
        local xorKey:byte
        local keySize:dword
        push    rbx
        push    rsi
        mov     rax, offset simple_substitution_cipher
        mov     cipherOffset, rax
        lea     rcx, regTable
        call    ShuffleRegTable
        xor     ebx, ebx
    ; Set the source register to the offset of the encoded portion
    permute_op1:
        mov     rcx, 1                      ; We'll have two potential instructions for this op
        call    rand_range            
        mov     ecx, offset simple_substitution_cipher
        add     ecx, ebx              
        test    eax, eax
        jz      op1_beta
        ; Generate an immediate 64 bit mov into a yet unused register before setting dest reg
        op1_alpha:                          ; Case rand_range returned 1
            mov     rdx, offset poly_begin
            mov     r8d, regTable.REG_TABLE.KeyReg
            call    GenMovImm64_64
            add     ebx, eax
            mov     rcx, simple_substitution_cipher
            add     rcx, rbx
            mov     edx, regTable.REG_TABLE.SourceReg
            mov     r8d, regTable.REG_TABLE.KeyReg
            mov     r9, 1
            call    GenMovReg            
            add     ebx, eax
            jmp     permute_op2
        op1_beta:                           ; Case rand_range returned 0
            mov     rdx, offset poly_begin
            mov     r8d, regTable.REG_TABLE.SourceReg
            call    GenMovImm64_64
            add     ebx, eax
    ; Set the key register to the random key. Determines keysize
    permute_op2:
        mov     ecx, 3
        call    rand_range
        mov     ecx, offset simple_substitution_cipher
        add     ecx, ebx
        rdrand  rdx
        mov     r8d, regTable.REG_TABLE.KeyReg
        test    eax, eax
        jz      op2_epsilon
        cmp     eax, 3
        je      op2_delta
        cmp     eax, 2
        je      op2_gamma
        cmp     eax, 1
        je      op2_beta 

        ; Generate movabs
        op2_alpha: 
            call    GenMovImm64_64
            add     ebx, eax
            mov     keySize, 3
            jmp     permute_op3         
        ; Generate 64 bit DWORD mov
        op2_beta:
            call    GenMovImm64_32
            add     ebx, eax
            mov     keySize, 4
            jmp     permute_op3
        ; Generate 32 bit DWORD mov
        op2_gamma:
            call    GenMovImm32
            add     ebx, eax
            mov     keySize, 4
            jmp     permute_op3

        ; Generate 16 bit mov
        op2_delta:
            call    GenMovImm16
            add     ebx, eax
            mov     keySize, 2
            jmp     permute_op3

        ; Generate 8 bit mov
        op2_epsilon:
            call    GenMovImm8
            mov     keySize, 1
            add     ebx, eax

     ; Set the length register to the size in whatever unit was selected in op2
    permute_op3:
        mov     rcx, 3                      ; We'll have three potential instructions for this op
        call    rand_range                  
        mov     rcx, offset simple_substitution_cipher          
        mov     r15, rax
        mov     r14, rbx
        mov     eax, (offset poly_end - offset poly_begin) 
        mov     ebx, [keySize]
        test    ebx, ebx
        jz      keysize_set
        xor     edx, edx
        div     rbx
        mov     edx, eax
        mov     rbx, r14
        mov     rax, r15
        keysize_set:
        mov     r8d, regTable.REG_TABLE.LengthReg
        test    eax, eax
        jz      op3_delta
        cmp     eax, 1
        je      op3_gamma
        cmp     eax, 2
        je      op3_beta
        ; Generate the original byte sequence from 0th generation cipher
        op3_alpha:                          ; Case rand_range returned 3
            call    GenMovImm64_64
            add     ebx, eax
            jmp     permute_op4
        ; Generate 32-bit x64  variant
        op3_beta:                           ; Case rand_range returned 2
            call    GenMovImm64_32
            add     ebx, eax
            jmp     permute_op4
        ; Generate 32-bit variant
        op3_gamma:                          ; Case rand_range returned 1
            call    GenMovImm32
            add     ebx, eax
            jmp     permute_op4
        ; Generate 16-bit variant            
        op3_delta:                          ; Case rand_range returned 0
            call    GenMovImm16
            add     ebx, eax

    ; i. Set the encryption register to the data to encrypt
    ; ii. Xor the value
    ; iii. Write the value back
    ; alpha: keysize 32
    ; beta: keysize 16
    ; gamma: keysize 8
    permute_op4:
        mov     rcx, 3
        call    rand_range        
        mov     ecx, offset simple_substitution_cipher
        add     ecx, ebx
        mov     edx, regTable.REG_TABLE.SourceReg
        mov     r8d, regTable.REG_TABLE.DestReg
        test    eax, eax
        jz      op4_gamma
        cmp     eax, 2
        je      op4_beta

        ; Encrypt in dwords
        op4_alpha:
            ; fastcall GenMovDestMem(rcx=address, rdx=src_index, r8=dest_index, r9=mode)
            xor     r9, r9
            call    GenMovDestMem
            add     ebx, eax

        ; Encrypt in words
        op4_beta:
            mov     r9, 2
            call    GenMovDestMem
            add     ebx, eax

        ; Encrypt in bytes
        op4_gamma: 
            mov     r9, 3
            call    GenMovDestMem
            add     ebx, eax

    permute_op5:


                                    
    epilog:
        call    simple_substitution_cipher
        pop     rsi
        pop     rbx
        ret
    PermutationEngine ENDP

;-----------------------------------------------------------------------------
;  2a. Instruction Generation Procedures
;-----------------------------------------------------------------------------
    ; fastcall GenMov32(rcx=address, edx=value, r8=index)
    GenMovImm64_32 PROC
        push    rbx
        mov     al, byte ptr s_rex_prefix
        mov     byte ptr [rcx], al          ; Set the REX prefix at address + 0
        mov     al, byte ptr s_mov64_imm32
        mov     byte ptr [rcx + 1], al      ; Set the MOV opcode at address + 1
        mov     al, byte ptr s_modrm        ; Get a Mod/RM byte
        lea     rbx, offset s_regtable        
        or      al, byte ptr [rbx + r8]     ; OR the Mod RM byte with the proper register
        mov     byte ptr [rcx + 2], al      ; Set the Mod/RM byte at address + 2
        mov     dword ptr [rcx + 3], edx    ; Set the immediate value at address + 3
        pop     rbx
        mov     eax, 7
        ret
    GenMovImm64_32 ENDP

    ; fastcall GenMov32(rcx=address, rdx=value, r8=index)
    GenMovImm64_64 PROC
        push    rbx
        mov     al, byte ptr s_rex_prefix
        mov     byte ptr [rcx], al          ; Set the REX prefix at address + 0
        mov     al, byte ptr s_mov64_imm64
        lea     rbx, offset s_regtable        
        or      al, byte ptr [rbx + r8]     ; OR the Mod RM byte with the proper register
        mov     byte ptr [rcx + 1], al      ; Set the MOV opcode at address + 1
        mov     qword ptr [rcx + 2], rdx    ; Set the immediate value at address + 3
        pop     rbx
        mov     eax, 10
        ret
    GenMovImm64_64 ENDP

    ; fastcall GenMov32(rcx=address, edx=value, r8d=index)
    GenMovImm32 PROC
        push    rbx
        mov     al, byte ptr s_mov32_imm
                                            ; Load the opcode into al
        lea     rbx, s_regtable             ; Load the register value table
        or      al, byte ptr [rbx + r8]     ; OR the opcode with the value at the passed index
        mov     byte ptr [rcx], al          ; Set the first byte at address to the opcode
        mov     dword ptr [rcx + 1], edx        ; Set the immediate value to opcode to 'value'
        pop     rbx         
        mov     rax, 5                      ; Return the number of bytes modified
        ret
    GenMovImm32 ENDP

    ; fastcall GenMovImm16(rcx=address, edx=value, r8d=index)
    GenMovImm16 PROC
        push    rbx
        mov     al, byte ptr s_16b_prefix   ; Load the 16 bit prefix (0x66)
        mov     byte ptr [rcx], al          ; Write the 16 bit prefix to the target address
        mov     al, byte ptr s_mov32_imm    ; Load the opcode
        lea     rbx, s_regtable             ; Load the register value table
        or      al, byte ptr [rbx + r8]     ; OR the opcode with the value at the passed index
        mov     byte ptr [rcx + 1], al      ; Set the first byte at address to the opcode
        mov     word ptr [rcx + 2], dx      ; Set the immediate value to opcode to 'value'
        mov     eax, 3                      ; This routine wrote 3 bytes
        pop     rbx
        ret
    GenMovImm16 ENDP

    ; fastcall GenMovImm8(rcx=address, edx=value, r8d=index)
    GenMovImm8 PROC
        push    rbx
        mov     al, byte ptr s_mov8_imm     ; Load the 8 bit opcode
        lea     rbx, s_regtable             ; Load register value table
        or      al, byte ptr [rbx + r8]     ; OR the opcode with the register value
        mov     byte ptr [rcx], al          ; Write the opcode to the target address
        mov     byte ptr [rcx + 1], dl      ; Write the immediate value passed in dl
        pop     rbx
        ret
    GenMovImm8 ENDP

    ; fastcall GenMovReg(rcx=address, rdx=src_index, r8=dest_index, r9=mode)
    ;   r9=0 -> gen 32 bit 
    ;   r9=1 -> gen 64 bit 
    ;   r9=2 -> gen 16 bit 
    ;   r9=3 -> gen 8 bit
    GenMovReg PROC
        push    rbx
        push    r10
        call    GenSetMode                  ; Set the mode (8, 16, 32, 64)
        GenOpModRM s_mov_reg                ; Generate the rest of the instruction
        pop     r10
        pop     rbx
        ret
    GenMovReg ENDP

    ; fastcall GenMovDestMem(rcx=address, rdx=src_index, r8=dest_index, r9=mode)
    GenMovDestMem PROC
        push    rbx
        push    r10
        call    GenSetMode
        GenOpAddress s_mov_dest_mem         ; Generate the instruction using the opcode
        pop     r10
        pop     rbx                         
        ret
    GenMovDestMem ENDP

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
        push    r10
        call    GenSetMode
        GenOpModRM s_xor_reg
        pop     r10
        pop     rbx
        ret
    GenXor ENDP

    ; fastcall GenInc(rcx=address, edx=src_index, r8=addressing_mode)
    GenInc PROC
        push    rbx
        push    r10
        mov     r9, r8
        call    GenSetMode
        GenOpModRMSourceReg s_inc_reg       ; Generate the byte sequence for the inc
        pop     r10
        pop     rbx
        ret
    GenInc ENDP

    ; fastcall GenDec(rcx=address, edx=src_index, r8=addressing_mode)
    GenDec PROC
        push    rbx
        push    r10
        mov     r9, r8
        call    GenSetMode
        add     al, byte ptr s_inc_reg      ; Get the opcode
        mov     byte ptr [rcx], al          ; Set the opcode         
        mov     al, byte ptr s_modrm        ; Get the Mod/RM default byte
        lea     rbx, offset s_regtable      ; Get the register value table
        mov     bl, byte ptr [rbx + rdx]    ; Get the dest register by index
        or      bl, 200                     ; Set the fourth bit to 1
        or      al, bl                      ; OR the source into Mod/RM
        mov     byte ptr [rcx + 1], al      ; Set the new Mod/RM byte
        pop     rax                         ; Get the byte count
        add     eax, 2                      ; Add the count of bytes just written
        pop     r10
        pop     rbx
        ret
    GenDec ENDP

    ; fasctall GenTest(rcx=address, edx=src_index, r8d=dst_index, r9=addressing_mode)
    GenTestReg PROC
        push    rbx
        push    r10
        call    GenSetMode                  ; Set the addressing mode
        GenOpModRM s_test                   ; Set the opcode
        pop     r10
        pop     rbx
        ret
    GenTestReg ENDP

    ; fastcall GenJump(rcx=address, rdx=offset, r8=mode, r9=direction)
    ;   r8=0 -> jb/jc/jnae  r8=6 -> js          r8=C -> jle/jng
    ;   r8=1 -> jae/jnb/jnc r8=7 -> jns         r8=D -> jg/jnle
    ;   r8=2 -> je/js       r8=8 -> jp/jpe      
    ;   r8=3 -> jne/jnz     r8=9 -> jnp/jpo     r9=0 -> forward
    ;   r8=4 -> jbe/jna     r8=A -> jl/jlge     r9=1 -> backward
    ;   r8=5 -> ja/jnbe     r8=B -> jnge/jnl
    GenJccRel8 PROC
        push    rbx
        mov     al, byte ptr s_jc           ; 0x74 (JE)
        mov     ebx, r8d                    ; Move the mode into a byte addressable reg
        or      al, bl                      ; Set the jump mode
        mov     byte ptr [rcx], al          ; Write the jump byte
        test    r9, r9                      ; Check the direction boolean
        jz      jcc_rel8_forward            ; Just write the offset if set to forwardP
        mov     al, 0FFh                    ; Otherwise, the offset needs to be subtracted from 255
        sub     al, dl                      ; Perform the subtraction
        mov     dl, al                      ; The write will use DL
        jcc_rel8_forward:
        mov     byte ptr [rcx + 1], al      ; Write the relative offset 
        mov     eax, 2                      ; This operation wrote two bytes
        pop     rbx
        ret 
    GenJccRel8 ENDP

    ; fastcall GenJmpRel8(rcx=address, rdx=offset, r8=forward/backward)
    ;   r8=0 -> forward
    ;   r8=1 -> backward
    GenJmpRel8 PROC
        mov     al, byte ptr s_jmp8         ; 0xEB (JMP Rel 8)
        mov     byte ptr [rcx], al          ; Write the opcode
        test    r8, r8                      ; Check the mode
        jz      jmp_rel8_forward            ; Perform a forward jump
        mov     al, 0FFh                    ; Count backwards from 0xFF
        sub     al, dl                      ;
        mov     dl, al                      ; The write will use DL
    jmp_rel8_forward:
        mov     byte ptr [rcx + 1], dl      ; Write the jump offset
        mov     eax, 2                      ; This operation wrote two bytes
        ret
    GenJmpRel8 ENDP
    
    ; polycall GenSetMode(r9=mode, r10=volatile)
    ;   r9=0 -> gen 32 bit 
    ;   r9=1 -> gen 64 bit 
    ;   r9=2 -> gen 16 bit 
    ;   r9=3 -> gen 8 bit
    GenSetMode PROC
        pop     r10                         ; Really stupid stack hack
                                            ; requires caller to save r10
        xor     eax, eax
        test    r9, r9
        jz      genmode_32_pre
        cmp     r9, 1
        je      genmode_64
        cmp     r9, 2
        je      genmode_16
        cmp     r9, 3
        je      genmode_8
        jmp     genmode_epilog
    genmode_16:
        mov     al, byte ptr s_16b_prefix   ; Get 0x66
        mov     byte ptr [rcx], al          ; Set the 16-bit prefix
        mov     rax, 1                      ; Set the XOR mode to add to 0x31
        push    rax                         ; Save the byte count
        inc     rcx                         ; Set the pointer to the next byte to write
        jmp     genmode_epilog              ; Jump to the standard routine
    genmode_8:
        xor     rax, rax                    ; Clear RAX so that the ocunt is correct
        push    rax                         ; Save the byte count
        jmp     genmode_epilog              ; 8 bits is easy
    genmode_64:
        mov     al, byte ptr s_rex_prefix   ; Get 0x48
        mov     byte ptr [rcx], al          ; Set the REX prefix
        mov     rax, 1                      ; Prepare 1 to the opcode
        push    rax                         ; Save the byte count for later
        inc     rcx                         ; Increment the pointer to write to
        jmp     genmode_epilog              ; Invoke the standard routine
    genmode_32_pre:
        push    rax
        inc     eax
    genmode_epilog:
        push    r10                         ; Unhack the stack
        ret
    GenSetMode ENDP
    
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
    s_mov64_imm32:
        db 11000111b    ; 0xC7 ( +4 bytes for imm)
    s_mov64_imm64:
        db 10111000b    ; 0xB8 ( +8 bytes for imm)
    s_mov32_imm:
        db 10111000b    ; 0xB8 ( +4 bytes for imm)
    s_mov8_imm:
        db 10110000b    ; 0xB0 ( +1 byte for imm)
    s_mov_dest_mem:
        db 10001000b    ; 0x88 ( e.g. mov byte ptr [rbx], cl). INC to address bigger regs
    s_mov_reg:
        db 10001000b    ; 0x89 ( +1 byte for mem/reg), works for 32 and 64 bit. 
    s_mov_rmem:
        db 10001011b;   ; 0x8B ( +1 byte for register code)
    s_push_reg:
        db 01001000b    ; 0x50 (PUSH reg)
    s_push_imm:
        db 01101010b    ; 0x6A (PUSH imm)
    s_pop_reg:
        db 01011000b    ; 0x58 (POP reg)
    s_xor_reg:
        db 00110000b    ; 0x30 (XOR). For 16 bit, add 16-bit prefix and inc 0x30.
    s_inc_reg:
        db 11111110b    ; 0xFE (INC)
    s_test:
        db 10000100b    ; 0x84 (TEST)
    s_jc:
        db 01110010b    ; 0x72 (JC)
    s_call:
        db 11101000b    ; 0xE8 (CALL)
    s_jmp8:
        db 11101011b    ; 0xEB (JMP)
    s_lea:
        db 10001101b    ; 0x8D (LEA)

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
        mov     rbx, offset poly_begin                      ;  op1  Set source register. Source = start of encrypted code                                                                  
        mov     rsi, rbx                                    ;  op1.                     
        mov     rdi, rsi                                    ;  op2. Set dest register, == source                             
        mov     rbx, 029Ah                                  ;  op4. rbx = key                                                                                                                                              
                                                                                                                        
    simple_substitution_cipher_loop_begin:                                                                              
        mov     ax, word ptr [rsi]                          ;  Essentially lodsw but better able to permutate      
        xor     ax, bx                                      ;  The fundamental cipher operation          
        mov     word ptr [rsi], ax                          ;  Could also be RDI  
        inc     rsi                                         ;  Increment twice / for word
        inc     rsi      
        dec     rcx
        test    rcx, rcx
        jnz     simple_substitution_cipher_loop_begin    
    simple_substitution_cipher_end:
        ret

db 52 - ($-simple_substitution_cipher_end) dup(0)               ; Space for cipher to permutate

TEXT$00 ENDS
END