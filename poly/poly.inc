;  <poly.inc>   -    includes for poly.asm
;                         April 2020
;
IFNDEF _VIR_INC
_VIR_INC EQU <1>

    ; GenMovRegPtr32 PROC
    ;     push    rbx
    ;     test    r9, r9
    ;     jz     _dir_mov_src_mem
    ; _dir_mov_dest_mem:                      ; r9 = 1
    ;     mov     al, byte ptr s_mov_reg      ; Set al to 0x89
    ;     jmp     _set_opcode
    ; _dir_mov_src_mem:                       ; r9 = 0
    ;     mov     al, byte ptr s_mov_rmem     ; Set al to 0x8B
    ; _set_opcode:
    ;     mov     byte ptr [rcx], al          ; Set the opcode
    ;     xor     eax, eax                    ; Clear the second byte of instruction
    ;     lea     rbx, offset s_regtable      ; Get the register value table
    ;     mov     bl, byte ptr [rbx + r8]     ; Get the dest register encoding by index
    ;     shl     bl, 3                       ; Shift the dest into the dest bits of mod/rm
    ;     or      al, bl                      ; OR the dest into the mod/rm variable
    ;     lea     rbx, offset s_regtable      ; Get the register value table again
    ;     mov     bl, byte ptr [rbx + rdx]    ; Get the source by index
    ;     or      al, bl                      ; OR the source into the Mod/RM
    ;     mov     byte ptr [rcx + 1], al      ; Set the newly generated Mod/RM byte
    ;     mov     eax, 2                      ; This operation wrote two bytes
    ;     pop     rbx                 
    ;     ret
    ; GenMovRegPtr32 ENDP

    ;     ; fastcall GenMovRegPtr32(rcx=address, rdx=src_index, r8=dest_index, r9=bool_direction)
    ; GenMovRegPtr64 PROC
    ;     mov     al, byte ptr s_rex_prefix   ; Get the REX prefix value
    ;     mov     byte ptr [rcx], al          ; Set the REX prefix
    ;     inc     rcx                         ; Increment RCX for function call
    ;     call    GenMovRegPtr32              ; Invoke the code generator for the MOV
    ;     inc     eax                         ; Count the added REX prefix
    ;     ret
    ; GenMovRegPtr64 ENDP

    ;     ; fastcall GenMovRegPtr16(rcx=address, rdx=src_index, r8=dest_index, r9=bool_direction)
    ; GenMovRegPtr16 PROC
    ;     mov     al, byte ptr s_16b_prefix   ; Get the 16-bit mode prefix
    ;     mov     byte ptr [rcx], al          ; Set the mode prefix
    ;     inc     rcx                         ; Move address pointer to next byte
    ;     call    GenMovRegPtr32              ; Gen the MOV
    ;     Inc     eax                         ; Count the added prefix
    ; GenMovRegPtr16 ENDP


    ; ; fastcall GenMovRegPtr8(rcx=address, rdx=src_index, r8=dest_index, r9=bool_direction)
    ; GenMovRegPtr8 PROC
    ;     mov     al, byte ptr s_8b_prefix    ; Get the 16-bit mode prefix
    ;     mov     byte ptr [rcx], al          ; Set the mode prefix
    ;     inc     rcx                         ; Move address pointer to next byte
    ;     call    GenMovRegPtr32              ; Gen the MOV
    ;     inc     eax                         ; Count the added prefix
    ;     ret
    ; GenMovRegPtr8 ENDP

ENDIF