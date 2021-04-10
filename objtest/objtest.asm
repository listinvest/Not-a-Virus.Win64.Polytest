option win64:0x08   ; init shadow space, reserve stack at PROC level
option zerolocals:1 ; autozero local vairable memory

TEXT$00 SEGMENT ALIGN(10h) 'code' READ WRITE EXECUTE
    Main PROC
        push 32
        push 30002

    simple_substitution_cipher:
        simple_substitution_cipher_setup:
            mov     rcx, (offset vir_end - offset vir_begin) / 2
                                                                ;  Calculate payload body size in words                         
            mov     rbx, offset vir_begin                                                                                                
            mov     rsi, rbx                                    ;  source = start of encrypted code                             
            mov     rdi, rsi                                    ;  destination = same as the source                             
            mov     rbx, 029Ah                                  ;  rbx = key                                                                                                                                              
                                                                                                                            
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
    Main ENDP

    vir_begin:
    db 44 dup(24)
    vir_end:
TEXT$00 ENDS
END