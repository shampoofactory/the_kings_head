default rel

global  pbkdf2_hmac_sha1


%include "hmac_sha1_ctx.nasm"
%include "sha1_ctx.nasm"


section .text

extern  hmac_sha1_init
extern  hmac_sha1_final
extern  hmac_sha1_wipe
extern  hmac_sha1_update
extern  sha1_transform_blk


; bool *(const uint8_t *p, uint32_t p_len, const uint8_t *s, uint32_t s_len, uint64_t c, uint32_t dk_len, uint8_t *dk);
pbkdf2_hmac_sha1:
    endbr64                                         ; CET
    push        rbp                                 ; prolog
    mov         rbp, rsp
    test        r9d, r9d                            ; if (dk_len == 0)
    je          .exit_ok                            ;   then exit_ok
    test        r8, r8                              ; if (c == 0)
    je          .exit_err                           ;   then exit_err
    sub         rsp, 0x00D0                         ; [0000:0090] ctx HMAC_SHA1_CTX
                                                    ; [0090:00A4] buf
                                                    ; [00A4:00A8] s_len
                                                    ; [00A8:00B0] s
                                                    ; [00B0:00C8] c
                                                    ; [00B8:00C0] r12
                                                    ; [00C0:00C8] r13
                                                    ; [00C8:00D0] r14
                                                    ; [00D0:00D8] rbp
    mov         [rsp + 0x00A4], ecx                 ; save s_len
    mov         [rsp + 0x00A8], rdx                 ; save s
    mov         [rsp + 0x00B0], r8                  ; save c
    mov         [rsp + 0x00B8], r12                 ; save registers
    mov         [rsp + 0x00C0], r13
    mov         [rsp + 0x00C8], r14
    mov         r12, [rbp + 0x0010]                 ; dk
    mov         r13d, r9d                           ; dk_len
    xor         r14d, r14d                          ; i = 0
    mov         edx, esi                            ; p_len
    mov         rsi, rdi                            ; p
    mov         rdi, rsp                            ; &ctx
    call        hmac_sha1_init                      ; call(&ctx, p, p_len)
.loop:
    lea         r14d, [r14 + 1]                     ; i += 1
    cmp         r13d, 0x14                          ; if (dk_len <= 0x14)
    mov         rsi, [rsp + 0x00A8]                 ; s
    mov         edx, [rsp + 0x00A4]                 ; s_len
    mov         rcx, [rsp + 0x00B0]                 ; c
    mov         r8d, r14d                           ; i
    jbe          .break                             ;   then .break
    mov         r9, r12                             ; dk
    call        pbkdf2_hmac_sha1_blk                ; call(ctx, s, s_len, c, i, dk)
    lea         r12, [r12 + 0x14]                   ; dk += 0x14
    lea         r13d, [r13 - 0x14]                  ; dk_len -= 0x14
    jmp         .loop                               ; continue
.break:
    test        r13d, r13d                          ; if (dk_len == 0)
    je          .out                                ;   then .out
    lea         r9, [rsp + 0x0090]                  ; &buf
    call        pbkdf2_hmac_sha1_blk                ; call(ctx, s, s_len, c, i, buf);
    mov         ecx, r13d                           ; count = dk_len
    mov         rdi, r12                            ; dk
    lea         rsi, [rsp + 0x0090]                 ; &buf
    rep         movsb                               ; copy
.out:
    mov         r12, [rsp + 0x00B8]                 ; load registers
    mov         r13, [rsp + 0x00C0]
    mov         r14, [rsp + 0x00C8]
    vpxor       xmm0, xmm0                          ; zero buf
    vmovdqa     [rsp], xmm0
    vmovdqa     [rsp + 0x10], xmm0
    vmovdqa     [rsp + 0x20], xmm0
    vmovdqa     [rsp + 0x30], xmm0
    vmovdqa     [rsp + 0x40], xmm0
    vmovdqa     [rsp + 0x50], xmm0
    vmovdqa     [rsp + 0x60], xmm0
    vmovdqa     [rsp + 0x70], xmm0
    vmovdqa     [rsp + 0x80], xmm0
    vmovdqa     [rsp + 0x90], xmm0
    vmovdqa     [rsp + 0xA0], xmm0
    vmovdqa     [rsp + 0xB0], xmm0
    vmovdqa     [rsp + 0xC0], xmm0
    vzeroall                                        ; zero xmm
.exit_ok:
    mov         eax, 1                              ; OK
.exit:
    mov         rsp, rbp                            ; epilog
    pop         rbp
    ret
.exit_err:
    xor         eax, eax                            ; ERR
    jmp         .exit                               ; exit


; bool *(HMAC_SHA1_CTX *ctx, const uint8_t *s, uint32_t s_len, uint64_t c, uint32_t i, uint8_t *dk)
; assert(c != 0)
pbkdf2_hmac_sha1_blk:
    push        rbp                                 ; prolog
    mov         rbp, rsp
    sub         rsp, 0x0030                         ; [0000:0014] buf
                                                    ; [0018:0020] c
                                                    ; [0020:0028] dk
    movbe       [rsp], r8d                          ; save i into buf
    mov         [rsp + 0x0018], rcx                 ; save c
    mov         [rsp + 0x0020], r9                  ; save dk
    call        hmac_sha1_update                    ; call(ctx, s, s_len)
    test        eax, eax                            ; if (!OK)
    je          .exit                               ;   then .exit
    mov         rsi, rsp                            ; &buf
    mov         edx, 4                              ; 4
    call        hmac_sha1_update                    ; call(ctx, c, 4)
    test        eax, eax                            ; if (!OK)
    je          .exit                               ;   then .exit
    mov         rsi, rsp                            ; &buf
    call        hmac_sha1_final                     ; call(ctx, &ctx->blk)
    vmovdqa     xmm14, xmm0                         ; ABCD chain
    vmovdqa     xmm15, xmm1                         ; E000 chain
    mov         rcx, [rsp + 0x0018]                 ; c
    sub         rcx, 1                              ; if (--c = 0)
    je          .break                              ;   then .break
                                                    ; H(ipad ^ key) working variables
    mov         eax, [rdi + hmac_sha1_CTX.ivar + 0x10]
    vmovdqa     xmm10, [rdi + hmac_sha1_CTX.ivar]   
    vpxor       xmm11, xmm11
    vpinsrd     xmm11, eax, 3
                                                    ; H(opad ^ key) working variables
    mov         eax, [rdi + hmac_sha1_CTX.ovar + 0x10]
    vmovdqu     xmm12, [rdi + hmac_sha1_CTX.ovar]
    vpxor       xmm13, xmm13
    vpinsrd     xmm13, eax, 3
    mov         eax, 0x80000000                     ; message pad
    mov         edx, 0x02A0                         ; message len    
.loop:
    vmovdqa     xmm3, xmm0                          ; blk_0 md
    vmovdqa     xmm4, xmm1                          ; blk_1 md
    vpinsrd     xmm4, eax, 2                        ; blk_1 pad
    vpxor       xmm5, xmm5                          ; blk_2 zero
    vmovd       xmm6, edx                           ; blk_3 len
    vmovdqa     xmm0, xmm10                         ; H(ipad ^ key) working variables
    vmovdqa     xmm1, xmm11
    call        sha1_transform_blk
    vmovdqa     xmm3, xmm0                          ; blk_0 md
    vmovdqa     xmm4, xmm1                          ; blk_1 md
    vpinsrd     xmm4, eax, 2                        ; blk_1 pad
    vpxor       xmm5, xmm5                          ; blk_2 zero
    vmovd       xmm6, edx                           ; blk_3 len
    vmovdqu     xmm0, xmm12                         ; H(opad ^ key) working variables
    vmovdqa     xmm1, xmm13
    call        sha1_transform_blk
    vpxor       xmm14, xmm0                         ; chain ^=
    vpxor       xmm15, xmm1
    sub         rcx, 1                              ; if (--c != 0)
    jne         .loop                               ;   then .loop
.break:
    mov         rsi, [rsp + 0x0020]                 ; dk
    vmovdqa     xmm10, [sha1_REVERSE_BYTES]         ; load mask
    vpshufb     xmm14, xmm10                        ; reverse bytes
    vpshufb     xmm15, xmm10                        ; reverse bytes
    vmovdqu     [rsi], xmm14                        ; save md
    vmovd       [rsi + 0x10], xmm15
    mov         eax, 1                              ; OK
.exit:
    vpxor       xmm0, xmm0                          ; zero buf
    vmovdqa     [rsp], xmm0
    vmovdqa     [rsp + 0x10], xmm0
    vmovdqa     [rsp + 0x20], xmm0
    mov         rsp, rbp                            ; epilog
    pop         rbp
    ret
