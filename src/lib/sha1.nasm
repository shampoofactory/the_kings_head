default rel

global  sha1_final
global  sha1_final_with_state
global  sha1_init
global  sha1_transform
global  sha1_transform_blk
global  sha1_update
global  sha1_update_blk
global  sha1_wipe


%include "sha1_ctx.nasm"


section .text

; bool *(sha1_CTX *ctx, const uint8_t *msg, uint64_t msg_len);
;
; CONST:
; rdi
; xmm11..
align 0x10
sha1_update:
    endbr64                                         ; CET
    test        rdx, rdx                            ; if (msg_len == 0)
    je          .exit_ok                            ;   then .exit_ok
    mov         rax, [rdi + sha1_ITX.len]           ; ctx_len = ctx->len
    mov         rcx, 0x1FFFFFFFFFFFFFFF             ; MAX ctx.len
    sub         rcx, rax                            ; ctx_rem = MAX - ctx_len
    cmp         rcx, rdx                            ; if (ctx_rem < msg_len)
    jb          .exit_err                           ;   then .exit_err
    mov         ecx, eax                            ; blk_off = ctx_len
    add         rax, rdx                            ; ctx_len += msg_len
    mov         [rdi + sha1_ITX.len], rax           ; ctx->len = ctx_len
    vmovdqa     xmm7, [sha1_REVERSE_BYTES]          ; load mask
    vmovdqa     xmm0, [rdi + sha1_ITX.var]
    vpxor       xmm1, xmm1                          ; load working variables
    vpinsrd     xmm1, [rdi + sha1_ITX.var + 0x10], 3
    lea         r10, [rdi + sha1_CTX.blk]           ; &ctx->blk
    mov         r9, rdi                             ; save ctx
    mov         r8, rdx                             ; save msg_len
    mov         rdi, r10                            ; &ctx->blk
    and         ecx, 0x3F                           ; blk_off &= 0x3F
    jz          .msg                                ; if (blk_off = 0) then .msg
    mov         eax, 0x40                           ; 0x40
    sub         eax, ecx                            ; blk_rem = 0x40 - blk_off
    add         rdi, rcx                            ; &ctx->blk + blk_off
    cmp         rax, rdx                            ; if (blk_rem < msg_len)
    jbe         .blk                                ;   then .blk
    mov         ecx, edx                            ; count = msg_len
    rep         movsb                               ; copy
.exit_ok_restore:
    mov         rdi, r9                             ; ctx
.exit_ok:
    mov         eax, 1                              ; return true
    ret
.blk:
    mov         ecx, eax                            ; count = blk_rem
    rep         movsb                               ; copy
    mov         rcx, rsi                            ; save msg
    mov         rsi, r10                            ; &ctx->blk
    mov         edx, 1                              ; 1
    call        sha1_transform                      ; call(&ctx->blk, 1, ABCD, E000)
    vpxor       xmm2, xmm2                          ; zero
    vmovdqa     [r10], xmm2                         ; zero &ctx->blk
    vmovdqa     [r10 + 0x10], xmm2
    vmovdqa     [r10 + 0x20], xmm2
    vmovdqa     [r10 + 0x30], xmm2
    mov         rdi, r10                            ; &ctx->blk
    mov         rsi, rcx                            ; msg
    sub         r8, rax                             ; msg_len -= blk_rem
    mov         rdx, r8                             ; copy msg_len
.msg:
    shr         rdx, 6                              ; msg_len / 0x40
    jz          .out                                ; if (n_blk != 0) then .rem
    call        sha1_transform                      ; call(msg, msg_len / 0x40, ABCD, E000)
.out:
    vmovdqa     [r9 + sha1_ITX.var], xmm0           ; save working variables
    vpextrd     [r9 + sha1_ITX.var + 0x10], xmm1, 3
    mov         ecx, r8d                            ; count = msg_len
    and         ecx, 0x3F                           ; count &= 0x3F
    rep         movsb                               ; copy
    jmp         .exit_ok_restore                    ; exit_ok_restore
.exit_err:
    xor         eax, eax                            ; return 0
    ret


; bool *(sha1_LTX *ctx, const uint8_t *blk, uint32_t blk_len);
;
; CONST:
; rdi, r9..
; xmm10..
;
; OUT:
; xmm0: ABCD
; xmm1: E000
align 0x10
sha1_update_blk:                                    ; assert(n_blk != 0)
    endbr64                                         ; CET
    mov         r8, rdx                             ; blk_len
    shl         r8, 6                               ; msg_len = blk_len * 0x40
    mov         rax, [rdi + sha1_ITX.len]           ; ctx_len = ctx.len
    mov         rcx, 0x1FFFFFFFFFFFFFFF             ; MAX ctx.len
    sub         rcx, rax                            ; ctx_rem = MAX - ctx_len
    cmp         rcx, r8                             ; if (ctx_rem < msg_len)
    jb          .exit_err                           ;   then .exit_err
    add         rax, r8                             ; ctx_len += msg_len
    mov         [rdi + sha1_ITX.len], rax           ; ctx.len = ctx_len
    vmovdqa     xmm7, [sha1_REVERSE_BYTES]          ; load mask
    vmovdqa     xmm0, [rdi + sha1_ITX.var]
    vpxor       xmm1, xmm1                          ; load working variables
    vpinsrd     xmm1, [rdi + sha1_ITX.var + 0x10], 3
    call        sha1_transform                      ; call(msg, blk_len, ABCD, E000)
    vmovdqa     [rdi + sha1_ITX.var], xmm0          ; save working variables
    vpextrd     [rdi + sha1_ITX.var + 0x10], xmm1, 3
.exit_ok:
    mov         eax, 1                              ; return true
    ret
.exit_err:
    xor         eax, eax                            ; return false
    ret


; void sha1_final(sha1_CTX *ctx, uint8_t md[static 0x14]);
;
; CONST:
; rdi
;
; OUT:
; xmm0: ABCD md
; xmm1: E000 md
; xmm2: DCBA md
; xmm3: 000E md
; xmm6: ZERO
; xmm7: REVERSE_BYTES
align 0x10
sha1_final:
    endbr64                                         ; CET
    vmovdqa     xmm10, [sha1_INIT_ITX]              ; load initial state
    vmovd       xmm11, [sha1_INIT_ITX + 0x10]
sha1_final_with_state:
    mov         rax, [rdi + sha1_ITX.len]           ; ctx_len = ctx.len
    lea         r8, [rdi + sha1_CTX.blk]            ; &ctx->blk
    mov         r9, rsi                             ; save md
    mov         rcx, rax                            ; copy ctx_len
    and         eax, 0x3F                           ; blk_off &= 0x3F
    mov         byte [r8 + rax], 0x80               ; append pad
    vmovdqa     xmm7, [sha1_REVERSE_BYTES]          ; load mask
    vmovdqa     xmm0, [rdi + sha1_ITX.var]
    vpxor       xmm1, xmm1                          ; load working variables
    vpinsrd     xmm1, [rdi + sha1_ITX.var + 0x10], 3
    mov         rsi, r8                             ; &ctx->blk
    mov         edx, 1                              ; 1
    cmp         eax, 0x38                           ; if (m_len < 0x38)
    jb          .blk_1                              ;   then .blk_1
.blk_0:                                             ; no room for m_len
    call        sha1_transform                      ; call(&ctx->blk, 1, ABCD, E000)
    vpxor       xmm2, xmm2                          ; zero
    xor         eax, eax                            ; zero
    vmovdqa     [r8], xmm2                          ; zero blk minus len
    vmovdqa     [r8 + 0x10], xmm2
    vmovdqa     [r8 + 0x20], xmm2
    mov         [r8 + 0x30], rax
    mov         rsi, r8                             ; &ctx->blk
    mov         edx, 1                              ; 1
.blk_1:                                             ; room for w_len
    lea         rcx, [rcx * 8]                      ; ctx_len *= 8
    movbe       [rsi + 0x38], rcx                   ; write ctx_len
    call        sha1_transform                      ; call(&ctx->blk, 1, ABCD, E000)
    call        sha1_init_with_state                ; call(ctx, state)
    vpshufb     xmm2, xmm0, xmm7                    ; reverse bytes
    vpshufb     xmm3, xmm1, xmm7
    vmovdqu     [r9], xmm2                          ; save md
    vmovd       [r9 + 0x10], xmm3
    ret


; void *(sha1_CTX *ctx)
;
; CONST:
; rdi, rsi, rdx, rcx, r8, r9
; rax
; xmm.. except xmm6
;
; OUT:
; xmm6: ZERO
align 0x10
sha1_init:
    endbr64                                         ; CET
    vmovdqa     xmm10, [sha1_INIT_ITX]              ; load initial state
    vmovd       xmm11, [sha1_INIT_ITX + 0x10]
sha1_init_with_state:
    vmovdqa     [rdi + sha1_ITX.var], xmm10         ; save initial state
    vmovdqa     [rdi + sha1_ITX.var + 0x10], xmm11
    vpxor       xmm6, xmm6                          ; zero
    vmovdqa     [rdi + sha1_CTX.blk], xmm6          ; zero block
    vmovdqa     [rdi + sha1_CTX.blk + 0x10], xmm6
    vmovdqa     [rdi + sha1_CTX.blk + 0x20], xmm6
    vmovdqa     [rdi + sha1_CTX.blk + 0x30], xmm6
    ret


; void *(sha1_CTX *ctx)
;
; CONST:
; rdi, rsi, rdx, rcx, r8, r9
; rax
; xmm.. except xmm6
;
; OUT:
; xmm6: ZERO
align 0x10
sha1_wipe:
    endbr64                                         ; CET
    vpxor       xmm6, xmm6                          ; zero
    vmovdqa     [rdi + sha1_CTX], xmm6
    vmovdqa     [rdi + sha1_CTX + 0x10], xmm6
    vmovdqa     [rdi + sha1_CTX + 0x20], xmm6
    vmovdqa     [rdi + sha1_CTX + 0x30], xmm6
    vmovdqa     [rdi + sha1_CTX + 0x40], xmm6
    vmovdqa     [rdi + sha1_CTX + 0x50], xmm6
    ret


; sha1_transform
;
; CONST
; rdi, rcx, r8, r9
; rax
; xmm7, xmm10..
;
; IN:
; rsi: const uint8_t* blks
; rdx: int64_t n_blk
; xmm0: working variables ABCD
; xmm1: working variables E000
; xmm7: REVERSE_BYTES
;
; OUT:
; rsi: const uint8_t* blk + n_blk *0x40
; rdx: 0
; xmm0: working variables ABCD
; xmm1: working variables E000
align 0x10
sha1_transform:                                     ; assert(n_blk != 0)
.loop:
    vmovdqa     xmm8, xmm0                          ; save working variables
    vmovdqa     xmm9, xmm1
    vmovdqu     xmm3, [rsi]                         ; rounds 0 through 3
    vpshufb     xmm3, xmm7
    vpaddd      xmm1, xmm3
    vmovdqa     xmm2, xmm0
    sha1rnds4   xmm0, xmm1, 0
    vmovdqu     xmm4, [rsi + 0x10]                  ; rounds 4 through 7
    vpshufb     xmm4, xmm7
    sha1nexte   xmm2, xmm4
    vmovdqa     xmm1, xmm0
    sha1rnds4   xmm0, xmm2, 0
    sha1msg1    xmm3, xmm4
    vmovdqu     xmm5, [rsi + 0x20]                  ; rounds 8 through 11
    vpshufb     xmm5, xmm7
    sha1nexte   xmm1, xmm5
    vmovdqa     xmm2, xmm0
    sha1rnds4   xmm0, xmm1, 0
    sha1msg1    xmm4, xmm5
    vpxor       xmm3, xmm5
    vmovdqu     xmm6, [rsi + 0x30]                  ; rounds 12 through 15
    vpshufb     xmm6, xmm7
    sha1nexte   xmm2, xmm6
    vmovdqa     xmm1, xmm0
    sha1msg2    xmm3, xmm6
    sha1rnds4   xmm0, xmm2, 0
    sha1msg1    xmm5, xmm6
    vpxor       xmm4, xmm6
    sha1nexte   xmm1, xmm3                          ; rounds 16 through 19
    vmovdqa     xmm2, xmm0
    sha1msg2    xmm4, xmm3
    sha1rnds4   xmm0, xmm1, 0
    sha1msg1    xmm6, xmm3
    vpxor       xmm5, xmm3
    sha1nexte   xmm2, xmm4                          ; rounds 20 through 23
    vmovdqa     xmm1, xmm0
    sha1msg2    xmm5, xmm4
    sha1rnds4   xmm0, xmm2, 1
    sha1msg1    xmm3, xmm4
    vpxor       xmm6, xmm4
    sha1nexte   xmm1, xmm5                          ; rounds 24 through 27
    vmovdqa     xmm2, xmm0
    sha1msg2    xmm6, xmm5
    sha1rnds4   xmm0, xmm1, 1
    sha1msg1    xmm4, xmm5
    vpxor       xmm3, xmm5
    sha1nexte   xmm2, xmm6                          ; rounds 28 through 31
    vmovdqa     xmm1, xmm0
    sha1msg2    xmm3, xmm6
    sha1rnds4   xmm0, xmm2, 1
    sha1msg1    xmm5, xmm6
    vpxor       xmm4, xmm6
    sha1nexte   xmm1, xmm3                          ; rounds 32 through 35
    vmovdqa     xmm2, xmm0
    sha1msg2    xmm4, xmm3
    sha1rnds4   xmm0, xmm1, 1
    sha1msg1    xmm6, xmm3
    vpxor       xmm5, xmm3
    sha1nexte   xmm2, xmm4                          ; rounds 36 through 39
    vmovdqa     xmm1, xmm0
    sha1msg2    xmm5, xmm4
    sha1rnds4   xmm0, xmm2, 1
    sha1msg1    xmm3, xmm4
    vpxor       xmm6, xmm4
    sha1nexte   xmm1, xmm5                          ; rounds 40 through 43
    vmovdqa     xmm2, xmm0
    sha1msg2    xmm6, xmm5
    sha1rnds4   xmm0, xmm1, 2
    sha1msg1    xmm4, xmm5
    vpxor       xmm3, xmm5
    sha1nexte   xmm2, xmm6                          ; rounds 44 through 47
    vmovdqa     xmm1, xmm0
    sha1msg2    xmm3, xmm6
    sha1rnds4   xmm0, xmm2, 2
    sha1msg1    xmm5, xmm6
    vpxor       xmm4, xmm6
    sha1nexte   xmm1, xmm3                          ; rounds 48 through 51
    vmovdqa     xmm2, xmm0
    sha1msg2    xmm4, xmm3
    sha1rnds4   xmm0, xmm1, 2
    sha1msg1    xmm6, xmm3
    vpxor       xmm5, xmm3
    sha1nexte   xmm2, xmm4                          ; rounds 52 through 55
    vmovdqa     xmm1, xmm0
    sha1msg2    xmm5, xmm4
    sha1rnds4   xmm0, xmm2, 2
    sha1msg1    xmm3, xmm4
    vpxor       xmm6, xmm4
    sha1nexte   xmm1, xmm5                          ; rounds 56 through 59
    vmovdqa     xmm2, xmm0
    sha1msg2    xmm6, xmm5
    sha1rnds4   xmm0, xmm1, 2
    sha1msg1    xmm4, xmm5
    vpxor       xmm3, xmm5
    sha1nexte   xmm2, xmm6                          ; rounds 60 through 63
    vmovdqa     xmm1, xmm0
    sha1msg2    xmm3, xmm6
    sha1rnds4   xmm0, xmm2, 3
    sha1msg1    xmm5, xmm6
    vpxor       xmm4, xmm6
    sha1nexte   xmm1, xmm3                          ; rounds 64 through 67
    vmovdqa     xmm2, xmm0
    sha1msg2    xmm4, xmm3
    sha1rnds4   xmm0, xmm1, 3
    sha1msg1    xmm6, xmm3
    vpxor       xmm5, xmm3
    sha1nexte   xmm2, xmm4                          ; rounds 68 through 71
    vmovdqa     xmm1, xmm0
    sha1msg2    xmm5, xmm4
    sha1rnds4   xmm0, xmm2, 3
    vpxor       xmm6, xmm4
    sha1nexte   xmm1, xmm5                          ; rounds 72 through 75
    vmovdqa     xmm2, xmm0
    sha1msg2    xmm6, xmm5
    sha1rnds4   xmm0, xmm1, 3
    sha1nexte   xmm2, xmm6                          ; rounds 76 through 79
    vmovdqa     xmm1, xmm0
    sha1rnds4   xmm0, xmm2, 3
    sha1nexte   xmm1, xmm9                          ; compute intermediate hash
    vpaddd      xmm0, xmm8
    add         rsi, 0x40                           ; next message block
    sub         rdx, 1                              ; if (--rdx != 0)
    jne         .loop                               ;   then .loop
.exit:
    ret


; sha1_transform_blk
;
; CONST:
; rdi, rsi, rdx, rcx, r8, r9
; xmm10..
;
; IN:
; xmm0: working variables ABCD
; xmm1: working variables E000
; xmm3: blk + 0x00
; xmm4: blk + 0x10
; xmm5: blk + 0x20
; xmm6: blk + 0x30
;
; OUT:
; xmm0: working variables ABCD
; xmm1: working variables E000
; xmm8: working variables ABCD SAVE
; xmm9: working variables E000 SAVE
align 0x10
sha1_transform_blk:
    vmovdqa     xmm8, xmm0                          ; save working variables
    vmovdqa     xmm9, xmm1
    vpaddd      xmm1, xmm3                          ; rounds 0 through 3
    vmovdqa     xmm2, xmm0
    sha1rnds4   xmm0, xmm1, 0
    sha1nexte   xmm2, xmm4                          ; rounds 4 through 7
    vmovdqa     xmm1, xmm0
    sha1rnds4   xmm0, xmm2, 0
    sha1msg1    xmm3, xmm4
    sha1nexte   xmm1, xmm5                          ; rounds 8 through 11
    vmovdqa     xmm2, xmm0
    sha1rnds4   xmm0, xmm1, 0
    sha1msg1    xmm4, xmm5
    vpxor       xmm3, xmm5
    sha1nexte   xmm2, xmm6                          ; rounds 12 through 15
    vmovdqa     xmm1, xmm0
    sha1msg2    xmm3, xmm6
    sha1rnds4   xmm0, xmm2, 0
    sha1msg1    xmm5, xmm6
    vpxor       xmm4, xmm6
    sha1nexte   xmm1, xmm3                          ; rounds 16 through 19
    vmovdqa     xmm2, xmm0
    sha1msg2    xmm4, xmm3
    sha1rnds4   xmm0, xmm1, 0
    sha1msg1    xmm6, xmm3
    vpxor       xmm5, xmm3
    sha1nexte   xmm2, xmm4                          ; rounds 20 through 23
    vmovdqa     xmm1, xmm0
    sha1msg2    xmm5, xmm4
    sha1rnds4   xmm0, xmm2, 1
    sha1msg1    xmm3, xmm4
    vpxor       xmm6, xmm4
    sha1nexte   xmm1, xmm5                          ; rounds 24 through 27
    vmovdqa     xmm2, xmm0
    sha1msg2    xmm6, xmm5
    sha1rnds4   xmm0, xmm1, 1
    sha1msg1    xmm4, xmm5
    vpxor       xmm3, xmm5
    sha1nexte   xmm2, xmm6                          ; rounds 28 through 31
    vmovdqa     xmm1, xmm0
    sha1msg2    xmm3, xmm6
    sha1rnds4   xmm0, xmm2, 1
    sha1msg1    xmm5, xmm6
    vpxor       xmm4, xmm6
    sha1nexte   xmm1, xmm3                          ; rounds 32 through 35
    vmovdqa     xmm2, xmm0
    sha1msg2    xmm4, xmm3
    sha1rnds4   xmm0, xmm1, 1
    sha1msg1    xmm6, xmm3
    vpxor       xmm5, xmm3
    sha1nexte   xmm2, xmm4                          ; rounds 36 through 39
    vmovdqa     xmm1, xmm0
    sha1msg2    xmm5, xmm4
    sha1rnds4   xmm0, xmm2, 1
    sha1msg1    xmm3, xmm4
    vpxor       xmm6, xmm4
    sha1nexte   xmm1, xmm5                          ; rounds 40 through 43
    vmovdqa     xmm2, xmm0
    sha1msg2    xmm6, xmm5
    sha1rnds4   xmm0, xmm1, 2
    sha1msg1    xmm4, xmm5
    vpxor       xmm3, xmm5
    sha1nexte   xmm2, xmm6                          ; rounds 44 through 47
    vmovdqa     xmm1, xmm0
    sha1msg2    xmm3, xmm6
    sha1rnds4   xmm0, xmm2, 2
    sha1msg1    xmm5, xmm6
    vpxor       xmm4, xmm6
    sha1nexte   xmm1, xmm3                          ; rounds 48 through 51
    vmovdqa     xmm2, xmm0
    sha1msg2    xmm4, xmm3
    sha1rnds4   xmm0, xmm1, 2
    sha1msg1    xmm6, xmm3
    vpxor       xmm5, xmm3
    sha1nexte   xmm2, xmm4                          ; rounds 52 through 55
    vmovdqa     xmm1, xmm0
    sha1msg2    xmm5, xmm4
    sha1rnds4   xmm0, xmm2, 2
    sha1msg1    xmm3, xmm4
    vpxor       xmm6, xmm4
    sha1nexte   xmm1, xmm5                          ; rounds 56 through 59
    vmovdqa     xmm2, xmm0
    sha1msg2    xmm6, xmm5
    sha1rnds4   xmm0, xmm1, 2
    sha1msg1    xmm4, xmm5
    vpxor       xmm3, xmm5
    sha1nexte   xmm2, xmm6                          ; rounds 60 through 63
    vmovdqa     xmm1, xmm0
    sha1msg2    xmm3, xmm6
    sha1rnds4   xmm0, xmm2, 3
    sha1msg1    xmm5, xmm6
    vpxor       xmm4, xmm6
    sha1nexte   xmm1, xmm3                          ; rounds 64 through 67
    vmovdqa     xmm2, xmm0
    sha1msg2    xmm4, xmm3
    sha1rnds4   xmm0, xmm1, 3
    sha1msg1    xmm6, xmm3
    vpxor       xmm5, xmm3
    sha1nexte   xmm2, xmm4                          ; rounds 68 through 71
    vmovdqa     xmm1, xmm0
    sha1msg2    xmm5, xmm4
    sha1rnds4   xmm0, xmm2, 3
    vpxor       xmm6, xmm4
    sha1nexte   xmm1, xmm5                          ; rounds 72 through 75
    vmovdqa     xmm2, xmm0
    sha1msg2    xmm6, xmm5
    sha1rnds4   xmm0, xmm1, 3
    sha1nexte   xmm2, xmm6                          ; rounds 76 through 79
    vmovdqa     xmm1, xmm0
    sha1rnds4   xmm0, xmm2, 3
    sha1nexte   xmm1, xmm9                          ; compute intermediate hash
    vpaddd      xmm0, xmm8
    ret
