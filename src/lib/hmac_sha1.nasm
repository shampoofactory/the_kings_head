default rel

global  hmac_sha1_init
global  hmac_sha1_final
global  hmac_sha1_wipe
global  hmac_sha1_update


%include "hmac_sha1_ctx.nasm"
%include "sha1_ctx.nasm"


section .text

extern  sha1_final
extern  sha1_final_with_state
extern  sha1_init
extern  sha1_update
extern  sha1_update_blk


; void *(HMAC_SHA1_CTX *ctx, const uint8_t *key, uint32_t key_len)
;
; OUTPUTS:
; rdi: original value
align 0x10
hmac_sha1_init:
    endbr64                                         ; CET
    push        rbp                                 ; prolog
    mov         rbp, rsp
    sub         rsp, 0x0040                         ; [0000:0040] tmp_key
    call        sha1_init                           ; call(ctx)
    vmovdqa     [rsp], xmm6                         ; zero tmp_key
    vmovdqa     [rsp + 0x10], xmm6
    vmovdqa     [rsp + 0x20], xmm6
    vmovdqa     [rsp + 0x30], xmm6
    cmp         edx, 0x40                           ; if (k_len <= 0x40)
    jbe         .short_key                          ;   then .short_key
.long_key:                                          ; long key, hash key into tmp_key
    call        sha1_update                         ; call(ctx, key, key_len)
    mov         rsi, rsp                            ; &tmp
    call        sha1_final                          ; call(ctx, &tmp)
    jmp         .cont
.short_key:                                         ; short key, copy key into tmp_key
    mov         rax, rdi                            ; save ctx
    mov         rdi, rsp                            ; dst = &tmp_key
    mov         ecx, edx                            ; count = key_len
    rep         movsb                               ; copy
    mov         rdi, rax                            ; ctx
.cont:
    vmovdqa     xmm2, [hmac_sha1_OPAD]              ; OPAD
    vpxor       xmm3, xmm2, [rsp]                   ; load tmp_key ^ IPAD
    vpxor       xmm4, xmm2, [rsp + 0x10]
    vpxor       xmm5, xmm2, [rsp + 0x20]
    vpxor       xmm6, xmm2, [rsp + 0x30]
    vmovdqa     [rsp], xmm3                         ; save tmp_key ^ IPAD
    vmovdqa     [rsp + 0x10], xmm4
    vmovdqa     [rsp + 0x20], xmm5
    vmovdqa     [rsp + 0x30], xmm6
    mov         rsi, rsp                            ; &tmp_key
    mov         edx, 1                              ; 1
    call        sha1_update_blk                     ; call(ctx, &tmp_key, 1)
    vmovdqu     [rdi + hmac_sha1_CTX.ovar], xmm0    ; save H(opad ^ key) working variables
    vpextrd     [rdi + hmac_sha1_CTX.ovar + 0x10], xmm1, 3
    vmovdqa     [rdi + sha1_ITX.var], xmm10         ; save initial state
    vmovdqa     [rdi + sha1_ITX.var + 0x10], xmm11
    vmovdqa     xmm2, [hmac_sha1_XPAD]              ; XPAD (IPAD ^ OPAD)
    vpxor       xmm3, xmm2, [rsp]                   ; tmp_key ^ OPAD
    vpxor       xmm4, xmm2, [rsp + 0x10]
    vpxor       xmm5, xmm2, [rsp + 0x20]
    vpxor       xmm6, xmm2, [rsp + 0x30]
    vmovdqa     [rsp], xmm3                         ; save tmp_key ^ IPAD
    vmovdqa     [rsp + 0x10], xmm4
    vmovdqa     [rsp + 0x20], xmm5
    vmovdqa     [rsp + 0x30], xmm6
    mov         rsi, rsp                            ; &tmp_key
    mov         edx, 1                              ; 1
    call        sha1_update_blk                     ; call(ctx, &tmp_key, 1)
    vmovdqa     [rdi + hmac_sha1_CTX.ivar], xmm0    ; save H(ipad ^ key) working variables
    vpextrd     [rdi + hmac_sha1_CTX.ivar + 0x10], xmm1, 3
    vpxor       xmm0, xmm0                          ; zero
    vmovdqa     [rsp], xmm0                         ; zero tmp_key
    vmovdqa     [rsp + 0x10], xmm0
    vmovdqa     [rsp + 0x20], xmm0
    vmovdqa     [rsp + 0x30], xmm0
    mov         rsp, rbp                            ; epilog
    pop         rbp
    ret


; void sha1_final(HMAC_SHA1_CTX *ctx, uint8_t md[static 0x14]);
;
; CONST:
; rdi
align 0x10
hmac_sha1_final:
    endbr64                                         ; CET
    mov         r10, rsi                            ; save md
    lea         rsi, [rdi + sha1_CTX.blk]           ; &(ctx->blk)
    mov         eax, 0x54                           ; 0x54
    vmovdqu     xmm10, [rdi + hmac_sha1_CTX.ovar]   ; load H(opad ^ key) working variables
    vmovd       xmm11, [rdi + hmac_sha1_CTX.ovar + 0x10]
    vpinsrd     xmm11, eax, 2                       ; set length
    call        sha1_final_with_state               ; call(ctx, &(ctx->blk))
    mov         rsi, r10                            ; md
    mov         eax, 0x40                           ; 0x40
    vmovdqa     xmm10, [rdi + hmac_sha1_CTX.ivar]   ; load H(ipad ^ key) working variables
    vmovd       xmm11, [rdi + hmac_sha1_CTX.ivar + 0x10]
    vpinsrd     xmm11, eax, 2                       ; set length
    jmp         sha1_final_with_state               ; call(ctx, &md)


; bool *(HMAC_SHA1_CTX *ctx, const uint8_t *msg, uint64_t msg_len);
;
; CONST:
; rdi
; xmm11..
align 0x10
hmac_sha1_update:
    endbr64                                         ; CET
    jmp         sha1_update                         ; jump(ctx->sha_CTX, msg, msg_len)


; bool *(HMAC_SHA1_CTX *ctx);
;
; CONST:
; rdi, rsi, rdx, rcx, r8, r9
; rax
; xmm.. except xmm6
;
; OUT:
; xmm6: ZERO
align 0x10
hmac_sha1_wipe:
    endbr64                                         ; CET
    vpxor       xmm6, xmm6                          ; zero
    vmovdqa     [rdi], xmm6
    vmovdqa     [rdi + 0x10], xmm6
    vmovdqa     [rdi + 0x20], xmm6
    vmovdqa     [rdi + 0x30], xmm6
    vmovdqa     [rdi + 0x40], xmm6
    vmovdqa     [rdi + 0x50], xmm6
    vmovdqa     [rdi + 0x60], xmm6
    vmovdqa     [rdi + 0x70], xmm6
    vmovdqa     [rdi + 0x80], xmm6
    ret
