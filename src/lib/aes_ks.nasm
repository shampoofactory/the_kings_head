default rel

global  aes256_ks_dec_gen
global  aes256_ks_enc_gen
global  aes256_ks_dec_wipe
global  aes256_ks_enc_wipe


section .text

; void *(AES256_KS_ENC *ctx, uint8_t key[static AES256_KEY_LEN]);
align 0x10
aes256_ks_enc_gen:
    vmovdqu     xmm0, [rsi]                         ; load key
    vmovdqu     xmm1, [rsi + 0x10]
    vmovdqa     [rdi], xmm0                         ; round 0
    vmovdqa     [rdi + 0x0010], xmm1                ; round 1
    vaeskeygenassist xmm2, xmm1, 0x1                ; round 2
    call        .assist_0
    vmovdqa     [rdi + 0x0020], xmm0
    vaeskeygenassist xmm2, xmm0, 0x0                ; round 3
    call        .assist_1
    vmovdqa     [rdi + 0x0030], xmm1
    vaeskeygenassist xmm2, xmm1, 0x2                ; round 4
    call        .assist_0
    vmovdqa     [rdi + 0x0040], xmm0
    vaeskeygenassist xmm2, xmm0, 0x0                ; round 5
    call        .assist_1
    vmovdqa     [rdi + 0x0050], xmm1
    vaeskeygenassist xmm2, xmm1, 0x4                ; round 6
    call        .assist_0
    vmovdqa     [rdi + 0x0060], xmm0
    vaeskeygenassist xmm2, xmm0, 0x0                ; round 7
    call        .assist_1
    vmovdqa     [rdi + 0x0070], xmm1
    vaeskeygenassist xmm2, xmm1, 0x8                ; round 8
    call        .assist_0
    vmovdqa     [rdi + 0x0080], xmm0
    vaeskeygenassist xmm2, xmm0, 0x0                ; round 9
    call        .assist_1
    vmovdqa     [rdi + 0x0090], xmm1
    vaeskeygenassist xmm2, xmm1, 0x10               ; round 10
    call        .assist_0
    vmovdqa     [rdi + 0x00A0], xmm0
    vaeskeygenassist xmm2, xmm0, 0x0                ; round 11
    call        .assist_1
    vmovdqa     [rdi + 0x00B0], xmm1
    vaeskeygenassist xmm2, xmm1, 0x20               ; round 12
    call        .assist_0
    vmovdqa     [rdi + 0x00C0], xmm0
    vaeskeygenassist xmm2, xmm0, 0x0                ; round 13
    call        .assist_1
    vmovdqa     [rdi + 0x00D0], xmm1
    vaeskeygenassist xmm2, xmm1, 0x40               ; round 14
    call        .assist_0
    vmovdqa     [rdi + 0x00E0], xmm0
    ret
.assist_0:
    vpshufd     xmm2, xmm2, 0xFF
    vpslldq     xmm4, xmm0, 0x08
    vpslldq     xmm3, xmm0, 0x04
    vpslldq     xmm5, xmm0, 0x0C
    vpxor       xmm2, xmm2, xmm4
    vpxor       xmm3, xmm3, xmm5
    vpxor       xmm2, xmm2, xmm3
    vpxor       xmm0, xmm2, xmm0
    ret
.assist_1:
    vpshufd     xmm2, xmm2, 0xAA
    vpslldq     xmm4, xmm1, 0x08
    vpslldq     xmm3, xmm1, 0x04
    vpslldq     xmm5, xmm1, 0x0C
    vpxor       xmm2, xmm2, xmm4
    vpxor       xmm3, xmm3, xmm5
    vpxor       xmm2, xmm2, xmm3
    vpxor       xmm1, xmm2, xmm1
    ret


; void *(AES256_KS_DEC *ctx, AES256_KS_ENC *src)
align 0x10
aes256_ks_dec_gen:
    vmovdqa     xmm0, [rsi + 0x00E0]                ; round 0
    vaesimc     xmm1, [rsi + 0x00D0]                ; round 1
    vaesimc     xmm2, [rsi + 0x00C0]                ; round 2
    vaesimc     xmm3, [rsi + 0x00B0]                ; round 3
    vmovdqa     [rdi], xmm0
    vmovdqa     [rdi + 0x0010], xmm1
    vmovdqa     [rdi + 0x0020], xmm2
    vmovdqa     [rdi + 0x0030], xmm3
    vaesimc     xmm0, [rsi + 0x00A0]                ; round 4
    vaesimc     xmm1, [rsi + 0x0090]                ; round 5
    vaesimc     xmm2, [rsi + 0x0080]                ; round 6
    vaesimc     xmm3, [rsi + 0x0070]                ; round 7
    vmovdqa     [rdi + 0x0040], xmm0
    vmovdqa     [rdi + 0x0050], xmm1
    vmovdqa     [rdi + 0x0060], xmm2
    vmovdqa     [rdi + 0x0070], xmm3
    vaesimc     xmm0, [rsi + 0x0060]                ; round 8
    vaesimc     xmm1, [rsi + 0x0050]                ; round 9
    vaesimc     xmm2, [rsi + 0x0040]                ; round 10
    vaesimc     xmm3, [rsi + 0x0030]                ; round 11
    vmovdqa     [rdi + 0x0080], xmm0
    vmovdqa     [rdi + 0x0090], xmm2
    vmovdqa     [rdi + 0x00A0], xmm3
    vmovdqa     [rdi + 0x00B0], xmm4
    vaesimc     xmm0, [rsi + 0x0020]                ; round 12
    vaesimc     xmm1, [rsi + 0x0010]                ; round 13
    vmovdqa     xmm2, [rsi]                         ; round 14
    vmovdqa     [rdi + 0x00C0], xmm0
    vmovdqa     [rdi + 0x00D0], xmm1
    vmovdqa     [rdi + 0x00E0], xmm2
    ret


; void *(AES256_KS_ENC *ctx);
; void *(AES256_KS_DEC *ctx);
align 0x10
aes256_ks_dec_wipe:
aes256_ks_enc_wipe:
    vpxor       xmm0, xmm0                          ; zero
    vmovdqa     [rdi], xmm0
    vmovdqa     [rdi + 0x0010], xmm0
    vmovdqa     [rdi + 0x0020], xmm0
    vmovdqa     [rdi + 0x0030], xmm0
    vmovdqa     [rdi + 0x0040], xmm0
    vmovdqa     [rdi + 0x0050], xmm0
    vmovdqa     [rdi + 0x0060], xmm0
    vmovdqa     [rdi + 0x0070], xmm0
    vmovdqa     [rdi + 0x0080], xmm0
    vmovdqa     [rdi + 0x0090], xmm0
    vmovdqa     [rdi + 0x00A0], xmm0
    vmovdqa     [rdi + 0x00B0], xmm0
    vmovdqa     [rdi + 0x00C0], xmm0
    vmovdqa     [rdi + 0x00D0], xmm0
    vmovdqa     [rdi + 0x00E0], xmm0
    ret
