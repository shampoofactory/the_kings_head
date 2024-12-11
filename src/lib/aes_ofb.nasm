default rel

global  aes256_ofb_decrypt
global  aes256_ofb_encrypt


section .text

; __m128i *(uint8_t *dst, const uint8_t *src, AES256_KS *ks, __m128i iv, uint64_t n_bytes);
align 0x10
aes256_ofb_encrypt:
aes256_ofb_decrypt:
    endbr64                                         ; CET
    test        rcx, rcx                            ; if (n_bytes == 0)
    je          .exit                               ;   then .exit
    push        rbp                                 ; prolog
    mov         rbp, rsp
    sub         rsp, 0x0010                         ; [0000:0010] blk
    xor         eax, eax                            ; offset = 0
    cmp         rcx, 0x10                           ; if (n_bytes < 0x10)
    vmovdqa     xmm1, [rdx]                         ; schedule[0]
    vmovdqa     xmm2 ,[rdx + 0x0010]                ; schedule[1]
    vmovdqa     xmm3 ,[rdx + 0x0020]                ; schedule[2]
    vmovdqa     xmm4 ,[rdx + 0x0030]                ; schedule[3]
    vmovdqa     xmm5 ,[rdx + 0x0040]                ; schedule[4]
    vmovdqa     xmm6 ,[rdx + 0x0050]                ; schedule[5]
    vmovdqa     xmm7 ,[rdx + 0x0060]                ; schedule[6]
    vmovdqa     xmm8 ,[rdx + 0x0070]                ; schedule[7]
    vmovdqa     xmm10,[rdx + 0x0090]                ; schedule[9]
    vmovdqa     xmm11,[rdx + 0x00A0]                ; schedule[10]
    vmovdqa     xmm12,[rdx + 0x00B0]                ; schedule[11]
    vmovdqa     xmm13,[rdx + 0x00C0]                ; schedule[12]
    vmovdqa     xmm14,[rdx + 0x00D0]                ; schedule[13]
    vmovdqa     xmm15,[rdx + 0x00E0]                ; schedule[14]
    jb          .block_sub                          ;   then .block_sub
    jmp         .block_1_init
.block_1:
    add         rax, 0x10                           ; offset += 0x10
.block_1_init:                                      ; invariant 0x10 <= n_bytes
    sub         rcx, 0x10                           ; n_bytes -= 0x10
    vpxor       xmm0, xmm1                          ; round 0 (whitening)
    vmovdqa     xmm1 ,[rdx + 0x0080]                ; schedule[8]
    vaesenc     xmm0, xmm2                          ; round 1
    vaesenc     xmm0, xmm3                          ; round 2
    vaesenc     xmm0, xmm4                          ; round 3
    vaesenc     xmm0, xmm5                          ; round 4
    vaesenc     xmm0, xmm6                          ; round 5
    vaesenc     xmm0, xmm7                          ; round 6
    vaesenc     xmm0, xmm8                          ; round 7
    cmp         rcx, 0x10                           ; if (n_bytes < 0x10)
    vaesenc     xmm0, xmm1                          ; round 8
    vmovdqa     xmm1, [rdx]                         ; schedule[0]
    vaesenc     xmm0, xmm10                         ; round 9
    vaesenc     xmm0, xmm11                         ; round 10
    vaesenc     xmm0, xmm12                         ; round 11
    vaesenc     xmm0, xmm13                         ; round 12
    vaesenc     xmm0, xmm14                         ; round 13
    vaesenclast xmm0, xmm15                         ; round 15
    vpxor       xmm9, xmm0, [rsi + rax]             ; xor cipher output with input block
    vmovdqu     [rdi + rax], xmm9                   ; store output block
    jae         .block_1                            ;   then .block_1
    test        ecx, ecx                            ; if (n_bytes == 0)
    je          .epilog                             ;   then .epilog
    lea         rdi, [rdi + rax + 0x10]             ; update rdi
    lea         rsi, [rsi + rax + 0x10]             ; update rsi
.block_sub:                                         ; invariant 0 <= n_bytes
    vmovdqa     xmm9 ,[rdx + 0x0080]                ; schedule[8]
    mov         r8, rdi                             ; store *dst
    mov         edx, ecx                            ; store n_bytes
    mov         rdi, rsp                            ; *blk
    rep         movsb                               ; copy remaing src bytes into blk
    vpxor       xmm0, xmm1                          ; round 0 (whitening)
    vaesenc     xmm0, xmm2                          ; round 1
    vaesenc     xmm0, xmm3                          ; round 2
    vaesenc     xmm0, xmm4                          ; round 3
    vaesenc     xmm0, xmm5                          ; round 4
    vaesenc     xmm0, xmm6                          ; round 5
    vaesenc     xmm0, xmm7                          ; round 6
    vaesenc     xmm0, xmm8                          ; round 7
    vaesenc     xmm0, xmm9                          ; round 8
    vaesenc     xmm0, xmm10                         ; round 9
    vaesenc     xmm0, xmm11                         ; round 10
    vaesenc     xmm0, xmm12                         ; round 11
    vaesenc     xmm0, xmm13                         ; round 12
    vaesenc     xmm0, xmm14                         ; round 13
    vaesenclast xmm0, xmm15                         ; round 15
    vpxor       xmm0, [rsp]                         ; xor cipher output with blk
    vmovdqa     [rsp], xmm0                         ; store into blk
    mov         rdi, r8                             ; *dst
    mov         rsi, rsp                            ; *blk
    mov         ecx, edx                            ; n_bytes
    rep         movsb                               ; copy remaining bytes into dst
    vpxor       xmm0, xmm0                          ; zero
    vmovdqa     [rsp], xmm0                         ; zero blk
.epilog:
    vzeroall                                        ; zero xmm
    mov         rsp, rbp                            ; epilog
    pop         rbp
.exit:
    ret
