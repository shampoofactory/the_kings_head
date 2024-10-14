        default     rel

        global      sha1_digest
        global      sha1_final
        global      sha1_init
        global      sha1_transform

        section     .data align=0x10

SHUFFLE_CONTROL_MASK:
dq      0x08090A0B0C0D0E0F
dq      0x0001020304050607

INITIAL_HASH_VALUE:
dq      0x89ABCDEF01234567
dq      0x76543210FEDCBA98
dq      0x00000000F0E1D2C3
dq      0x0000000000000000


        section     .text

; void *(uint8_t* md, const uint8_t* m, uint32_t m_len)
sha1_digest:
        push        rbp                 ; prolog
        mov         rbp, rsp
        sub         rsp, 0x40           ; RSP [0x00:0x40] blk
        call        sha1_init           ; init hash
        mov         ecx, edx            ; copy m_len
        shr         edx, 6              ; n_blk = len / 64
        call        sha1_transform      ; transform compete blocks
        mov         rdx, rsp            ; blk = rsp
        call        sha1_final          ; final block
        mov         rsp, rbp            ; epilog
        pop         rbp
        ret


; void *(uint8_t* md, const uint8_t* restrict m, uint8_t* restrict blk, uint32_t m_len)
sha1_final:
        mov         r8, rdi             ; copy md
        mov         r9, rdx             ; copy blk
        mov         r10d, ecx           ; copy m_len
        vpxor       xmm0, xmm0          ; zero
        xor         eax, eax            ; zero
        vmovdqa     [r9], xmm0          ; zero blk minus len
        vmovdqa     [r9 + 0x10], xmm0
        vmovdqa     [r9 + 0x20], xmm0
        mov         [r9 + 0x30], rax
        and         ecx, 0x3F           ; m_len &= 0x3F
        mov         edx, ecx            ; copy m_len & 0x3F
        mov         rdi, r9             ; DI blk
        rep         movsb               ; copy remaining m into blk
        mov         eax, 0x80           ; pad
        mov         [rdi], al           ; append pad
        mov         ecx, edx            ; load m_len & 0x3F
        lea         r10, [r10 * 8]      ; w_len = m_len * 8
        mov         rsi, r9             ; blk = blk
        mov         rdi, r8             ; hash = md
        mov         edx, 1              ; n_blk = 1
        bswap       r10                 ; factor w_len endianess
        cmp         ecx, 0x38           ; if (m_len < 0x38)
        jb          .blk_1              ;   then .blk_1
.blk_0:                                 ; no room for m_len
        call        sha1_transform      ; transform block
        vpxor       xmm0, xmm0          ; zero
        xor         eax, eax            ; zero
        vmovdqa     [r9], xmm0          ; zero blk minus len
        vmovdqa     [r9 + 0x10], xmm0
        vmovdqa     [r9 + 0x20], xmm0
        mov         [r9 + 0x30], rax
        mov         rsi, r9             ; blk = blk
        mov         edx, 1              ; n_blk = 1
.blk_1:                                 ; room for w_len
        mov         [rsi + 0x38], r10   ; write w_len
        call        sha1_transform      ; transform block and exit
.exit:
        vpxor       xmm0, xmm0          ; zero
        vmovdqa     [r9], xmm0          ; zero blk
        vmovdqa     [r9 + 0x10], xmm0
        vmovdqa     [r9 + 0x20], xmm0
        vmovdqa     [r9 + 0x30], xmm0
        ret


; void *(uint8_t* hash)
sha1_init:
        vmovdqa     xmm0, [INITIAL_HASH_VALUE]  ; load initial hash
        mov         eax, [INITIAL_HASH_VALUE + 0x0010]
        vmovdqu     [rdi], xmm0                 ; save initial hash
        mov         [rdi + 0x10], eax
        ret


; void *(uint8_t* hash, const uint8_t* blk, int32_t n_blk)
sha1_transform:
        test        edx, edx            ; if (n == 0)
        je          .exit               ;   then .exit
        vmovdqa     xmm7, [SHUFFLE_CONTROL_MASK]    ; load mask
        vmovdqu     xmm4, [rdi]         ; load initial hash value
        vmovd       xmm5, [rdi + 0x10]
        vpshufb     xmm4, xmm7          ; reverse bytes
        vpshufb     xmm5, xmm7          ; reverse bytes
.loop:
        vmovdqa     xmm8, xmm4          ; save working variables
        vmovdqa     xmm9, xmm5
        vmovdqu     xmm0, [rsi]         ; rounds 0 through 3
        vpshufb     xmm0, xmm7
        vpaddd      xmm5, xmm0
        vmovdqa     xmm6, xmm4
        sha1rnds4   xmm4, xmm5, 0
        vmovdqu     xmm1, [rsi + 0x10]  ; rounds 4 through 7
        vpshufb     xmm1, xmm7
        sha1nexte   xmm6, xmm1
        vmovdqa     xmm5, xmm4
        sha1rnds4   xmm4, xmm6, 0
        sha1msg1    xmm0, xmm1
        vmovdqu     xmm2, [rsi + 0x20]  ; rounds 8 through 11
        vpshufb     xmm2, xmm7
        sha1nexte   xmm5, xmm2
        vmovdqa     xmm6, xmm4
        sha1rnds4   xmm4, xmm5, 0
        sha1msg1    xmm1, xmm2
        vpxor       xmm0, xmm2
        vmovdqu     xmm3, [rsi + 0x30]  ; rounds 12 through 15
        vpshufb     xmm3, xmm7
        sha1nexte   xmm6, xmm3
        vmovdqa     xmm5, xmm4
        sha1msg2    xmm0, xmm3
        sha1rnds4   xmm4, xmm6, 0
        sha1msg1    xmm2, xmm3
        vpxor       xmm1, xmm3
        sha1nexte   xmm5, xmm0          ; rounds 16 through 19
        vmovdqa     xmm6, xmm4
        sha1msg2    xmm1, xmm0
        sha1rnds4   xmm4, xmm5, 0
        sha1msg1    xmm3, xmm0
        vpxor       xmm2, xmm0
        sha1nexte   xmm6, xmm1          ; rounds 20 through 23
        vmovdqa     xmm5, xmm4
        sha1msg2    xmm2, xmm1
        sha1rnds4   xmm4, xmm6, 1
        sha1msg1    xmm0, xmm1
        vpxor       xmm3, xmm1
        sha1nexte   xmm5, xmm2          ; rounds 24 through 27
        vmovdqa     xmm6, xmm4
        sha1msg2    xmm3, xmm2
        sha1rnds4   xmm4, xmm5, 1
        sha1msg1    xmm1, xmm2
        vpxor       xmm0, xmm2
        sha1nexte   xmm6, xmm3          ; rounds 28 through 31
        vmovdqa     xmm5, xmm4
        sha1msg2    xmm0, xmm3
        sha1rnds4   xmm4, xmm6, 1
        sha1msg1    xmm2, xmm3
        vpxor       xmm1, xmm3
        sha1nexte   xmm5, xmm0          ; rounds 32 through 35
        vmovdqa     xmm6, xmm4
        sha1msg2    xmm1, xmm0
        sha1rnds4   xmm4, xmm5, 1
        sha1msg1    xmm3, xmm0
        vpxor       xmm2, xmm0
        sha1nexte   xmm6, xmm1          ; rounds 36 through 39
        vmovdqa     xmm5, xmm4
        sha1msg2    xmm2, xmm1
        sha1rnds4   xmm4, xmm6, 1
        sha1msg1    xmm0, xmm1
        vpxor       xmm3, xmm1
        sha1nexte   xmm5, xmm2          ; rounds 40 through 43
        vmovdqa     xmm6, xmm4
        sha1msg2    xmm3, xmm2
        sha1rnds4   xmm4, xmm5, 2
        sha1msg1    xmm1, xmm2
        vpxor       xmm0, xmm2
        sha1nexte   xmm6, xmm3          ; rounds 44 through 47
        vmovdqa     xmm5, xmm4
        sha1msg2    xmm0, xmm3
        sha1rnds4   xmm4, xmm6, 2
        sha1msg1    xmm2, xmm3
        vpxor       xmm1, xmm3
        sha1nexte   xmm5, xmm0          ; rounds 48 through 51
        vmovdqa     xmm6, xmm4
        sha1msg2    xmm1, xmm0
        sha1rnds4   xmm4, xmm5, 2
        sha1msg1    xmm3, xmm0
        vpxor       xmm2, xmm0
        sha1nexte   xmm6, xmm1          ; rounds 52 through 55
        vmovdqa     xmm5, xmm4
        sha1msg2    xmm2, xmm1
        sha1rnds4   xmm4, xmm6, 2
        sha1msg1    xmm0, xmm1
        vpxor       xmm3, xmm1
        sha1nexte   xmm5, xmm2          ; rounds 56 through 59
        vmovdqa     xmm6, xmm4
        sha1msg2    xmm3, xmm2
        sha1rnds4   xmm4, xmm5, 2
        sha1msg1    xmm1, xmm2
        vpxor       xmm0, xmm2
        sha1nexte   xmm6, xmm3          ; rounds 60 through 63
        vmovdqa     xmm5, xmm4
        sha1msg2    xmm0, xmm3
        sha1rnds4   xmm4, xmm6, 3
        sha1msg1    xmm2, xmm3
        vpxor       xmm1, xmm3
        sha1nexte   xmm5, xmm0          ; rounds 64 through 67
        vmovdqa     xmm6, xmm4
        sha1msg2    xmm1, xmm0
        sha1rnds4   xmm4, xmm5, 3
        sha1msg1    xmm3, xmm0
        vpxor       xmm2, xmm0
        sha1nexte   xmm6, xmm1          ; rounds 68 through 71
        vmovdqa     xmm5, xmm4
        sha1msg2    xmm2, xmm1
        sha1rnds4   xmm4, xmm6, 3
        vpxor       xmm3, xmm1
        sha1nexte   xmm5, xmm2          ; rounds 72 through 75
        vmovdqa     xmm6, xmm4
        sha1msg2    xmm3, xmm2
        sha1rnds4   xmm4, xmm5, 3
        sha1nexte   xmm6, xmm3          ; rounds 76 through 79
        vmovdqa     xmm5, xmm4
        sha1rnds4   xmm4, xmm6, 3
        sha1nexte   xmm5, xmm9          ; compute intermediate hash
        vpaddd      xmm4, xmm8
        add         rsi, 0x40           ; next message block
        sub         edx, 1              ; if (--n_blk != 0)
        jne         .loop               ;   then .loop
        vpshufb     xmm4, xmm7          ; reverse bytes
        vpshufb     xmm5, xmm7          ; reverse bytes
        vmovdqu     [rdi], xmm4         ; save hash value
        vmovd       [rdi + 0x10], xmm5
.exit:
        ret

