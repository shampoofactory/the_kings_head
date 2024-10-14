        default     rel

        global      hmac_sha1

        section     .data align=0x10

XPAD:   ; IPAD ^ OPAD
dq      0x6A6A6A6A6A6A6A6A
dq      0x6A6A6A6A6A6A6A6A
IPAD:
dq      0x3636363636363636
dq      0x3636363636363636


        section     .text

extern  sha1_digest
extern  sha1_final
extern  sha1_init
extern  sha1_transform


; void *(uint8_t *hmac, const uint8_t *k, uint32_t k_len, const uint8_t *m, uint32_t m_len)
hmac_sha1:
        push        rbp                 ; prolog
        mov         rbp, rsp
        sub         rsp, 0xB0           ; RSP [0x70:0xB0] blk
                                        ; RSP [0x60:0x68] *hmac
                                        ; RSP [0x58:0x60] *m
                                        ; RSP [0x54:0x58] m_len
                                        ; RSP [0x40:0x54] imd (inner message digest)
                                        ; RSP [0x00:0x40] key
        mov         [rsp + 0x54], r8d   ; save  m_len
        mov         [rsp + 0x58], rcx   ; save  *m
        mov         [rsp + 0x60], rdi   ; save  *hmac
        vpxor       xmm0, xmm0          ; zero
        vmovdqa     [rsp], xmm0         ; zero key
        vmovdqa     [rsp + 0x10], xmm0
        vmovdqa     [rsp + 0x20], xmm0
        vmovdqa     [rsp + 0x30], xmm0
        mov         rdi, rsp            ; DI / md = key
        cmp         edx, 0x40           ; if (k_len <= 0x40)
        jbe         .short_key          ;   then .short_key
.long_key:                              ; long key, hash required
        call        sha1_digest
        jmp         .cont
.short_key:                             ; short key
        mov         ecx, edx            ; set k_len
        rep         movsb               ; copy k into key
.cont:
        vmovdqa     xmm3, [IPAD]        ; load IPAD
        vpxor       xmm0, xmm3, [rsp]   ; key  ^ IPAD
        vmovdqa     [rsp], xmm0
        vpxor       xmm1, xmm3, [rsp + 0x10]    ; key  ^ IPAD
        vmovdqa     [rsp + 0x10], xmm1
        vpxor       xmm2, xmm3, [rsp + 0x20]    ; key  ^ IPAD
        vmovdqa     [rsp + 0x20], xmm2
        vpxor       xmm3, xmm3, [rsp + 0x30]    ; key  ^ IPAD
        vmovdqa     [rsp + 0x30], xmm3
        lea         rdi, [rsp + 0x40]   ; md = imd
        call        sha1_init           ; sha1 init
        mov         rsi, rsp            ; blk = key ^ IPAD
        mov         edx, 1              ; n_blk = 1
        call        sha1_transform      ; sha1 transform: key ^ IPAD
        mov         rsi, [rsp + 0x58]   ; blk = *m
        mov         edx, [rsp + 0x54]   ; load m_len
        mov         r8d, edx            ; copy m_len
        shr         edx, 6              ; n_blk  = m_len / 64
        call        sha1_transform      ; sha1 transform: complete message blocks
        lea         rdx, [rsp + 0x70]   ; blk
        lea         ecx, [r8d + 0x40]   ; m_len = m_len + 0x40
        call        sha1_final          ; sha1 final
        vmovdqa     xmm3, [XPAD]        ; load XPAD
        vpxor       xmm0, xmm3, [rsp]   ; key  ^ XPAD (key ^ OPAD)
        vmovdqa     [rsp], xmm0
        vpxor       xmm1, xmm3, [rsp + 0x10]    ; key  ^ XPAD (key ^ OPAD)
        vmovdqa     [rsp + 0x10], xmm1
        vpxor       xmm2, xmm3, [rsp + 0x20]    ; key  ^ XPAD (key ^ OPAD)
        vmovdqa     [rsp + 0x20], xmm2
        vpxor       xmm3, xmm3, [rsp + 0x30]    ; key  ^ XPAD (key ^ OPAD)
        vmovdqa     [rsp + 0x30], xmm3
        mov         rdi, [rsp + 0x60]   ; md = *hmac
        call        sha1_init           ; sha1 init
        mov         rsi, rsp            ; blk = (key ^ OPAD) | imd
        mov         edx, 1
        call        sha1_transform      ; sha1 transform: key ^ IPAD
        lea         rdx, [rsp + 0x70]   ; blk
        mov         ecx, 0x54           ; m_len = 0x54
        call        sha1_final          ; sha1 final
        vpxor       xmm0, xmm0          ; zero
        vmovdqa     [rsp], xmm0         ; zero key, imd and store
        vmovdqa     [rsp + 0x10], xmm0
        vmovdqa     [rsp + 0x20], xmm0
        vmovdqa     [rsp + 0x30], xmm0
        vmovdqa     [rsp + 0x40], xmm0
        vmovdqa     [rsp + 0x50], xmm0  
        vmovdqa     [rsp + 0x60], xmm0  
        mov         rsp, rbp            ; epilog
        pop         rbp
        ret
