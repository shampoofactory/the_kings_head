        default     rel

        global      totp_code_str
        global      totp_sha1_gen
        global      totp_div_30
        global      totp_div

        section     .data align=0x10

        section     .text

extern  hmac_sha1


; Compute a HOTP value ASCII string
; 
; RFC4226#section-5.3
;
; Pseudocode:
; dst = Integer.toString(Snum mod 10^Digit)
; 
; Parameters:
;      dst: n_digits length destination buffer
;        v: Snum
; n_digits: number of digits
;
; void *(uint8_t* dst, uint64_t v, uint32_t n_digits)
totp_code_str:
        mov         r8, 0xCCCCCCCCCCCCCCCD  ; 10 reciprocal
        mov         ecx, edx            ; c = n (as mul clobbers rdx)
        and         ecx, 0x0F           ; cap n_digits
.loop:
        sub         rcx, 1              ; if (--c < 0)
        js          .exit               ;   then .exit
        mov         rax, rsi            ; a = v
        mul         r8                  ; d = a * reciprocal
        shr         rdx, 3              ; d >>= 3   (v / 10)
        lea         rax, [rdx + rdx * 4]; a = d * 5
        add         rax, rax            ; a *= 2
        sub         rsi, rax            ; v -= a    (v % 10)
        add         esi, 0x30           ; v += '0'  (to ASCII digit)
        mov         [rdi + rcx], sil    ; store
        mov         rsi, rdx            ; v = d
        jmp         .loop
.exit:
        ret


; t = ts / s
; uint64_t *(uint64_t ts, uint32_t s)
totp_div:
        mov         rax, rdi            ; move ts
        xor         edx, edx            ; zero
        div         rsi                 ; RDX:RAX = ts / s
        ret

; t = ts / 30
; uint64_t *(uint64_t ts)
totp_div_30:
                                        ; via reciprocal multiplication
        mov         rax, 0x8888888888888889 ; reciprocal
        mul         rdi                 ; RDX:RAX = ts * r
        mov         rax, rdx            ; trunc(ts * r)
        shr         rax, 4              ; trunc(ts * r) / 0x10
        ret


; Generate TOTP value
;
; RFC6238#section-4.2
; RFC4226#section-5.3
;
; Pseudocode:
; HS = HMAC-SHA-1(K, T) 
; Sbits = DT(HS) // Dynamic Truncation
; Snum  = StToNum(Sbits)
; return Snum
;
; Parameters:
;      k: key
;  k_len: key length
;      t: time/ moving factor
;
; Return: Snum
;
; uint32_t *(const uint8_t *k, uint32_t k_len, uint64_t t);
totp_sha1_gen:
        push        rbp                 ; prolog
        mov         rbp, rsp
        sub         rsp, 0x20           ; RSP [0x18:0x20] m
                                        ; RSP [0x00:0x14] hmac
                                        ; HOTP(K, T)
        bswap       rdx                 ; factor endianess
        mov         [rsp + 0x18], rdx   ; save t as m
        lea         rcx, [rsp + 0x18]   ; *m = &m
        mov         rdx, rsi            ; k_len = k_len
        mov         rsi, rdi            ; *k = *k
        mov         rdi, rsp            ; *hmac = &hmac
        mov         r8d, 8              ; m_len = 8
        call        hmac_sha1           ; hmac sha1
                                        ; DT(HS)
        mov         cl, [rsp + 0x13]    ; offset
        and         ecx, 0x0F           ; offset &= 0x0F
        mov         eax, [rsp + rcx]    ; hmac
        bswap       eax                 ; factor endianess
        and         eax, 0x7FFFFFFF     ; mask
                                        ;
        vpxor       xmm0, xmm0          ; zero
        vmovdqa     [rsp], xmm0         ; zero store
        vmovdqa     [rsp + 0x10], xmm0
        mov         rsp, rbp            ; epilog
        pop         rbp
        ret
