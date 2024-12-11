        default     rel

        global      totp_code_str
        global      totp_sha1_gen
        global      totp_div_30
        global      totp_div

        section     .text

extern  hmac_sha1_update
extern  hmac_sha1_final


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
; key: key
; key_len: key length
; time: time/ moving factor
;
; Return: Snum
;
; uint32_t *(HMAC_SHA1_CTX *ctx, uint64_t t);
totp_sha1_gen:
        endbr64                             ; CET
        push        rbp                     ; prolog
        mov         rbp, rsp
        sub         rsp, 0x20               ; RSP [0x00:0x14] hmac
                                            ; RSP [0x18:0x20] message
                                            ; HOTP(K, T)
        movbe       [rsp + 0x18], rsi       ; save big endian time message
        lea         rsi, [rsp + 0x18]       ; &message
        mov         edx, 8                  ; 8
        call        hmac_sha1_update        ; call(ctx, &message, 8)
        mov         rsi, rsp                ; &hmac
        call        hmac_sha1_final         ; call(ctx, &hmac)
        mov         ecx, [rsp + 0x13]       ; offset
        and         ecx, 0x0F               ; offset &= 0x0F
        movbe       eax, [rsp + rcx]        ; hmac
        and         eax, 0x7FFFFFFF         ; mask
        vpxor       xmm8, xmm8              ; zero
        vmovdqa     [rsp], xmm8             ; zero store
        vmovdqa     [rsp + 0x10], xmm8
        mov         rsp, rbp                ; epilog
        pop         rbp
        ret
