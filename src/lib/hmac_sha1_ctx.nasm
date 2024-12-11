%ifndef HMAC_SHA1_CTX
%define HMAC_SHA1_CTX

section .rodata align=0x10

hmac_sha1_XPAD:   ; IPAD ^ OPAD
dq      0x6A6A6A6A6A6A6A6A
dq      0x6A6A6A6A6A6A6A6A

hmac_sha1_OPAD:
dq      0x5C5C5C5C5C5C5C5C
dq      0x5C5C5C5C5C5C5C5C

; HMAC_SHA1 context
; CTX_size = 0x90
struc   hmac_sha1_CTX
    .sha_CTX:   resb    0x60
    .ivar:      resb    0x14
    .ovar:      resb    0x14
endstruc

%endif
