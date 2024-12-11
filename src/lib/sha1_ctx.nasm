%ifndef SHA1_CTX
%define SHA1_CTX

section .rodata align=0x10

sha1_REVERSE_BYTES:
dq      0x08090A0B0C0D0E0F
dq      0x0001020304050607

sha1_INIT_ITX:
dq      0x98BADCFE10325476
dq      0x67452301EFCDAB89
dq      0x00000000C3D2E1F0
dq      0x0000000000000000


; SHA1 internal context
; size = 0x20
struc   sha1_ITX
    .var:       resb    0x14
    ._:         resb    0x04
    .len:       resb    0x08
endstruc

; SHA1 context
; size = 0x60
struc   sha1_CTX
    ._:         resb    sha1_ITX_size
    .blk:       resb    0x40

endstruc

%endif
