        default     rel

        global      sys_exit
        global      sys_print
        global      sys_write
        global      sys_time

        section     .text

; void *(uint32_t status)
sys_exit:
        mov         rax, 0x3C           ; sys_exit
        syscall

; uint64_t *(const uint8_t* str, uint32_t len)
sys_print:
        mov         rdx, rsi            ; len
        mov         rsi, rdi            ; str
        mov         rdi, 1              ; stdout
        mov         rax, 1              ; sys_write
        syscall
        ret

; uint64_t *(uint32_t fd, const uint8_t* buf, uint64_t count)
sys_write:
        mov         rax, 1              ; sys_write
        syscall
        ret

; uint64_t *()
sys_time:
        mov rax, 0xC9
        xor edi, edi
        syscall
        ret
