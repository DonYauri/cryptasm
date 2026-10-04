; CryptASM - Caesar / ROT13 / brute-force / frequency toolkit
; x86-64 Linux, NASM.  Build:
;   nasm -f elf64 cryptasm.asm -o cryptasm.o && ld cryptasm.o -o cryptasm

%define SYS_READ  0
%define SYS_WRITE 1
%define SYS_EXIT  60
%define BUFSZ     256

section .data
banner  db 10,"=== CryptASM ===",10,0
menu    db 10,"1) Caesar encrypt",10,"2) Caesar decrypt",10,"3) ROT13",10
        db "4) Brute-force crack",10,"5) Frequency analysis",10,"0) Exit",10,"> ",0
p_text  db "Text: ",0
p_shift db "Shift (1-25): ",0
p_bad   db "Invalid input.",10,0
p_out   db "Result: ",0
p_try   db "Key ",0
colon   db ": ",0
space   db " ",0
nl      db 10,0
p_freq  db "Letter frequencies:",10,0
p_none  db "No letters found.",10,0
p_most  db "Most frequent letter: ",0
p_key   db 10,"If this is English (E most common), likely Caesar key: ",0
stars   times 64 db '*'

section .bss
inbuf    resb BUFSZ
textbuf  resb BUFSZ
workbuf  resb BUFSZ
linebuf  resb 8
numbuf   resb 12
freqtab  resd 26

section .text
global _start

; ---------- I/O helpers (clobber rax, rcx, rdx, rsi, rdi, r11) ----------

; print_z: rdi = pointer to NUL-terminated string
print_z:
        mov rsi, rdi
        xor edx, edx
.len:   cmp byte [rsi+rdx], 0
        je .go
        inc rdx
        jmp .len
.go:    mov edi, 1
        mov eax, SYS_WRITE
        syscall
        ret

; print_uint: eax = unsigned value
print_uint:
        lea rdi, [numbuf+11]
        mov byte [rdi], 0
        mov ecx, 10
.dig:   xor edx, edx
        div ecx
        add dl, '0'
        dec rdi
        mov [rdi], dl
        test eax, eax
        jnz .dig
        jmp print_z                 ; tail call

; read_line: rdi = buffer. Reads byte-by-byte up to newline.
; returns rax = length, or -1 on EOF with no data. Buffer is NUL-terminated.
read_line:
        xor r8d, r8d
        mov r9, rdi
.next:  cmp r8d, BUFSZ-1
        jae .end
        lea rsi, [r9+r8]
        xor edi, edi
        mov edx, 1
        xor eax, eax                ; SYS_READ
        syscall
        test rax, rax
        jle .eof
        cmp byte [r9+r8], 10
        je .end
        inc r8d
        jmp .next
.eof:   test r8d, r8d
        jnz .end
        mov rax, -1
        ret
.end:   mov byte [r9+r8], 0
        mov eax, r8d
        ret

; parse_int: rdi = string -> eax (stops at first non-digit)
parse_int:
        xor eax, eax
.lp:    movzx ecx, byte [rdi]
        sub ecx, '0'
        cmp ecx, 9
        ja .done
        imul eax, eax, 10
        add eax, ecx
        inc rdi
        jmp .lp
.done:  ret

; copy_z: rsi = src, rdi = dst
copy_z:
.lp:    mov al, [rsi]
        mov [rdi], al
        inc rsi
        inc rdi
        test al, al
        jnz .lp
        ret

; ---------- cipher core ----------

; caesar: rdi = buffer (in place), esi = shift 0..25. Non-letters untouched.
caesar:
.lp:    movzx eax, byte [rdi]
        test al, al
        jz .done
        mov edx, eax
        or dl, 0x20                 ; fold to lowercase
        sub dl, 'a'
        cmp dl, 25
        ja .skip                    ; not a letter
        movzx edx, dl
        add edx, esi
        cmp edx, 26
        jb .ok
        sub edx, 26
.ok:    and eax, 0x20               ; keep case bit (0x20 = lower)
        lea eax, [rax+rdx+0x41]
        mov [rdi], al
.skip:  inc rdi
        jmp .lp
.done:  ret

; freq: rdi = text. Prints histogram + guessed key.
freq:
        push rbx
        push r12
        push r13
        mov rsi, rdi
        lea rdi, [freqtab]
        mov ecx, 26
        xor eax, eax
        rep stosd
.cnt:   movzx eax, byte [rsi]
        test al, al
        jz .counted
        or al, 0x20
        sub al, 'a'
        cmp al, 25
        ja .nx
        movzx eax, al
        inc dword [freqtab+rax*4]
.nx:    inc rsi
        jmp .cnt
.counted:
        lea rdi, [p_freq]
        call print_z
        xor r12d, r12d              ; index
        xor r13d, r13d              ; index of max
        xor ebx, ebx                ; max count
.row:   mov eax, [freqtab+r12*4]
        test eax, eax
        jz .skip
        cmp eax, ebx
        jbe .notmax
        mov ebx, eax
        mov r13d, r12d
.notmax:
        mov eax, r12d
        add al, 'A'
        mov [linebuf], al
        mov byte [linebuf+1], ':'
        mov byte [linebuf+2], ' '
        mov byte [linebuf+3], 0
        lea rdi, [linebuf]
        call print_z
        mov eax, [freqtab+r12*4]
        call print_uint
        lea rdi, [space]
        call print_z
        mov edx, [freqtab+r12*4]
        cmp edx, 64
        jbe .bar
        mov edx, 64
.bar:   lea rsi, [stars]
        mov edi, 1
        mov eax, SYS_WRITE
        syscall
        lea rdi, [nl]
        call print_z
.skip:  inc r12d
        cmp r12d, 26
        jb .row
        test ebx, ebx
        jnz .report
        lea rdi, [p_none]
        call print_z
        jmp .out
.report:
        lea rdi, [p_most]
        call print_z
        mov eax, r13d
        add al, 'A'
        mov [linebuf], al
        mov byte [linebuf+1], 0
        lea rdi, [linebuf]
        call print_z
        lea rdi, [p_key]
        call print_z
        lea eax, [r13+22]           ; (idx - 4 + 26)
        xor edx, edx
        mov ecx, 26
        div ecx
        mov eax, edx
        call print_uint
        lea rdi, [nl]
        call print_z
.out:   pop r13
        pop r12
        pop rbx
        ret

; ---------- UI helpers ----------

get_text:
        lea rdi, [p_text]
        call print_z
        lea rdi, [textbuf]
        call read_line
        test rax, rax
        js do_exit
        ret

; returns eax = shift 1..25, or 0 if invalid
get_shift:
        lea rdi, [p_shift]
        call print_z
        lea rdi, [inbuf]
        call read_line
        test rax, rax
        js do_exit
        lea rdi, [inbuf]
        call parse_int
        cmp eax, 25
        jbe .ok
        xor eax, eax
.ok:    ret

show_result:
        lea rdi, [p_out]
        call print_z
        lea rdi, [textbuf]
        call print_z
        lea rdi, [nl]
        jmp print_z

; ---------- main ----------

_start:
        lea rdi, [banner]
        call print_z
main_loop:
        lea rdi, [menu]
        call print_z
        lea rdi, [inbuf]
        call read_line
        test rax, rax
        js do_exit
        movzx eax, byte [inbuf]
        cmp al, '0'
        je do_exit
        cmp al, '1'
        je do_enc
        cmp al, '2'
        je do_dec
        cmp al, '3'
        je do_rot
        cmp al, '4'
        je do_brute
        cmp al, '5'
        je do_freq
bad:    lea rdi, [p_bad]
        call print_z
        jmp main_loop

do_enc: call get_text
        call get_shift
        test eax, eax
        jz bad
        mov esi, eax
        lea rdi, [textbuf]
        call caesar
        call show_result
        jmp main_loop

do_dec: call get_text
        call get_shift
        test eax, eax
        jz bad
        mov esi, 26
        sub esi, eax
        lea rdi, [textbuf]
        call caesar
        call show_result
        jmp main_loop

do_rot: call get_text
        mov esi, 13
        lea rdi, [textbuf]
        call caesar
        call show_result
        jmp main_loop

do_brute:
        call get_text
        mov r12d, 1
.try:   lea rsi, [textbuf]
        lea rdi, [workbuf]
        call copy_z
        mov esi, 26
        sub esi, r12d
        lea rdi, [workbuf]
        call caesar
        lea rdi, [p_try]
        call print_z
        mov eax, r12d
        call print_uint
        lea rdi, [colon]
        call print_z
        lea rdi, [workbuf]
        call print_z
        lea rdi, [nl]
        call print_z
        inc r12d
        cmp r12d, 26
        jb .try
        jmp main_loop

do_freq:
        call get_text
        lea rdi, [textbuf]
        call freq
        jmp main_loop

do_exit:
        mov eax, SYS_EXIT
        xor edi, edi
        syscall
