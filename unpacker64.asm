; Compile with: nasm -f win32 vm.asm
; Link with: i686-w64-mingw32-gcc vm.obj -o vm.exe


[bits 64]

;prologue
push rbx
push rdx
push rax
push rdx
push rdi
;address code area
mov rbx, ADDRESS_CODE_START 	; start code
mov rdx, PARTIAL_KEY 			; key
xor rax, rax					; end of key
start_main_loop: 				; xor
and rdx, 0xFFFFFFFFFFFFFF00		; set two last bytes to 0
or dl, al						; change two last bytes
mov rdx, TOTAL_CODE_SIZE 		; size code
start_second_loop:
sub rdx, 8
xor [rbx + rdx], rdx
test rdx, rdx
jnz start_second_loop
xor rdi, rdi
Hash: ;test hash
xor rdi, [rbx + rdx]
add rdx, 8
cmp rdx, TOTAL_CODE_SIZE
jnz Hash
cmp rdi, CORRECT_HASH
jz run_prog
revert_xor: 					; undo xor
sub rdx, 8
xor [rbx + rdx], rdx
test rdx, rdx
jnz revert_xor
inc al
jmp start_main_loop
run_prog:						; goto start
;epilogue
pop rdi
pop rdx
pop rax
pop rdx
pop rbx
push ADDRESS_OEP
;call rbx
ret