; Compile with: nasm -f win32 vm.asm
; Link with: i686-w64-mingw32-gcc vm.obj -o vm.exe

section .data

SECTION .text
global _start

_start:

;address code area
mov ebx, ADDRESS_CODE_START 	;start code
mov ecx, TOTAL_CODE_SIZE 	;size code
mov edx, PARTIAL_KEY 	;key
xor eax, eax			; end of key
start_main_loop: 		; xor
and edx, 0xFFFFFF00		; set two last bytes to 0
or edx, al				; change two last bytes
start_second_loop:
xor [ebx + ecx], edx
dec ecx
test ecx, ecx
jnz start_second_loop
mov ecx, TOTAL_CODE_SIZE
xor edi, edi
Hash: ;test hash
xor edi, [ebx + ecx]
dec ecx
test ecx, ecx
jnz Hash
cmp edi, CORRECT_HASH
jz run_prog
mov ecx, TOTAL_CODE_SIZE
revert_xor: ;undo xor
xor [ebx + ecx], edx
dec ecx
test ecx, ecx
jnz revert_xor
inc al
jmp start_main_loop
run_prog:
;start