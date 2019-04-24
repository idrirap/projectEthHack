; Compile with: nasm -f win32 vm.asm
; Link with: i686-w64-mingw32-gcc vm.obj -o vm.exe


[bits 32]

;prologue
push ebx
push ecx
push eax
push edx
push edi
;address code area
mov ebx, ADDRESS_CODE_START 	; start code
mov edx, PARTIAL_KEY 			; key
xor eax, eax					; end of key
start_main_loop: 				; xor
and edx, 0xFFFFFF00				; set two last bytes to 0
or dl, al						; change two last bytes
mov ecx, TOTAL_CODE_SIZE 		; size code
start_second_loop:
sub ecx, 4
xor [ebx + ecx], edx
test ecx, ecx
jnz start_second_loop
xor edi, edi
Hash: ;test hash
xor edi, [ebx + ecx]
add ecx, 4
cmp ecx, TOTAL_CODE_SIZE
jnz Hash
cmp edi, CORRECT_HASH
jz run_prog
revert_xor: 					; undo xor
sub ecx, 4
xor [ebx + ecx], edx
test ecx, ecx
jnz revert_xor
inc al
jmp start_main_loop
run_prog:						; goto start
;epilogue
pop edi
pop edx
pop eax
pop ecx
pop ebx
push ADDRESS_CODE_START
;call ebx
ret