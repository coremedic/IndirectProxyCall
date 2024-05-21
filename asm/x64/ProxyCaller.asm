.x64
.model flat, fastcall
option casemap:none
option win64:1

public ProxyCaller

.data

    qwOrignalReturnAddress  QWORD 0
    qwNtStatus              QWORD 0

.code

ProxyCaller PROC
    mov rbx, rdx                        ; Back up struct to rbx
    mov r11, [rbx]                      ; UINT_PTR      pSyscallInstruction
    mov eax, [rbx + 08h]                ; DWORD         dwSsn
    mov r9,  [rbx + 010h]               ; UINT64        argCount
    mov rcx, [rbx + 048h]               ; NTSTATUS*     pNtStatus
    mov qwNtStatus, rcx

    mov rdx, [rsp]                      ; Save original return address to rdx
    mov qwOrignalReturnAddress, rdx     ; Perserve original return address in data segment
    lea r8, [return_handler]            ; Load address of return_handler
    mov [rsp], r8                       ; Overwrite return address with address of return_handler


    cmp r9,  4                          ; Check if there are more than 4 args
    jle register_args                   ; If 4 or fewer args, just load registers

    mov r8,  r9                         ; Back up argCount to r8
    sub r8,  5                          ; Calculate index for last stack arg
    lea r10, [rbx + 038h]               ; Pointer to 5th arg in pArgs

stack_args:
    mov rdx, [r10 + r8*8]               ; Copy arg from pArgs to rdx
    mov [rsp + 028h + r8*8], rdx        ; Load arg onto stack
    dec r8                              ; Move to previous stack arg in pArgs
    jns stack_args                      ; Continue if more stack args remain

register_args:
    mov  r10, [rbx + 018h]              ; Load 1st arg
    dec  r9                             ; Decrement argCount
    test r9, r9                         ; Check for more args
    jz   syscall_jmp                    ; 1 arg syscall
    mov  rdx, [rbx + 020h]              ; Load 2nd arg
    dec  r9
    test r9, r9
    jz   syscall_jmp                    ; 2 arg syscall
    mov  r8,  [rbx + 028h]              ; Load 3rd arg
    dec  r9
    test r9, r9
    jz   syscall_jmp                    ; 3 arg syscall
    mov  r9,  [rbx + 030h]              ; Load 4th arg

syscall_jmp:
    jmp r11                             ; Jump to pSyscallInstruction

return_handler:
    mov rdx, qwOrignalReturnAddress     ; Restore original return address
    mov rcx, [qwNtStatus]               ; Move pNtStatus pointer into rcx
    mov [rcx], eax                      ; Move syscall NTSTATUS return to pNtStatus
    jmp rdx                             ; Jump to original return address

ProxyCaller ENDP

end