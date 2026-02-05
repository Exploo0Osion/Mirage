; SysWhispers3 gate + helpers

.data
PUBLIC g_wSystemCall
PUBLIC g_qSyscallIns
PUBLIC g_qClean
PUBLIC g_qThunk
g_wSystemCall   WORD    0
g_qSyscallIns   QWORD   0
g_qClean        QWORD   0
g_qThunk        QWORD   0

.code
PUBLIC Gate
PUBLIC Descent
PUBLIC SyscallWrapper
PUBLIC get_current_rsp

Gate PROC
    mov g_wSystemCall, cx
    mov g_qSyscallIns, rdx
    mov g_qClean, r8
    mov g_qThunk, r9
    ret
Gate ENDP

SyscallWrapper PROC
    mov r10, rcx
    mov eax, 0
    mov ax, g_wSystemCall
    jmp g_qSyscallIns
SyscallWrapper ENDP

Descent PROC
    jmp SyscallWrapper
Descent ENDP

get_current_rsp proc
    mov rax, rsp
    add rax, 8
    ret
get_current_rsp endp

END
