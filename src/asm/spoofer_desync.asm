; SilentMoonwalk Desync Spoofer

.data?

SPOOFER STRUCT
    FirstFrameFunctionPointer       QWORD ?
    SecondFrameFunctionPointer      QWORD ?
    JmpRbxGadget                    QWORD ?
    AddRspXGadget                   QWORD ?
    FirstFrameSize                  QWORD ?
    FirstFrameRandomOffset          QWORD ?
    SecondFrameSize                 QWORD ?
    SecondFrameRandomOffset         QWORD ?
    JmpRbxGadgetFrameSize           QWORD ?
    AddRspXGadgetFrameSize          QWORD ?
    StackOffsetWhereRbpIsPushed     QWORD ?
    JmpRbxGadgetRef                 QWORD ?
    SpoofFunctionPointer            QWORD ?
    ReturnAddress                   QWORD ?
    Nargs                           QWORD ?
    Arg01                           QWORD ?
    Arg02                           QWORD ?
    Arg03                           QWORD ?
    Arg04                           QWORD ?
    Arg05                           QWORD ?
    Arg06                           QWORD ?
    Arg07                           QWORD ?
    Arg08                           QWORD ?
    Arg09                           QWORD ?
    Arg10                           QWORD ?
    Arg11                           QWORD ?
    Arg12                           QWORD ?
SPOOFER ENDS

.code
PUBLIC SpoofCall

; ------------------------------------------------------------------
; Desynchronization Spoofer
; ------------------------------------------------------------------
SpoofCall proc
    ; 保存非易失寄存器 (使用调用方 shadow space)
    mov     [rsp+08h], rbp
    mov     [rsp+10h], rbx
    mov     [rsp+18h], r15

    ; 构建 JMP [RBX] gadget 的引用 (存放在原始栈上)
    mov     rbx, [rcx].SPOOFER.JmpRbxGadget
    mov     [rsp+20h], rbx
    lea     rbx, [rsp+20h]
    mov     [rcx].SPOOFER.JmpRbxGadgetRef, rbx

    ; RBP 作为原始栈锚点
    mov     rbp, rsp

    ; 准备 JMP [RBX] 跳转回来的目标
    lea     rax, restore
    push    rax
    lea     rbx, [rsp]      ; RBX 指向 restore

    ; ==========================================================
    ; Desync 栈伪造构建 (RBP 注入)
    ; ==========================================================

    ; 1. 构建 FirstFrame
    ;    注意: Desync 模式不物理分配 FirstFrameSize
    push    [rcx].SPOOFER.FirstFrameFunctionPointer ; 压入函数地址 (作为 SecondFrame 的返回地址)
    mov     rax, [rcx].SPOOFER.FirstFrameRandomOffset
    add     qword ptr [rsp], rax                    ; 加上偏移，指向函数体内

    ; 2. 计算伪造 RBP (指向原始 ReturnAddress - FirstFrameSize)
    mov     rax, [rcx].SPOOFER.ReturnAddress
    sub     rax, [rcx].SPOOFER.FirstFrameSize

    ; 3. 构建 SecondFrame 并注入伪造 RBP
    sub     rsp, [rcx].SPOOFER.SecondFrameSize
    mov     r10, [rcx].SPOOFER.StackOffsetWhereRbpIsPushed
    mov     [rsp+r10], rax
    push    [rcx].SPOOFER.SecondFrameFunctionPointer
    mov     rax, [rcx].SPOOFER.SecondFrameRandomOffset
    add     qword ptr [rsp], rax

    ; 4. 构建 JmpRbxFrame
    sub     rsp, [rcx].SPOOFER.JmpRbxGadgetFrameSize
    push    [rcx].SPOOFER.JmpRbxGadgetRef

    ; 5. 构建 AddRspFrame
    sub     rsp, [rcx].SPOOFER.AddRspXGadgetFrameSize
    mov     r10, [rcx].SPOOFER.JmpRbxGadget
    mov     r11, [rcx].SPOOFER.AddRspXGadgetFrameSize
    mov     [rsp+r11], r10

    ; 6. 设置 AddRspGadget (syscall 返回地址)
    push    [rcx].SPOOFER.AddRspXGadget
    mov     rax, [rcx].SPOOFER.AddRspXGadgetFrameSize
    mov     [rbp+28h], rax

    ; 7. 设置目标函数
    mov     rax, [rcx].SPOOFER.SpoofFunctionPointer
    jmp     parameter_handler_desync
    jmp execute_desync
SpoofCall endp

restore proc
    mov     rsp, rbp
    mov     rbp, [rsp+08h]
    mov     rbx, [rsp+10h]
    mov     r15, [rsp+18h]

    ret
restore endp

parameter_handler_desync proc
    cmp     [rcx].SPOOFER.Nargs, 8
    je      handle_eight_desync
    cmp     [rcx].SPOOFER.Nargs, 9
    je      handle_nine_desync
    cmp     [rcx].SPOOFER.Nargs, 10
    je      handle_ten_desync
    cmp     [rcx].SPOOFER.Nargs, 11
    je      handle_eleven_desync
    cmp     [rcx].SPOOFER.Nargs, 12
    je      handle_twelve_desync
    cmp     [rcx].SPOOFER.Nargs, 7
    je      handle_seven_desync
    cmp     [rcx].SPOOFER.Nargs, 6
    je      handle_six_desync
    cmp     [rcx].SPOOFER.Nargs, 5
    je      handle_five_desync
    cmp     [rcx].SPOOFER.Nargs, 4
    je      handle_four_desync
    cmp     [rcx].SPOOFER.Nargs, 3
    je      handle_three_desync
    cmp     [rcx].SPOOFER.Nargs, 2
    je      handle_two_desync
    cmp     [rcx].SPOOFER.Nargs, 1
    je      handle_one_desync
    cmp     [rcx].SPOOFER.Nargs, 0
    je      handle_none_desync
parameter_handler_desync endp

handle_eight_desync proc
    push    r15
    mov     r15, [rcx].SPOOFER.Arg08
    mov     [rsp+48h], r15
    pop     r15
    jmp     handle_seven_desync
handle_eight_desync endp
handle_nine_desync proc
    push    r15
    mov     r15, [rcx].SPOOFER.Arg09
    mov     [rsp+50h], r15
    pop     r15
    jmp     handle_eight_desync
handle_nine_desync endp
handle_ten_desync proc
    push    r15
    mov     r15, [rcx].SPOOFER.Arg10
    mov     [rsp+58h], r15
    pop     r15
    jmp     handle_nine_desync
handle_ten_desync endp
handle_eleven_desync proc
    push    r15
    mov     r15, [rcx].SPOOFER.Arg11
    mov     [rsp+60h], r15
    pop     r15
    jmp     handle_ten_desync
handle_eleven_desync endp
handle_twelve_desync proc
    push    r15
    mov     r15, [rcx].SPOOFER.Arg12
    mov     [rsp+68h], r15
    pop     r15
    jmp     handle_eleven_desync
handle_twelve_desync endp
handle_seven_desync proc
    push    r15
    mov     r15, [rcx].SPOOFER.Arg07
    mov     [rsp+40h], r15
    pop     r15
    jmp     handle_six_desync
handle_seven_desync endp
handle_six_desync proc
    push    r15
    mov     r15, [rcx].SPOOFER.Arg06
    mov     [rsp+38h], r15
    pop     r15
    jmp     handle_five_desync
handle_six_desync endp
handle_five_desync proc
    push    r15
    mov     r15, [rcx].SPOOFER.Arg05
    mov     [rsp+30h], r15
    pop     r15
    jmp     handle_four_desync
handle_five_desync endp
handle_four_desync proc
    mov     r9, [rcx].SPOOFER.Arg04
    jmp     handle_three_desync
handle_four_desync endp
handle_three_desync proc
    mov     r8, [rcx].SPOOFER.Arg03
    jmp     handle_two_desync
handle_three_desync endp
handle_two_desync proc
    mov     rdx, [rcx].SPOOFER.Arg02
    jmp     handle_one_desync
handle_two_desync endp
handle_one_desync proc
    mov     rcx, [rcx].SPOOFER.Arg01
    jmp     handle_none_desync
handle_one_desync endp

handle_none_desync proc
    jmp     execute_desync
handle_none_desync endp

execute_desync proc
    jmp     qword ptr rax
execute_desync endp

END
