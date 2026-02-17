default rel
global main

extern GetCurrentProcess
extern OpenProcessToken
extern LookupPrivilegeValueA
extern CloseHandle
extern AdjustTokenPrivileges
extern NtSystemDebugControl
extern CreateFileA
extern CreateEventA
extern printf

section .data
    SE_DEBUG_NAME db "SeDebugPrivilege", 0
    SE_SYSTEM_PROFILE_NAME db "SeSystemProfilePrivilege", 0
    file_name db "dump.bin", 0
    fmt_status db "NTSTATUS: 0x%08X", 0x0a, 0
    
    .msgs:
        msg_okay db "Success", 0x0a, 0
        error_msg_open_token db "Failed to open process token.",0x0a, 0
        error_msg_lookup_privilege db "Failed to lookup privilege value.",0x0a, 0
        error_msg_adjust_privileges db "Failed to adjust token privileges.",0x0a, 0
        error_msg_create_file db "Failed to create file.",0x0a, 0

section .bss
    hToken resq 1
    hEvent resq 1
    luid resd 2 ; DWORD LowPart, LONG HighPart
    tokenPrivileges resb 16 ; token priv struct 
    sysdbgLiveDumpControl resb 64 ; sysdbg control struct
    returnLength resd 1

section .text
main:
    push rbx
    sub rsp, 64 ; shadow space and allign

    mov rbx, SE_DEBUG_NAME
    call adjust_privileges
     
    mov rbx, SE_SYSTEM_PROFILE_NAME
    call adjust_privileges

    mov rcx, file_name
    mov rdx, 0xC0000000 ; GENERIC_READ | GENERIC_WRITE
    mov r8, 0 ; dwShareMode 0
    mov r9, 0 ; security attributes null
    mov dword [rsp + 32], 2
    mov dword [rsp + 40], 0x80
    mov qword [rsp + 48], 0
    call CreateFileA
    mov rbx, rax ; save file handle in rbx

    cmp rax, -1 ; INVALID_HANDLE_VALUE
    jnz .create_file_success

    mov rcx, error_msg_create_file
    call printf

    jmp .end

    .create_file_success:
    mov rcx, 0 ; event attributes
    mov rdx, 1 ; manual reset
    mov r8, 0 ; initial state
    mov r9, 0 ; name null
    call CreateEventA
    mov [hEvent], rax ; save event handle

    mov dword [sysdbgLiveDumpControl], 1 ; version = 1
    mov [sysdbgLiveDumpControl + 40], rbx ; FileHandle
    mov rax, [hEvent]
    mov [sysdbgLiveDumpControl + 48], rax ; cancel event
    mov dword [sysdbgLiveDumpControl + 56], 0 ; flags

    mov rcx, 37 ; SysDbgLiveKernelDump
    lea rdx, [rel sysdbgLiveDumpControl] ; input_buffer
    mov r8, 64 ; input_buffer_length
    mov r9, 0 ; output_buffer
    mov dword [rsp + 32], 0
    mov qword [rsp + 40], 0
    lea rax, [rel returnLength]
    mov [rsp + 48], rax
    call NtSystemDebugControl
    mov rdx, rax
    mov rcx, fmt_status
    call printf

    .end:
    add rsp, 64 ; restore shadow space
    pop rbx
    ret

adjust_privileges:
    push rdi  ; save rdi stack 16 at this point<
    sub rsp, 48 ; 32 bytes shadow space & 16 byte alligned
    call GetCurrentProcess
    mov rdi, rax ; own process handle

    mov rcx, rdi
    mov rdx, 0x28 ; TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES
    lea r8, [rel hToken]
    call OpenProcessToken

    cmp rax, 0
    jnz .open_token_success

    mov rcx, error_msg_open_token
    call printf

    jmp .end

    .open_token_success:
    mov rcx, 0 ; lpSystemName = NULL
    mov rdx, rbx ; lpName
    lea r8, [rel luid] ; lpLuid
    call LookupPrivilegeValueA
    cmp rax, 0
    jnz .lookup_success

    mov rcx, [hToken]
    call CloseHandle ; cleanup

    mov rcx, error_msg_lookup_privilege
    call printf

    jmp .end

    .lookup_success:
    mov dword [tokenPrivileges], 1 ; PrivilegeCount
    mov rax, [luid] ; Luid
    mov [tokenPrivileges + 4], rax ; Privilges[0].Luid = Luid
    mov dword [tokenPrivileges + 12], 2 ; Privilges[0].Attributes = SE_PRIVILEGE_ENABLED

    mov rcx, [hToken]
    mov rdx, 0 ; DisableAllPrivileges = FALSE
    lea r8, [rel tokenPrivileges] ; NewState
    mov r9, 0x10 ; sizeof TOKEN_PRIVILEGES
    mov qword [rsp + 32], 0 ; PreviousState = NULL
    mov qword [rsp + 40], 0 ; ReturnLength = NULL
    call AdjustTokenPrivileges

    cmp rax, 0
    jnz .adjust_success

    mov rcx, [hToken]
    call CloseHandle ; cleanup

    mov rcx, error_msg_adjust_privileges
    call printf

    jmp .end

    .adjust_success:
    mov rcx, msg_okay
    call printf

    .end:
    add rsp, 48 ; restore stack
    pop rdi ; restore rdi
    ret
