// Entered by a CALL in the 0.7.4 server result handler. Keep the frame and
// incoming Win64 arguments intact. The original callee receives the return.
.text
.p2align 4
.globl tfm2_faster_days_draft
tfm2_faster_days_draft:
    cmp qword ptr [rdx], 5
    jne .Loriginal
    cmp byte ptr [rdx + 0x1b8], 0
    jne .Loriginal

    // Game database and server state remain on the handler's stack.
    mov r10, [rbp + 0x20608]
    test r10, r10
    je .Loriginal
    cmp byte ptr [r10 + 0x736], 0
    jne .Loriginal
    mov r10, [rbp + 0x205f0]
    test r10, r10
    je .Loriginal
    cmp qword ptr [r10 + 0xba8], 1
    jne .Loriginal
    cmp byte ptr [r10 + 0x13d0], 0
    jne .Loriginal
    cmp byte ptr [r10 + 0x13d4], 0
    jne .Loriginal

    // Empty, deleted and padding control bytes all have the top bit set.
    // The map stores 16-byte (player, team) entries before its control bytes.
    mov r11, [r10 + 0xb98]
    cmp r11, 4095
    ja .Loriginal
    mov r10, [r10 + 0xb90]
    test r10, r10
    je .Loriginal
    xor eax, eax
.Lnext:
    test byte ptr [r10 + rax], 0x80
    jz .Loccupied
    inc rax
    cmp rax, r11
    jbe .Lnext
    jmp .Loriginal
.Loccupied:
    neg rax
    shl rax, 4
    mov r11, [r10 + rax - 8]
    test r11, r11
    jz .Loriginal
    cmp r11, -1
    je .Loriginal

    mov rax, [rdx + 0x1a8]
    test rax, rax
    jz .Loriginal
    cmp rax, -1
    je .Loriginal
    cmp rax, r11
    je .Loriginal
    mov r10, [rdx + 0x1b0]
    test r10, r10
    jz .Loriginal
    cmp r10, -1
    je .Loriginal
    cmp r10, r11
    je .Loriginal
    cmp rax, r10
    je .Loriginal
    mov byte ptr [rdx + 0x1b8], 1
    lock inc qword ptr [rip + TFM2_TURBO_DRAFT_JOBS]

.Loriginal:
    // One call site copies into its preallocated job. The other two call
    // the native helper that allocates and copies a job.
    cmp r8d, 0x9ee0
    je .Lcopy
    jmp qword ptr [rip + TFM2_TURBO_ORIGINAL_DISPATCH]
.Lcopy:
    jmp qword ptr [rip + TFM2_TURBO_ORIGINAL_COPY]
