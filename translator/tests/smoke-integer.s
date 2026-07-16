        .text
        .globl _entry
_entry:
        movl $0x12345678, %eax
        rorl $8, %eax
        movl $101, %ebx
        cmpl $0x78123456, %eax
        jne _failed

        movl $0x80000001, %eax
        roll $1, %eax
        movl $103, %ebx
        jnc _failed
        movl $104, %ebx
        jno _failed
        movl $102, %ebx
        cmpl $3, %eax
        jne _failed

        movl $7, %eax
        movl $6, %ecx
        mull %ecx
        movl $105, %ebx
        cmpl $42, %eax
        jne _failed
        movl $106, %ebx
        testl %edx, %edx
        jne _failed

        movl $-7, %eax
        movl $6, %ecx
        imull %ecx
        movl $107, %ebx
        cmpl $-42, %eax
        jne _failed
        movl $108, %ebx
        cmpl $-1, %edx
        jne _failed
        movl $109, %ebx
        jo _failed

        # Three-operand 16-bit IMUL is used by Diablo II's interaction layout.
        movw $7, %cx
        imulw $15, %cx, %cx
        movl $117, %ebx
        cmpw $105, %cx
        jne _failed
        movl $118, %ebx
        jo _failed
        movw $0x4000, %cx
        imulw $4, %cx, %cx
        movl $119, %ebx
        jno _failed

        movl $126, %eax
        cdq
        movl $3, %ecx
        idivl %ecx
        movl $110, %ebx
        cmpl $42, %eax
        jne _failed
        movl $111, %ebx
        testl %edx, %edx
        jne _failed

        pushl %eax
        pushl 0(%esp)
        popl %ecx
        addl $4, %esp
        movl $112, %ebx
        cmpl $42, %ecx
        jne _failed

        movl %esp, %edx
        pushl %esp
        popl %ecx
        movl $113, %ebx
        cmpl %edx, %ecx
        jne _failed

        movl $1, %eax
        movl $2, %ebx
        movl $3, %ecx
        movl $4, %edx
        movl $5, %esi
        movl $6, %edi
        movl $7, %ebp
        pushal
        xorl %eax, %eax
        xorl %ebx, %ebx
        xorl %ecx, %ecx
        xorl %edx, %edx
        xorl %esi, %esi
        xorl %edi, %edi
        xorl %ebp, %ebp
        popal
        cmpl $1, %eax
        jne _failed
        cmpl $2, %ebx
        jne _failed
        cmpl $3, %ecx
        jne _failed
        cmpl $4, %edx
        jne _failed
        cmpl $5, %esi
        jne _failed
        cmpl $6, %edi
        jne _failed
        cmpl $7, %ebp
        jne _failed

        xorl %eax, %eax
        cpuid
        movl $114, %eax
        cmpl $0x756e6547, %ebx
        jne _failed

        movl $0x100, %eax
        bsrl %eax, %ecx
        cmpl $8, %ecx
        jne _failed
        bsfl %eax, %edx
        cmpl $8, %edx
        jne _failed
        movl $77, %ecx
        xorl %eax, %eax
        bsrl %eax, %ecx
        jnz _failed
        cmpl $77, %ecx
        jne _failed

        # A dead INC flag result must not hide the carry produced by the ADD
        # before it. ADC consumes that preserved carry even when its own flags
        # are overwritten by the following comparison.
        movl $-1, %eax
        xorl %edx, %edx
        xorl %ecx, %ecx
        addl $1, %eax
        incl %ecx
        adcl $0, %edx
        movl $121, %ebx
        cmpl $1, %edx
        jne _failed

        # These two arithmetic flag results are dead inside this basic block:
        # each is overwritten before the conditional comparison observes flags.
        movl $1, %ecx
        movl $10, %edx
        incl %ecx
        addl $12, %edx
        movl $122, %ebx
        cmpl $2, %ecx
        jne _failed
        movl $123, %ebx
        cmpl $22, %edx
        jne _failed

        rdtsc
        movl %eax, %ecx
        rdtsc
        cmpl %ecx, %eax
        jbe _failed

        # Storm.dll's MPQ crypt-table generator: this exercises two unsigned
        # EDX:EAX divisions inside a register-carried recurrence.
        movl $0x00100001, %esi
        xorl %ebp, %ebp
_crypt_outer:
        movl %ebp, %edi
        movl $5, %ebx
_crypt_inner:
        leal (%esi,%esi,4), %eax
        xorl %edx, %edx
        movl $0x002aaaab, %ecx
        movl $0x002aaaab, %esi
        leal (%eax,%eax,4), %eax
        addl $0x400, %edi
        leal 3(%eax,%eax,4), %eax
        divl %ecx
        movl %edx, %ecx
        leal (%edx,%edx,4), %eax
        xorl %edx, %edx
        andl $0xffff, %ecx
        leal (%eax,%eax,4), %eax
        shll $16, %ecx
        leal 3(%eax,%eax,4), %eax
        divl %esi
        movl %edx, %esi
        andl $0xffff, %edx
        orl %edx, %ecx
        decl %ebx
        movl %ecx, _crypt_table-0x400(%edi)
        jne _crypt_inner
        addl $4, %ebp
        cmpl $0x400, %ebp
        jl _crypt_outer

        movl $115, %ebx
        cmpl $0xa3f16205, _crypt_table+0x110
        jne _failed
        movl $116, %ebx
        cmpl $0x31a5e829, _crypt_table+0x510
        jne _failed

        # Constants from different sides of a diamond must be merged at the
        # indirect-call block. Keeping only the first predecessor hard-codes
        # the wrong callee (the D2 stats-panel MAXHP/MAXMANA regression).
        xorl %eax, %eax
        testl %eax, %eax
        je _indirect_test
        call _indirect_good
        call _indirect_bad
_indirect_test:
        xorl %ecx, %ecx
        cmpl $1, %ecx
        movl $_indirect_bad, %edx
        je _indirect_join
        movl $_indirect_good, %edx
_indirect_join:
        call *%edx
        movl $120, %ebx
        cmpl $0x13579bdf, %eax
        jne _failed

        movl $42, %eax
        retl

_indirect_good:
        movl $0x13579bdf, %eax
        retl

_indirect_bad:
        movl $0x2468ace0, %eax
        retl

_failed:
        movl %ebx, %eax
        retl

        .data
        .p2align 2
_crypt_table:
        .zero 0x1400
