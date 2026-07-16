        .text
        .globl _entry
_entry:
        # Cache the IAT function pointer before a merge where static register
        # facts intentionally disagree. The generated code must materialize a
        # callable host thunk rather than the PE's raw import-name-table RVA.
        movl __imp__HostAdd, %ebx
        xorl %eax, %eax
        testl %eax, %eax
        je 1f
        movl %eax, %ebx
1:
        pushl $2
        pushl $40
        calll *%ebx
        addl $8, %esp

        # Exercise a direct imported call after the indirect host thunk. The
        # host smoke test requests a cooperative yield from this second call.
        pushl $0
        pushl %eax
        calll _HostAdd
        addl $8, %esp
        retl
