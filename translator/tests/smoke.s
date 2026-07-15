        .text
        .globl _entry
_entry:
        movl $40, %eax
        calll _plus_two
        cmpl $42, %eax
        jne _failed

        # Make both dynamic targets ordinary CFG roots, then call the shared
        # dispatcher with different register arguments.  Caller-specific
        # constants must not freeze its indirect call to either target.
        calll _callback_one
        calll _callback_42
        leal _callback_one, %ecx
        calll _invoke
        cmpl $1, %eax
        jne _failed
        leal _callback_42, %ecx
        calll _invoke
        cmpl $42, %eax
        jne _failed
        movl $42, %eax
        retl
_plus_two:
        addl $2, %eax
        retl
_invoke:
        movl %ecx, %ebx
        calll *%ebx
        retl
_callback_one:
        movl $1, %eax
        retl
_callback_42:
        movl $42, %eax
        retl
_failed:
        movl $1, %eax
        retl
