        .text
        .globl _entry
_entry:
        subl $4, %esp
        fld1
        fld1
        faddp %st, %st(1)
        fistpl (%esp)
        popl %ecx
        cmpl $2, %ecx
        jne _failed

        fld1
        fchs
        fchs
        fldz
        fxch %st(1)
        fld1
        fcomp %st(1)
        fnstsw %ax
        sahf
        jne _failed

        subl $4, %esp
        fldz
        fcos
        fistpl (%esp)
        popl %ecx
        cmpl $1, %ecx
        jne _failed

        subl $4, %esp
        fldz
        fsin
        fistpl (%esp)
        popl %ecx
        testl %ecx, %ecx
        jne _failed
        movl $42, %eax
        retl
_failed:
        movl $1, %eax
        retl
