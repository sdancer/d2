        .text
        .globl _entry
_entry:
        pushl $2
        pushl $40
        calll *__imp__HostAdd
        addl $8, %esp
        retl

