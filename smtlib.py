# Copyright (c) 2013-2024, Felipe Andres Manzano, LMS57
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

from subprocess import PIPE, Popen
import logging
import copy
import weakref
from functools import wraps
import z3

BitVecRef = z3.z3.BitVecRef
BoolRef = z3.z3.BoolRef
BitVecNumRef = z3.z3.BitVecNumRef
BitVec = z3.BitVec
BitVecVal = z3.BitVecVal
BoolVal = z3.z3.BoolVal
Bool = z3.z3.Bool

#friend operations
def TRUE(a):
    return z3.is_true(a)

def FALSE(a):
    return z3.is_false(a)

def SIMP(a):
    if type(a) in [BitVecRef, BoolRef]:
        a = z3.simplify(a)
    if type(a) is BitVecNumRef:
        a = a.as_long()
    return a

def AND(a,b):
    return z3.And(a,b)
    return a & b 

def OR(a, b):
    return z3.Or(a,b)
    return a | b

def XOR(a,b):
    return z3.Xor(a,b)

def UGT(a, b):
    return {  (int, int): lambda : a > b if a>=0 and b>=0 else None,
              ( int): lambda : a > b if a>=0 and b>=0 else None,
              (int): lambda : a > b if a>=0 and b>=0 else None,
              (int): lambda : a > b if a>=0 and b>=0 else None,
              (z3.z3.BitVecRef, int): lambda : a>b,
              (int, z3.z3.BitVecRef): lambda : b<=a == False,
              (z3.z3.BitVecRef): lambda : a>b,
              ( z3.z3.BitVecRef): lambda : b<=a == False,
              (z3.z3.BitVecRef, z3.z3.BitVecRef): lambda : a>b,
            }[(type(a),type(b))]()

def UGE(a, b):
    return {  (int, int): lambda : a >= b if a>=0 and b>=0 else None,
              ( int): lambda : a >= b if a>=0 and b>=0 else None,
              (int): lambda : a >= b if a>=0 and b>=0 else None,
              (int): lambda : a >= b if a>=0 and b>=0 else None,
              (z3.z3.BitVecRef, int): lambda : a>=b,
              (z3.z3.BitVecRef): lambda : a>=b,
              (int, z3.z3.BitVecRef): lambda : b<a == False,
              ( z3.z3.BitVecRef): lambda : b<a == False,
              (z3.z3.BitVecRef,z3.z3.BitVecRef): lambda : a>=b,
            }[(type(a),type(b))]()


def ULT(a, b):
    if type(a) == z3.z3.BitVecRef or type(b) == z3.z3.BitVecRef:
        return z3.ULT(a,b)
    return {  (int, int): lambda : a < b if a>=0 and b>=0 else None,
              (int): lambda : a < b if a>=0 and b>=0 else None,
              (int): lambda : a < b if a>=0 and b>=0 else None,
              (int): lambda : a < b if a>=0 and b>=0 else None,
              (z3.z3.BitVecNumRef, int): lambda : a<b,
              (int, z3.z3.BitVecNumRef): lambda : b>=a == False,
              (z3.z3.BitVecRef, int): lambda : a<b,
              (int, z3.z3.BitVecRef): lambda : b>=a == False,
              (z3.z3.BitVecRef,z3.z3.BitVecRef): lambda : a<b,
              (z3.z3.BitVecNumRef,z3.z3.BitVecNumRef): lambda : a<b,
            }[(type(a),type(b))]()

def ULE(a, b):
    return z3.ULE(a,b)
    return {  (int, int): lambda : a <= b if a>=0 and b>=0 else None,
              ( int): lambda : a <= b if a>=0 and b>=0 else None,
              (int): lambda : a <= b if a>=0 and b>=0 else None,
              (int): lambda : a <= b if a>=0 and b>=0 else None,
              (z3.z3.BitVecRef, int): lambda : a<=b,
              (z3.z3.BitVecRef): lambda : a<=b,
              (int, z3.z3.BitVecRef): lambda : b>a == False,
              ( z3.z3.BitVecRef): lambda : b>a == False,
              (z3.z3.BitVecRef,z3.z3.BitVecRef): lambda : a<=b,
            }[(type(a),type(b))]()

def ZEXTEND(x, size):
    if isinstance(x, (int)):
        return x & ((1<<size)-1)
    return z3.ZeroExt(size-x.size(), x)

def SEXTEND(x, size_src, size_dest):
    if size_src-size_dest ==0:
        return x
    if type(x) is int:
        if x >= (1<<(size_src-1)):
            x -= 1<<size_src
        return x & ((1<<size_dest)-1)
    if x.size() == size_dest:
        return x
    return z3.SignExt(size_dest-size_src,x)

def UDIV(a,b):
    symb = False
    a = SIMP(a)
    b = SIMP(b)

    if b==0:
        raise "azaraza"
    if type(a) is z3.z3.BitVecRef or type(b) is z3.z3.BitVecRef:
        return z3.UDiv(a,b)
        
    return a//b


def UREM(a,b):
    a = SIMP(a)
    b = SIMP(b)

    if b==0:
        raise "azaraza"
    return a%b

def EXTRACT(s, offset, size):
    s = SIMP(s)
    if isinstance(s, BitVecRef):
            c = z3.Extract(offset+size-1, offset, s)
            return c
    else:
        return (s>>offset)&((1<<size)-1)

def ITEBV(size, cond, true, false):
    cond = SIMP(cond)
    if type(cond) in (bool,int):
        if cond:
            return true
        else:
            return false
    if type(cond) is z3.z3.BoolRef:
        if TRUE(cond):
            return true
        elif FALSE(cond):
            return false
    if type(true) is int:
        if size == 1:
            true = z3.BitVecVal(true, 1)
        else:
            true = z3.BitVecVal(true&((1<<size)-1),size)
    if type(false) is int:
        if size == 1:
            false = z3.BitVecVal(false, 1)
        else:
            false = z3.BitVecVal(false&((1<<size)-1),size)
    try:
        a= z3.If(cond, true, false)
        return z3.simplify(a)
    except Exception as e:
        #this is a problem, example is a symbolic ROR RAX, 0x11
        #but how would I set it just for that instruction?
        print(e)
        print('test')
        exit(0)
        return false

def CONCAT(size, *args):
    '''
    size1 = size
    size = len(args)*size
    result = z3.BitVecVal(0,size)
    for arg in args:
        arg = SEXTEND(arg,arg.size(),size)
        result = (result<<size1) | arg
    '''
    l = []
    for x in args:
        if type(x) is int:
            x = z3.BitVecVal(x,size)
        l.append(x)
    result = z3.Concat(*l)
    return result

_ord = ord
def ord(s):
    if isinstance(s, BitVecRef):
        if s.size() == 8:
            return s
        else:
            return z3.Extract(7,0,s)
    elif isinstance(s, int):
        return s&0xff
    elif isinstance(s, bytes) and len(s)==1:
        return _ord(s)
    elif isinstance(s,bytes):
        return s.decode('latin-1')
    else:
        return _ord(s)


_chr = chr
def chr(s):
    if isinstance(s, BitVecRef):
        if s.size() == 8:
            return s
        else:
            return z3.extract(7,0,s)
    elif type(s) is int:
        return _chr(s&0xff)
    else:
        assert len(s) == 1
        return s
