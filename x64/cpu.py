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

import uuid
import sys
import types
import weakref
import z3
from functools import wraps, partial
import collections

from capstone import *
from capstone.x86 import *
CapRegisters = ['(INVALID)', 'AH', 'AL', 'AX', 'BH', 'BL', 'BP', 'BPL', 'BX', 'CH', 'CL', 'CS', 'CX', 'DH', 'DI', 'DIL', 'DL', 'DS', 'DX', 'EAX', 'EBP', 'EBX', 'ECX', 'EDI', 'EDX', 'RFLAGS', 'EIP', 'EIZ', 'ES', 'ESI', 'ESP', 'FPSW', 'FS', 'GS', 'IP', 'RAX', 'RBP', 'RBX', 'RCX', 'RDI', 'RDX', 'RIP', 'RIZ', 'RSI', 'RSP', 'SI', 'SIL', 'SP', 'SPL', 'SS', 'CR0', 'CR1', 'CR2', 'CR3', 'CR4', 'CR5', 'CR6', 'CR7', 'CR8', 'CR9', 'CR10', 'CR11', 'CR12', 'CR13', 'CR14', 'CR15', 'DR0', 'DR1', 'DR2', 'DR3', 'DR4', 'DR5', 'DR6', 'DR7', 'DR8', 'DR9', 'DR10', 'DR11', 'DR12', 'DR13', 'DR14', 'DR15', 'FP0', 'FP1', 'FP2', 'FP3', 'FP4', 'FP5', 'FP6', 'FP7', 'K0', 'K1', 'K2', 'K3', 'K4', 'K5', 'K6', 'K7', 'MM0', 'MM1', 'MM2', 'MM3', 'MM4', 'MM5', 'MM6', 'MM7', 'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15', 'ST0', 'ST1', 'ST2', 'ST3', 'ST4', 'ST5', 'ST6', 'ST7', 'XMM0', 'XMM1', 'XMM2', 'XMM3', 'XMM4', 'XMM5', 'XMM6', 'XMM7', 'XMM8', 'XMM9', 'XMM10', 'XMM11', 'XMM12', 'XMM13', 'XMM14', 'XMM15', 'XMM16', 'XMM17', 'XMM18', 'XMM19', 'XMM20', 'XMM21', 'XMM22', 'XMM23', 'XMM24', 'XMM25', 'XMM26', 'XMM27', 'XMM28', 'XMM29', 'XMM30', 'XMM31', 'YMM0', 'YMM1', 'YMM2', 'YMM3', 'YMM4', 'YMM5', 'YMM6', 'YMM7', 'YMM8', 'YMM9', 'YMM10', 'YMM11', 'YMM12', 'YMM13', 'YMM14', 'YMM15', 'YMM16', 'YMM17', 'YMM18', 'YMM19', 'YMM20', 'YMM21', 'YMM22', 'YMM23', 'YMM24', 'YMM25', 'YMM26', 'YMM27', 'YMM28', 'YMM29', 'YMM30', 'YMM31', 'ZMM0', 'ZMM1', 'ZMM2', 'ZMM3', 'ZMM4', 'ZMM5', 'ZMM6', 'ZMM7', 'ZMM8', 'ZMM9', 'ZMM10', 'ZMM11', 'ZMM12', 'ZMM13', 'ZMM14', 'ZMM15', 'ZMM16', 'ZMM17', 'ZMM18', 'ZMM19', 'ZMM20', 'ZMM21', 'ZMM22', 'ZMM23', 'ZMM24', 'ZMM25', 'ZMM26', 'ZMM27', 'ZMM28', 'ZMM29', 'ZMM30', 'ZMM31', 'R8B', 'R9B', 'R10B', 'R11B', 'R12B', 'R13B', 'R14B', 'R15B', 'R8D', 'R9D', 'R10D', 'R11D', 'R12D', 'R13D', 'R14D', 'R15D', 'R8W', 'R9W', 'R10W', 'R11W', 'R12W', 'R13W', 'R14W', 'R15W']

lookup = {"JE":"JZ","CMOVE":"CMOVZ","CMOVNE":"CMOVNZ","MOVUPS":"MOV","MOVABS":"MOV", "REP MOVSB":"MOVS", "REP MOVSW":"MOVS", "REP MOVSD":"MOVS","SETNE":"SETNZ","SETE":"SETZ","STOSD":"STOS","STOSB":"STOS","STOSW":"STOS","STOSQ":"STOS","SCASD":"SCAS","SCASB":"SCAS","SCASW":"SCAS","SCASQ":"SCAS"}

from smtlib import ITEBV as ITE, ZEXTEND, SEXTEND, ord, chr, OR, AND, CONCAT, UDIV, XOR, UREM, ULT, UGT, ULE, EXTRACT, TRUE, FALSE, SIMP, BitVecRef, BoolRef, BitVecNumRef, BitVecVal, BitVec

import logging
logger = logging.getLogger("CPU")

###############################################################################
#Exceptions..
class DecodeException(Exception):
    ''' You tried to decode an unknown or invalid intruction '''
    def __init__(self, pc, bytes, extra):
        super(DecodeException,self).__init__("Error decoding instruction @%08x", pc)
        self.pc=pc
        self.bytes=bytes
        self.extra=extra

class InvalidPCException(Exception):
    ''' Exception raised when you try to execute invalid or not executable memory
    '''
    def __init__(self, pc):
        super(InvalidPCException, self).__init__("Trying to execute invalid memory @%08x", pc)
        self.pc=pc

class InstructionNotImplemented(Exception):
    ''' Exception raised when you try to execute an instruction that is
        not yet implemented in the emulator.
        Go to cpu.py and add it!
    '''
    pass

class DivideError(Exception):
    ''' A division by zero '''
    pass

class Interruption(Exception):
    ''' '''
    def __init__(self, N):
        super(Interruption,self).__init__("CPU Software Interruption %08x", N)
        self.N = N

class Syscall(Exception):
    ''' '''
    def __init__(self):
        super(Syscall, self).__init__("CPU Syscall")

class SymbolicLoopException(Exception):
    ''' '''
    def __init__(self, reg_name):
        super(SymbolicLoopException, self).__init__("Symbolic Loop")
        self.reg_name = reg_name

class SymbolicPCException(Exception):
    ''' '''
    def __init__(self, symbol):
        super(SymbolicPCException, self).__init__("Symbolic PC")
        self.symbol = symbol

###############################################################################
#Auxiliar decorators...
def memoized(cache_name):
    def wrap(old_method):
        @wraps(old_method)
        def new_method(obj, *args):
            cache = getattr(obj, cache_name)
            if args in cache:
                return cache[args]
            else:
                value = old_method(obj, *args)
                cache[args] = value
                return value

        return new_method
    return wrap

#Instruction decorators
def instruction(old_method):
    #This should decorate every instruction implementation
    @wraps(old_method)
    def new_method(cpu, *args, **kw_args):
        cpu.PC += cpu.instruction.size
        return old_method(cpu,*args,**kw_args)
    return new_method

def rep(old_method):
    #This decorate every REP enabled instruction implementation
    @wraps(old_method)
    def new_method(cpu, *args, **kw_args):
        prefix = cpu.instruction.prefix
        if (X86_PREFIX_REP in prefix) or (X86_PREFIX_REPNE in prefix):
            counter_name = {16: 'CX', 32: 'ECX', 64: 'RCX'}[cpu.instruction.addr_size*8] 
            count = cpu.getRegister(counter_name)

            cpu.IF = count != 0

            #Repeate!
            if (type(cpu.IF) is bool and cpu.IF) or TRUE(SIMP(cpu.IF)):
                old_method(cpu, *args, **kw_args)
                count -= 1

                #if 'FLAG_REPNZ' in cpu.instruction.flags:
                if X86_PREFIX_REP in prefix:
                    cpu.IF = count !=0 #AND(cpu.ZF == False, count != 0)  #true IF means loop
                #elif 'FLAG_REPZ' in cpu.instruction.flags:
                elif X86_PREFIX_REPNE in prefix:
                    cpu.IF = cpu.ZF == False  #true IF means loop

                cpu.setRegister(counter_name, count)

                cpu.PC = ITE(cpu.AddressSize, cpu.IF, cpu.PC, cpu.PC + cpu.instruction.size)

            #Advance!
            else:
                cpu.PC = cpu.PC + cpu.instruction.size

        else:
            cpu.PC += cpu.instruction.size
            old_method(cpu, *args,**kw_args)
    return new_method

###############################################################################
#register/flag descriptors
class Flag(object):
    value = False
    def __get__(self, obj, type=None):
        return self.value
    def __set__(self, obj, value):
        assert isinstance(val, (bool,Bool))
        self.value = value

class Register16(object):
    '''
    16 bit register.
    '''
    value = False
    def __get__(self, obj, type=None):
        return self.value
    def __set__(self, obj, value):
        self.value = value

class Register512(object):
    ''' 
    512 bit register. 
    '''
    def __init__(self):
        self._ZMM = 0
        self._cache = {} 
    
    def setZMM(self, val):
        self._ZMM = val
        self._cache = {}
    def getZMM(self):
        return self._ZMM

    def setYMM(self, val):
        self._ZMM = ZEXTEND(val, 512)
        self._cache = { 'YMM': val}
        return self._ZMM
    def getYMM(self):
        return self._cache.setdefault('YMM', EXTRACT(self._ZMM,0,256) )

    def setXMM(self, val):
        self._ZMM = ZEXTEND(val,512) 
        self._cache = { 'XMM': val }
        return val
    def getXMM(self):
        return self._cache.setdefault('XMM', EXTRACT(self._ZMM,0,128) )

class Register64(object):
    ''' 
    64 bit register. 
    '''
    def __init__(self):
        self._RX = 0
        self._cache = {} 

    def setRX(self, val):

        i = isinstance(val,BitVecRef)
        if not i or (i and val.size() > 64) :
            val = EXTRACT(val, 0, 64)
        if i:
            val = SIMP(val)
        self._RX = val
        self._cache = {}
        return val
    def getRX(self):
        return self._RX

    def setEX(self,val):

        i = isinstance(val,BitVecRef)
        if not i or (i and val.size() > 32) :
            val = EXTRACT(val, 0, 32)
        if i:
            val = SIMP(val)
        self._RX = ZEXTEND(val,64)
        self._cache = { 'EX': EXTRACT(val, 0,32) }
        return val

    def getEX(self):
        return self._cache.setdefault('EX', EXTRACT(self._RX, 0,32))

    def setX(self, val):
        i = isinstance(val,BitVecRef)
        if not i or (i and val.size() > 16) :
            val = EXTRACT(val, 0, 16)
        if i:
            val = SIMP(val)
        val = EXTRACT(val, 0,16)
        self._RX = self._RX & 0xFFFFFFFFFFFF0000 | ZEXTEND(val,64)
        self._cache = { 'X': val}
        return val
    def getX(self):
        return self._cache.setdefault('X', EXTRACT(self._RX, 0,16))

    def setH(self, val):
        i = isinstance(val,BitVecRef)
        if not i or (i and val.size() > 8) :
            val = EXTRACT(val, 0, 8)
        if i:
            val = SIMP(val)
        val = EXTRACT(val, 0,8)
        self._RX = self._RX & 0xFFFFFFFFFFFF00FF | ZEXTEND(val,64) << 8
        self._cache = {'H': val, 'L': self.getL()}
        return val
    def getH(self):
        return self._cache.setdefault('H', EXTRACT(self._RX, 8,8))

    def setL(self, val):
        i = isinstance(val,BitVecRef)
        if not i or (i and val.size() > 8) :
            val = EXTRACT(val, 0, 8)
        if i:
            val = SIMP(val)
        val = EXTRACT(val, 0,8)
        self._RX = self._RX & 0xFFFFFFFFFFFFFF00 | ZEXTEND(val,64)
        self._cache = {'L': val, 'H': self.getH()}
        return val
    def getL(self):
        return self._cache.setdefault('L', EXTRACT(self._RX, 0,8))

def prop(attr, size): 
    get = eval('lambda self: self.%s.get%s()'%(attr,size))
    put = eval('lambda self, value: self.%s.set%s(value)'%(attr,size))
    return property (get, put)

###############################################################################
#Main CPU class
class Cpu(object):
    '''
    A CPU model.
    '''
    def __init__(self, memory, fs, machine, truejump, noread, nowrite, noseg, cycles, loop_max, no_constraints):
        '''
        Builds a CPU model.
        @param memory: memory object for this CPU.
        @param machine:  machine code name. Supported machines: C{'i386'} and C{'amd64'}.
        '''
        assert machine in ['amd64']
        self.mem            = memory #Shall have getchar and putchar methods.
        self.icount         = 0
        self.machine        = machine
        self.done           = 0
        self.bad_inst       = 0
        self.impossible     = 0
        self.const_counter  = 0
        self.target         = 0
        self.true_jumps     = truejump
        self.noread         = noread
        self.nowrite        = nowrite
        self.noseg          = noseg
        self.cycles         = cycles
        self.fs_addr        = fs
        self.loop_max       = loop_max
        self.nc             = no_constraints

        self.AddressSize    = {'amd64':64}[self.machine]
        self.PC_name        = {'amd64': 'RIP'}[self.machine]
        self.STACK_name     = {'amd64': 'RSP'}[self.machine]
        self.FRAME_name     = {'amd64': 'RBP'}[self.machine]
        self.segments       = {'GS': 0, 'FS': self.fs_addr}

        self.constraints = {}           #Overall Constraints to keep track of memory references
        self.jump_constraints  = ['Jump Constraints']     #Constraints to keep track of comparisons or flag altering instructions
        self.read_constraints  = ['Read Constraints']
        self.write_constraints = ['Write Constraints']
        self.seg_constraints   = ['Segment Constraints']
        self.condition_condition   = ['Conditions']
        self.syscall           = ['Syscall']

        self.flag_constraints = ()      #Last constraint used, as we don't want all possible flag altering instructions
        self.size_lookup = {8:'Byte',16:'Word',32:'Dword',64:'Qword'}
        

        #caches
        self.instruction_cache  = {}
        self.mem_cache          = {}
        self.mem_cache_used     = {}

        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True
        self.md.syntax = 0

        # Adding convenience methods to Cpu class for accessing registers
        for reg in ['RAX', 'RCX', 'RDX', 'RBX', 'RSP', 'RBP', 'RSI', 'RDI', 'R8',
                    'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15',  'RIP']:

            setattr(self, '_%s'%reg, Register64())

        for reg in ['_ZMM0', '_ZMM1', '_ZMM2', '_ZMM3', '_ZMM4', '_ZMM5',
                    '_ZMM6', '_ZMM7', '_ZMM8', '_ZMM9', '_ZMM10', '_ZMM11',
                    '_ZMM12', '_ZMM13', '_ZMM14', '_ZMM15']:
            setattr(self, reg, Register512())

        for reg in ['ES', 'CS', 'SS', 'DS', 'FS', 'GS' ]:
            setattr(self, '%s'%reg, 0)

        for reg in ['CF','PF','AF','ZF','SF','DF','OF','IF']:
            setattr(self, reg, False)

        logger.info("Cpu Initialized.")

    RIP   = prop('_RIP', 'RX')
    EIP   = prop('_RIP', 'EX')
    IP    = prop('_RIP', 'X')

    RSP   = prop('_RSP', 'RX')
    ESP   = prop('_RSP', 'EX')
    SP    = prop('_RSP', 'X')
    SPL   = prop('_RSP', 'L')

    RBP   = prop('_RBP', 'RX')
    EBP   = prop('_RBP', 'EX')
    BP    = prop('_RBP', 'X')
    BPL   = prop('_RBP', 'L')

    RAX   = prop('_RAX', 'RX')
    EAX   = prop('_RAX', 'EX')
    AX    = prop('_RAX', 'X')
    AH    = prop('_RAX', 'H')
    AL    = prop('_RAX', 'L')

    RBX   = prop('_RBX', 'RX')
    EBX   = prop('_RBX', 'EX')
    BX    = prop('_RBX', 'X')
    BH    = prop('_RBX', 'H')
    BL    = prop('_RBX', 'L')

    RCX   = prop('_RCX', 'RX')
    ECX   = prop('_RCX', 'EX')
    CX    = prop('_RCX', 'X')
    CH    = prop('_RCX', 'H')
    CL    = prop('_RCX', 'L')

    RDX   = prop('_RDX', 'RX')
    EDX   = prop('_RDX', 'EX')
    DX    = prop('_RDX', 'X')
    DH    = prop('_RDX', 'H')
    DL    = prop('_RDX', 'L')


    RSI   = prop('_RSI', 'RX')
    ESI   = prop('_RSI', 'EX')
    SI    = prop('_RSI', 'X')
    SIL   = prop('_RSI', 'L')

    RDI   = prop('_RDI', 'RX')
    EDI   = prop('_RDI', 'EX')
    DI    = prop('_RDI', 'X')
    DIL   = prop('_RDI', 'L')

    R8    = prop('_R8', 'RX')
    R8D   = prop('_R8', 'EX')
    R8W   = prop('_R8', 'X')
    R8B   = prop('_R8', 'L')

    R9    = prop('_R9', 'RX')
    R9D   = prop('_R9', 'EX')
    R9W   = prop('_R9', 'X')
    R9B   = prop('_R9', 'L')

    R10   = prop('_R10', 'RX')
    R10D  = prop('_R10', 'EX')
    R10W  = prop('_R10', 'X')
    R10B  = prop('_R10', 'L')

    R11   = prop('_R11', 'RX')
    R11D  = prop('_R11', 'EX')
    R11W  = prop('_R11', 'X')
    R11B  = prop('_R11', 'L')

    R12   = prop('_R12', 'RX')
    R12D  = prop('_R12', 'EX')
    R12W  = prop('_R12', 'X')
    R12B  = prop('_R12', 'L')

    R13   = prop('_R13', 'RX')
    R13D  = prop('_R13', 'EX')
    R13W  = prop('_R13', 'X')
    R13B  = prop('_R13', 'L')

    R14   = prop('_R14', 'RX')
    R14D  = prop('_R14', 'EX')
    R14W  = prop('_R14', 'X')
    R14B  = prop('_R14', 'L')

    R15   = prop('_R15', 'RX')
    R15D  = prop('_R15', 'EX')
    R15W  = prop('_R15', 'X')
    R15B  = prop('_R15', 'L')

    XMM0  = prop('_ZMM0', 'XMM')
    YMM0  = prop('_ZMM0', 'YMM')
    ZMM0  = prop('_ZMM0', 'ZMM')
    XMM1  = prop('_ZMM1', 'XMM')
    YMM1  = prop('_ZMM1', 'YMM')
    ZMM1  = prop('_ZMM1', 'ZMM')
    XMM2  = prop('_ZMM2', 'XMM')
    YMM2  = prop('_ZMM2', 'YMM')
    ZMM2  = prop('_ZMM2', 'ZMM')
    XMM3  = prop('_ZMM3', 'XMM')
    YMM3  = prop('_ZMM3', 'YMM')
    ZMM3  = prop('_ZMM3', 'ZMM')
    XMM4  = prop('_ZMM4', 'XMM')
    YMM4  = prop('_ZMM4', 'YMM')
    ZMM4  = prop('_ZMM4', 'ZMM')
    XMM5  = prop('_ZMM5', 'XMM')
    YMM5  = prop('_ZMM5', 'YMM')
    ZMM5  = prop('_ZMM5', 'ZMM')
    XMM6  = prop('_ZMM6', 'XMM')
    YMM6  = prop('_ZMM6', 'YMM')
    ZMM6  = prop('_ZMM6', 'ZMM')
    XMM7  = prop('_ZMM7', 'XMM')
    YMM7  = prop('_ZMM7', 'YMM')
    ZMM7  = prop('_ZMM7', 'ZMM')
    XMM8  = prop('_ZMM8', 'XMM')
    YMM8  = prop('_ZMM8', 'YMM')
    ZMM8  = prop('_ZMM8', 'ZMM')
    XMM9  = prop('_ZMM9', 'XMM')
    YMM9  = prop('_ZMM9', 'YMM')
    ZMM9  = prop('_ZMM9', 'ZMM')
    XMM10 = prop('_ZMM10', 'XMM')
    YMM10 = prop('_ZMM10', 'YMM')
    ZMM10  = prop('_ZMM10', 'ZMM')
    XMM11 = prop('_ZMM11', 'XMM')
    YMM11 = prop('_ZMM11', 'YMM')
    ZMM11  = prop('_ZMM11', 'ZMM')
    XMM12 = prop('_ZMM12', 'XMM')
    YMM12 = prop('_ZMM12', 'YMM')
    ZMM12  = prop('_ZMM12', 'ZMM')
    XMM13 = prop('_ZMM13', 'XMM')
    YMM13 = prop('_ZMM13', 'YMM')
    ZMM13  = prop('_ZMM13', 'ZMM')
    XMM14 = prop('_ZMM14', 'XMM')
    YMM14 = prop('_ZMM14', 'YMM')
    ZMM15  = prop('_ZMM14', 'ZMM')
    XMM15 = prop('_ZMM15', 'XMM')
    YMM15 = prop('_ZMM15', 'YMM')
    ZMM15  = prop('_ZMM15', 'ZMM')

    def listRegisters(self):
        '''
        Returns the list of registers for this CPU.
        @rtype: list
        @return: the list of register names for this CPU.
        '''
        return ['RAX', 'EAX', 'AX', 'AL', 'AH', 'RCX', 'ECX', 'CX', 'CL', 'CH',
                'RDX', 'EDX', 'DX', 'DL', 'DH', 'RBX', 'EBX', 'BX', 'BL', 'BH',
                'RSP', 'ESP', 'SP', 'SPL', 'RBP', 'EBP', 'BP', 'BPL', 'RSI', 
                'ESI', 'SI', 'SIL', 'RDI', 'EDI', 'DI', 'DIL', 'R8', 'R8D',
                'R8W', 'R8B', 'R9', 'R9D', 'R9W', 'R9B', 'R10', 'R10D', 'R10W',
                'R10B', 'R11', 'R11D', 'R11W', 'R11B', 'R12', 'R12D', 'R12W',
                'R12B', 'R13', 'R13D', 'R13W', 'R13B', 'R14', 'R14D', 'R14W',
                'R14B', 'R15', 'R15D', 'R15W', 'R15B', 'ES', 'CS', 'SS', 'DS',
                'FS', 'GS', 'RIP', 'EIP', 'IP','RFLAGS','EFLAGS','FLAGS', 
                'XMM0', 'XMM1', 'XMM2', 'XMM3', 'XMM4', 'XMM5', 'XMM6', 'XMM7',
                'XMM8', 'XMM9', 'XMM10', 'XMM11', 'XMM12', 'XMM13', 'XMM14', 
                'XMM15', 
                'YMM0', 'YMM1', 'YMM2', 'YMM3', 'YMM4', 'YMM5', 'YMM6',
                'YMM7', 'YMM8', 'YMM9', 'YMM10', 'YMM11', 'YMM12', 'YMM13', 
                'YMM14', 'YMM15',
                'ZMM0', 'ZMM1', 'ZMM2', 'ZMM3', 'ZMM4', 'ZMM5', 'ZMM6',
                'ZMM7', 'ZMM8', 'ZMM9', 'ZMM10', 'ZMM11', 'ZMM12', 'ZMM13', 
                'ZMM14', 'ZMM15',
                'CF','SF','ZF','OF','AF', 'PF', 'IF']

    def setRegister(self, name, value):
        '''
        Updates a register value
        @param name: the register name to update its value
        @param value: the new value for the register.
        '''
        assert name in self.listRegisters()
        setattr(self, name, value)
        return value

    def getRegister(self, name):
        '''
        Obtains the current value of a register
        @rtype: int
        @param name: the register name to obtain its value
        @return: the value of the register
        '''
        try:
            assert name in self.listRegisters()
        except:
            print("unkown register")
            print(name)
            self.impossible = 1
            return
            exit(0)
        return getattr(self, name)

    _flags={
        'CF': 0x00001,
        'PF': 0x00004,
        'AF': 0x00010,
        'ZF': 0x00040,
        'SF': 0x00080,
        'DF': 0x00400,
        'OF': 0x00800,
        'IF': 0x10000,
    }
    base_flags = 0
    def setRFLAGS(self, value):
        '''
        Setter for RFLAGS.
        @param value: new value for RFLAGS. 
        '''
        for name, mask in self._flags.items():
            setattr(self, name, value & mask !=0)
        self.base_flags = value

    def getRFLAGS(self):
        '''
        Getter for RFLAGS.
        @rtype: int
        @return: current RFLAGS value. 
        '''
        reg = 0
        for name, mask in self._flags.items():
            reg |= ITE(64, getattr(self, name), mask, 0)
        return reg | ZEXTEND(self.base_flags & ~ (0x00001|0x00004|0x00010|0x00040|0x00080|0x00400|0x00800|0x10000), 64)

    def getEFLAGS(self):
        '''
        Getter for EFLAGS.
        @rtype: int
        @return: current EFLAGS value. 
        '''
        return EXTRACT(self.getRFLAGS(),0,32)

    def getFLAGS(self):
        '''
        Getter for FLAGS.
        
        @rtype: int
        @return: current FLAGS value. 
        '''
        return EXTRACT(self.getRFLAGS(),0,16)
    
    RFLAGS = property(getRFLAGS, setRFLAGS)
    EFLAGS = property(getEFLAGS, setRFLAGS)
    FLAGS = property(getFLAGS, setRFLAGS)

    #Special Registers
    def getPC(self):
        '''
        Returns the current program counter.
        
        @rtype: int
        @return: the current program counter value. 
        '''
        return getattr(self, self.PC_name)
    def setPC(self, value):
        '''
        Changes the program counter value.
        
        @param value: the new value for the program counter.
        '''
        return setattr(self, self.PC_name, value)
    PC = property(getPC,setPC)

    def getSTACK(self):
        '''
        Returns the stack pointer.
        
        @rtype: int
        @return: the current value for the stack pointer.
        '''
        return self.getRegister(self.STACK_name)
    def setSTACK(self, value):
        '''
        Changes the stack pointer value.
        
        @param value: the new value for the stack pointer.
        '''
        return self.setRegister(self.STACK_name,value)
    STACK = property(getSTACK, setSTACK)

    def getFRAME(self):
        '''
        Returns the base pointer.
        
        @rtype: int
        @return: the current value of the base pointer.
        '''
        return self.getRegister(self.FRAME_name)
    def setFRAME(self, value):
        '''
        Changes the base pointer value.
        
        @param value: the new value for the base pointer.
        '''
        return self.setRegister(self.FRAME_name,value)
    FRAME = property(getFRAME, setFRAME)

    def constFold(self,e):
        try:
           if is_app(e) and all([is_bv_value(c) for c in e.children()]):
              return simplify(e)
           else:
              return e
        except:
            return e
    def dumpregs(self):
        '''
        Returns the current registers values.
        
        @rtype: str
        @return: a string containing the name and current value for all the registers. 
        '''
        final = {}
        for reg_name in ['RAX', 'RCX', 'RDX', 'RBX', 'RSP', 'RBP', 'RSI', 'RDI', 'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15',  'RIP',]:
            value = getattr(self, reg_name)
            final[reg_name] = value

        for reg_name in ['CF','SF','ZF','OF','AF', 'PF', 'IF']:
            value = getattr(self, reg_name)
            final[reg_name] = value

        return final

    ####################
    #Basic Memory Access
    def write(self, where, data):
        '''
        Writes C{data} in the address C{where}.
        
        @param where: address to write the data C{data}.
        @param data: the data to write in the address C{where}.  
        '''
        for c in data:
            self.store(where, ord(c), 8) #TODO: fix chr/ord redundancy + putcache use
            where += 1

    def read(self, where, size):
        '''
        Writes C{data} in the address C{where}.
        
        @param where: address to read the data C{data} from.
        @param size: number of bytes.
        '''
        result = ''
        for i in range(size):
            result += chr(self.load(where+i,8))
        return result

    #@putcache("mem_cache")
    def store(self, where, expr, size):
        '''
        Writes a little endian value in memory.
        
        @param where: the address in memory where to store the value.
        @param expr: the value to store in memory.
        @param size: the amount of bytes to write. 
        '''
        if size == 0: #bug in capstone?
            size = 512
        assert size in [8, 16, 32, 64, 128, 256, 512]

        where = SIMP(where)
        
        expr = SIMP(expr)

        for i in range(size-8,-1,-8):
            if type(where) is BitVecRef:
                if self.nowrite:
                    self.impossible = 1
                addr = str(uuid.uuid1())
                self.mem.issym[addr] = 1
                self.constraints[addr] = where+i//8

            else:
                if type(expr) is BitVecRef:
                    val = EXTRACT(expr,i,8)
                else:
                    val = (expr>>i)&0xff
                ret = self.mem.putchar(where+i//8, val)
                if ret == 0:
                    self.impossible = 1

        if type(where) is BitVecRef:
            
            self.write_constraints.append((addr,size, self.const_counter, expr))
            self.const_counter+=1

    #@getcache("mem_cache")
    def load(self, where, size):
        '''
        Reads a little endian value of C{size} bits from memory at address C{where}.
        
        @rtype: int or L{BitVec}
        @param where: the address to read from.
        @param size: the number of bits to read.
        @return: the value read.
        '''
        if where in self.constraints:
            if self.noread:
                self.impossible = 1
            self.read_constraints.append((where, size, self.const_counter))
            self.const_counter+=1
            return self.constraints

        if(type(where) is BitVecRef):
            a = SIMP(where)
            if type(a) is not int:
                if self.noread:
                    self.impossible = 1
                uid = str(uuid.uuid1())
                self.read_constraints.append((uid, size, self.const_counter))
                self.const_counter+=1
                self.constraints[uid] = a
                if size == 0: #could be a bad idea but eh
                    size = 512
                return BitVec(uid,size)
        t = []
        a = ''
        for i in reversed(range(0,size,8)):
            a = self.mem.getchar(where+i//8)
            if type(a) is str and a == 'BAD':
                self.impossible = 1
                return 0
            if isinstance(a,bytes) and len(a) > 1:
                if self.noread:
                    self.impossible = 1
                a = a.decode('latin-1')
                self.read_constraints.append((a,size,self.const_counter))
                self.const_counter==1
                self.constraints[a] = str(where+i//8)
                a = BitVec(a,8)
            elif type(a) is BitVecRef:
                pass#?
            else:
                a = BitVecVal(ord(a),8)
            t.append(a)
        if len(t) == 1:
            return t[0]
        return SIMP(CONCAT(len(t)*8,*t))

    def store_int(self, where, expr):
        self.store(where, expr, self.AddressSize)

    def load_int(self, where):
        return self.load(where, self.AddressSize)

    #
    def push(cpu, value, size):
        '''
        Writes a value in the stack.
        
        @param value: the value to put in the stack.
        @param size: the size of the value.
        '''
        assert size in [ 8, 16, cpu.AddressSize ]
        cpu.STACK = cpu.STACK-size//8
        cpu.store(cpu.STACK, value, size)

    def pop(cpu, size):
        '''
        Gets a value from the stack.
        
        @rtype: int
        @param size: the size of the value to consume from the stack.
        @return: the value from the stack.
        '''
        assert size in [ 16, cpu.AddressSize ]
        value = cpu.load(cpu.STACK, size)
        cpu.STACK = cpu.STACK + size//8
        return value

    @memoized('instruction_cache') #No dynamic code!!! #TODO!
    def getInstructionCapstone(cpu, pc):
        text = b''
        try:
            for i in range(0,16):
                a = cpu.mem.getchar(pc+i)
                text += a
        except Exception as e:
            pass

        instruction = None
        for i in cpu.md.disasm(text, pc):
            instruction = i
            break

        if instruction is None:
            print("Instructin Failure, cpu:777ish")
            exit(-1)

        #Fix/aument opperands so it can access cpu/memory
        for op in instruction.operands:
            op.read=types.MethodType(cpu.readOperandCapstone, op)
            op.write=types.MethodType(cpu.writeOperandCapstone, op)
            op.address=types.MethodType(cpu.getOperandAddressCapstone, op)
            op.size *= 8
        return instruction


    def getOperandAddressCapstone(cpu,o):
        address = 0
        if o.mem.segment != 0:
            seg = cpu.instruction.reg_name(o.mem.segment).upper()
            if seg in cpu.segments:
                address += cpu.segments[seg]

        if o.mem.base != 0:
            base = cpu.instruction.reg_name(o.mem.base).upper()
            address += cpu.getRegister(base)
        if o.mem.index != 0:
            index = cpu.instruction.reg_name(o.mem.index).upper()
            rdi = cpu.getRegister(index)
            address += o.mem.scale*cpu.getRegister(index)
        if o.mem.disp != 0:
            address += o.mem.disp
 
        address = address & ((1<<cpu.AddressSize)-1)

        if o.mem.segment != 0:
            if cpu.noseg:
                cpu.impossible = 1
            address = SIMP(address)
            if type(address) is not int:
                value = f"[{seg} + {address-cpu.segments[seg]}]"
                cpu.seg_constraints.append(value)
                return address

            if cpu.segments[seg] != address:
                value = f"[{seg} + {hex(address-cpu.segments[seg])}]"
            else:
                value = f"[{seg}]"
            cpu.seg_constraints.append(value)
        
        return address

    def readOperandCapstone(cpu, o):
        if o.type == X86_OP_REG:
            return cpu.getRegister(cpu.instruction.reg_name(o.reg).upper())
        elif o.type == X86_OP_IMM:
            return o.imm
        elif o.type == X86_OP_MEM:
            return cpu.load(o.address(), o.size)
        else:
            raise NotImplemented("readOperand unknown type", o.type)

    def writeOperandCapstone(cpu, o, value):
        if o.type == X86_OP_REG:
            cpu.setRegister(cpu.instruction.reg_name(o.reg).upper(), value)
        elif o.type == X86_OP_MEM:
            cpu.store(o.address(), value, o.size)
        else:
            raise NotImplemented()
        return value

#TODO: erradicate stupid flag functions
    def calculateFlags(self, op, size, res, arg0=0, arg1=0):
        '''
        Changes the value of the flags after an operation.
        
        @param op: the operation that was performed.
        @param size: the size of the operands.
        @param res: the result of the operation.
        @param arg0: the first argument of the operation.
        @param arg1: the second argument of the operation.
        '''
        MASK = (1<<size)-1
        SIGN_MASK = 1<<(size-1)
        res = res & MASK
        arg0 = arg0 & MASK
        arg1 = arg1 & MASK
        bit = [BitVecRef, BitVecNumRef]

        if arg0 == 0:
            if type(res) is BitVecRef:
                arg0 = SIMP(res)

        arg0 = SIMP(arg0)

        arg1 = SIMP(arg1)

        if type(arg0) in bit or type(arg1) in bit:
            self.flag_constraints = (op,arg0,arg1,size)
        else:
            self.flag_constraints = ()

        '''Carry Flag.
            Set if an arithmetic operation generates a carry or a borrow out
            of the most-significant bit of the result; cleared otherwise. This flag indi-
            cates an overflow condition for unsigned-integer arithmetic. It is also used
            in multiple-precision arithmetic.
        '''
        if op in ['ADC']:
            self.CF = OR(ULT(res, arg0), AND(self.CF,  res == arg0))
        elif op in ['ADD']:
            self.CF = OR( ULT(res, arg0), ULT(res, arg1))
        elif op in ['CMP', 'SUB']:
            self.CF = ULT(arg0, arg1)
        elif op in ['SBB']:
            self.CF = AND(ULT(arg0, res), AND(self.CF , (arg1==MASK)))
        elif op in ['LOGIC']: 
            self.CF = False     #cleared
        elif op in ['NEG']: 
            self.CF = arg0 != 0
        elif op in ['SHL']: 
            #self.CF = ITE(1, UGT(arg1,size), False, 0 != (arg0 >> (size-arg1))&1)
            self.CF = ( ULE(arg1,size)) | ( 0 != (arg0 >> (size-arg1))&1)
        elif op in ['SHR']:
            if isinstance(arg1, (int)) and arg1 > 0 :
                self.CF = 0 != ((arg0 >> (arg1 - 1))&1) #Shift one less than normally and keep LSB
            else:
                #symbol friendly op
                self.CF = ITE(1, arg1>0, 0 != ((arg0 >> (arg1 - 1))&1), self.CF) !=0 
        elif op in ['SAR']: 
            if arg1>0 :
                self.CF = 0 != ((arg0 // ( 1 << (arg1 - 1) ))&1) #Shift(SIGNED) one less than normally and keep LSB
        elif op in ['SHL']: 
            self.CF = 0 != ((arg0 >> (size - arg1)) & 1) 
        elif op in ['AAA', 'DEC', 'INC']:
            pass            #undefined / Not Affected
        else:
            raise NotImplemented()



        '''Adjust flag.
            Set if an arithmetic operation generates a carry or a borrow
            out of bit 3 of the result; cleared otherwise. This flag is used in binary-
            coded decimal (BCD) arithmetic.
        '''
        if op in ['ADC', 'ADD', 'CMP', 'SBB', 'SUB' ]:
            self.AF = ((arg0 ^ arg1) ^ res) & 0x10 != 0
        elif op in ['DEC']:
            self.AF= (res & 0x0f) == 0x0f
        elif op in ['INC']:
            self.AF= (res & 0x0f) == 0x00
        elif op in ['NEG']:
            #self.AF=((0 ^ (-res)) ^ res) & 0x10 != 0
            self.AF= (res & 0x0f) == 0x00
        elif op in ['AAA', 'SHL', 'SAR', 'SHR']:
            self.AF = False 
            pass #undefined
        elif op in ['LOGIC']:
            self.AF = False
        else:
            raise NotImplemented()

        '''Zero flag.
            Set if the result is zero; cleared otherwise.
        '''
        if op in ['ADC', 'ADD', 'CMP', 'LOGIC', 'NEG', 'DEC', 'INC', 'SBB', 'SUB', 'SHL', 'SHR', 'SAR']:
            self.ZF = res == 0
        else:
            raise NotImplemented()

        '''Sign flag.
            Set equal to the most-significant bit of the result, which is the
            sign bit of a signed integer. (0 indicates a positive value and 1 indicates a
            negative value.)
        '''
        if op in ['ADC', 'ADD', 'LOGIC', 'NEG', 'DEC', 'INC', 'CMP', 'SBB', 'SUB', 'SHL', 'SHR', 'SAR']:
            self.SF = (res & SIGN_MASK)!=0
        else:
            raise NotImplemented()

        '''Overflow flag.
            Set if the integer result is too large a positive number or
            too small a negative number (excluding the sign-bit) to fit in the destina-
            tion operand; cleared otherwise. This flag indicates an overflow condition
            for signed-integer (two's complement) arithmetic.
        '''
        if op in ['ADC', 'ADD']:
            self.OF = (((arg0 ^ arg1 ^ SIGN_MASK) & (res ^ arg1)) & SIGN_MASK) != 0
        elif op in ['CMP', 'SBB', 'SUB']:
            sign0 = (arg0 & SIGN_MASK) ==SIGN_MASK
            sign1 = (arg1 & SIGN_MASK) ==SIGN_MASK
            signr = (res & SIGN_MASK) ==SIGN_MASK
            self.OF = AND(XOR(sign0, sign1), XOR(sign0, signr)) #(((arg0 ^ arg1& SIGN_MASK ) & (arg0 ^ res& SIGN_MASK)& SIGN_MASK) & SIGN_MASK) != 0
        elif op in ['LOGIC']: 
            self.OF = False     #cleared
        elif op in ['DEC']: 
            self.OF = res == ~SIGN_MASK
        elif op in ['INC', 'NEG']: 
            self.OF = res == SIGN_MASK
        elif op in ['SHL']: 
            self.OF = 0 != ((res ^ arg0) & SIGN_MASK)
        elif op in ['SHR']: 
            self.OF = AND(arg1 == 1, arg0 & SIGN_MASK != 0)
#            self.OF = ITE(1,arg1 == 1, 0 != (arg0>>(size-1))&1, False)
        elif op in ['SAR']: 
            self.OF = False
        elif op in ['AAA']:
            pass            #undefined
        else:
            raise NotImplemented()

        '''Parity flag.
            Set if the least-significant byte of the result contains an even
            number of 1 bits; cleared otherwise.
        '''
        if op in ['ADC', 'ADD', 'CMP', 'SUB', 'SBB', 'LOGIC', 'NEG', 'DEC', 'INC', 'SHL', 'SHR', 'SAR']:
            self.PF = (res ^ res>>1 ^ res>>2 ^ res>>3 ^ res>>4 ^ res>>5 ^ res>>6 ^ res>>7)&1 == 0
        else:
            raise NotImplemented()

        for x in ['ZF','CF','PF','OF','AF','SF']:
            r = getattr(self,x)
            r = SIMP(r)
            setattr(self,x,r)
#End calculate flags
    
    #initializes ELF MEMORY
    def initialize(self, mems):
        '''
        Loads and an ELF program in memory and prepares the initial CPU state.
        Creates the stack and loads the environment variables and the arguments in it.
        @param filename: pathname of the file to be executed.
        @param argv: list of parameters for the program to execute.
        @param envp: list of environment variables for the program to execute.
        '''
        for val in mems:
            self.mem.mmap(val[0],val[1],val[2],val[3])

        
        stack_base = 0x7ffffffde000
        stack = self.mem.mmap(stack_base,0x21000,'rw')+0x21000-1

    def reset(self, insts, knownvalues):

        self.icount         = 0
        self.done           = 0
        self.bad_inst       = 0
        self.impossible     = 0
        self.const_counter  = 0
        self.target         = 0

        self.segments       = {'GS': 0, 'FS': self.fs_addr}

        self.constraints = {}           #Overall Constraints to keep track of memory references
        self.jump_constraints  = ['Jump Constraints']     #Constraints to keep track of comparisons or flag altering instructions
        self.read_constraints  = ['Read Constraints']
        self.write_constraints = ['Write Constraints']
        self.seg_constraints   = ['Segment Constraints']
        self.condition_condition   = ['Conditions']
        self.syscall           = ['Syscall']
        
        self.flag_constraints = ()      #Last constraint used, as we don't want all possible flag altering instructions
        #caches
        self.instruction_cache  = {}
        self.mem_cache          = {}
        self.mem_cache_used     = {}

        self.mem.clean()

        addressbitsize = 64
        stack_base = 0x7fffffffe000
        stack = stack_base
        bsz = 16
        stack-=bsz
        self.write(stack, "A"*16)

        #end envp marker empty string
        stack-=1
        self.write(stack,'\x00')

        stack = ((stack - bsz) //bsz )*bsz      # [ padding ]

        stack-=bsz
        self.store(stack,0,addressbitsize)
        stack-=bsz
        self.store(stack,0,addressbitsize)

        for x in insts:
            self.write(x.address,x.bytes)

        logger.info("Setting initial cpu state")
        #set initial CPU state
        self.setRegister('RSP',stack)
        for x in ["RAX","RBX","RCX","RDX","RDI","RSI","RBP","FS","GS","R8","R9","R10","R11","R12","R13","R14","R15"]:
            if knownvalues and x in knownvalues:
                self.setRegister(x, BitVecVal(knownvalues[x],64))
            else:
                self.setRegister(x, BitVec(x,64))

        for x in range(0,16):
            self.setRegister(f"ZMM{x}", BitVec(x,512))

        self.setRegister('RIP',            insts[0].address)
        self.setRegister('RFLAGS',         0x202)
        self.setRegister('CS',             0x23)
        self.setRegister('SS',             0x2b)
        self.setRegister('DS',             0x2b)
        self.setRegister('ES',             0x2b)

    def execute(cpu):
        ''' Decode, and execute one intruction pointed by register PC'''

        try:
            instruction = cpu.getInstructionCapstone(cpu.PC)
        except:
                raise SymbolicPCException(cpu.PC)

        cpu.instruction = instruction
        #print(instruction)

        #Check if we already have an implementation...
        name = instruction.insn_name().upper()

        if name in lookup:
            name = lookup[name]

        if instruction.bytes == b'\x00\x00':
            raise("bad bytes hit")

        try:
            implementation = getattr(cpu, name)
        except:
            #unregistered instruction
            cpu.impossible=1
            return

        implementation(*instruction.operands)

        #housekeeping
        cpu.icount += 1

        if cpu.icount > cpu.cycles:
            cpu.impossible = 1

    @instruction
    def ENDBR64(cpu):
        '''
        ENDBR64 instruction
        
        Currently not fully implemented and handles like a nop
        '''
        pass

    @instruction
    def CPUID(cpu):
        '''
        CPUID instruction.
        
        The ID flag (bit 21) in the EFLAGS register indicates support for the CPUID instruction. 
        If a software procedure can set and clear this flag, the processor executing the procedure
        supports the CPUID instruction. This instruction operates the same in non-64-bit modes and 64-bit mode.
        CPUID returns processor identification and feature information in the EAX, EBX, ECX, and EDX registers.
        
        The instruction's output is dependent on the contents of the EAX register upon execution.
        
        @param cpu: current CPU. 
        '''
        arg0 = cpu.EAX
        if arg0 == 0:
            cpu.EAX=0x0000000d
            cpu.EBX=0x756e6547
            cpu.ECX=0x6c65746e
            cpu.EDX=0x49656e69
        elif arg0 == 1:
            cpu.EAX = 0x206a7
            cpu.EBX = 0x2100800
            cpu.ECX = 0x1fbae3ff
            cpu.EDX = 0xbfebfbff
        elif arg0 == 2:
            cpu.EAX = 0x76035a01
            cpu.EBX = 0xf0b2ff
            cpu.ECX = 0
            cpu.EDX = 0xca0000
        elif arg0 == 4:
            if cpu. ECX == 0:
                cpu.EAX = 0x1c004121
                cpu.EBX = 0x1c0003f
                cpu.ECX = 0x3f
                cpu.EDX = 0x00
            elif cpu. ECX == 1:
                cpu.EAX = 0x1c004122
                cpu.EBX = 0x1c0003f
                cpu.ECX = 0x3f
                cpu.EDX = 0x00
            elif cpu. ECX == 2:
                cpu.EAX = 0x1c004143
                cpu.EBX = 0x1c0003f
                cpu.ECX = 0x1ff
                cpu.EDX = 0x00
            elif cpu. ECX == 3:
                cpu.EAX = 0x1c03c163
                cpu.EBX = 0x3c0003f
                cpu.ECX = 0xfff
                cpu.EDX = 0x06
            else: 
                cpu.EAX = 0
                cpu.EBX = 0
                cpu.ECX = 0
                cpu.EDX = 0
        elif arg0 == 7:
            cpu.EBX = 0xffffffff
        elif arg0 == 0xb:
            if cpu. ECX == 0:
                cpu.EAX = 0x1
                cpu.EBX = 0x2
                cpu.ECX = 0x100
                cpu.EDX = 0x0
            else:
                cpu.EAX = 0x4
                cpu.EBX = 0x4
                cpu.ECX = 0x201
                cpu.EDX = 0x3
        else: 
            raise NotImplemented()  

    @instruction
    def XGETBV(cpu):
        '''
        XGETBV instruction.
        
        Reads the contents of the extended cont register (XCR) specified in the ECX register into registers EDX:EAX. 
        Implemented only for ECX = 0.
        
        @param cpu: current CPU. 
        '''
        assert TRUE(SIMP(cpu.ECX == 0)), 'Only implemented for ECX = 0'
        cpu.EAX = 0x7
        cpu.EDX = 0x0

########################################################################################
# Generic Operations
########################################################################################
# Logical: AND, TEST, NOT, XOR, OR
########################################################################################
    @instruction
    def AND(cpu, dest, src):
        ''' 
        Logical AND. 
        
        Performs a bitwise AND operation on the destination (first) and source 
        (second) operands and stores the result in the destination operand location. 
        Each bit of the result is set to 1 if both corresponding bits of the first and 
        second operands are 1; otherwise, it is set to 0.
        
        The OF and CF flags are cleared; the SF, ZF, and PF flags are set according to the result::
        
            DEST  =  DEST AND SRC;
        
        @param cpu: current CPU.
        @param dest: destination operand.
        @param src: source operand.  
        '''
        res = dest.write(dest.read() & src.read())
        #Defined Flags: szp
        cpu.calculateFlags('LOGIC',dest.size, res)

    @instruction
    def TEST(cpu, src1, src2):
        '''
        Logical compare. 
        
        Computes the bit-wise logical AND of first operand (source 1 operand) 
        and the second operand (source 2 operand) and sets the SF, ZF, and PF 
        status flags according to the result. The result is then discarded::

            TEMP  =  SRC1 AND SRC2;
            SF  =  MSB(TEMP);
            IF TEMP  =  0
            THEN ZF  =  1;
            ELSE ZF  =  0;
            FI:
            PF  =  BitwiseXNOR(TEMP[0:7]);
            CF  =  0;
            OF  =  0;
            (*AF is Undefined*)
        
        @param cpu: current CPU. 
        @param src1: first operand.
        @param src2: second operand.
        '''
        #Defined Flags: szp
        cpu.calculateFlags('LOGIC', src1.size, src1.read() & src2.read())

    @instruction
    def NOT(cpu, dest):
        '''
        One's complement negation. 
        
        Performs a bitwise NOT operation (each 1 is cleared to 0, and each 0 
        is set to 1) on the destination operand and stores the result in the destination 
        operand location::
        
            DEST  =  NOT DEST;
        
        @param cpu: current CPU.
        @param dest: destination operand. 
        '''
        res = dest.write(~dest.read())
        #Flags Affected: None.

    @instruction
    def XOR(cpu, dest, src):
        ''' 
        Logical exclusive OR. 
        
        Performs a bitwise exclusive OR (XOR) operation on the destination (first) 
        and source (second) operands and stores the result in the destination 
        operand location.
              
        Each bit of the result is 1 if the corresponding bits of the operands 
        are different; each bit is 0 if the corresponding bits are the same.
            
        The OF and CF flags are cleared; the SF, ZF, and PF flags are set according to the result::            
            
            DEST  =  DEST XOR SRC;
        
        @param cpu: current CPU.
        @param dest: destination operand.
        @param src: source operand.
        '''
        if dest == src:
            res = dest.write(BitVecVal(0,dest.size))
        elif TRUE(dest.read() == src.read()):
            res = dest.write(BitVecVal(0,dest.size))
        else:
            res = dest.write(dest.read() ^ src.read())
        #Defined Flags: szp
        cpu.calculateFlags('LOGIC', dest.size, res)

    @instruction
    def OR(cpu, dest, src):
        '''
        Logical inclusive OR. 
        
        Performs a bitwise inclusive OR operation between the destination (first) 
        and source (second) operands and stores the result in the destination operand location.
         
        Each bit of the result of the OR instruction is set to 0 if both corresponding 
        bits of the first and second operands are 0; otherwise, each bit is set 
        to 1.
        
        The OF and CF flags are cleared; the SF, ZF, and PF flags are set according to the result::

            DEST  =  DEST OR SRC;

        @param cpu: current CPU.
        @param dest: destination operand.
        @param src: source operand.
        '''
        res = dest.write(dest.read() | src.read())
        #Defined Flags: szp
        cpu.calculateFlags('LOGIC',dest.size, res)

########################################################################################
# Generic Operations
########################################################################################
# Arithmetic: AAA, AAD, AAM, AAS, ADC, ADD, ADX, AMX, CMP, CMPXCHG
#             CMPXCHG8B,DAA, DAS, DEC, DIV, IDIV, IMUL, INC, MUL, 
#             NEG, SBB, SUB, XADD
########################################################################################
    @instruction
    def AAA(cpu):
        ''' 
        ASCII adjust after addition. 
        
        Adjusts the sum of two unpacked BCD values to create an unpacked BCD 
        result. The AL register is the implied source and destination operand 
        for this instruction. The AAA instruction is only useful when it follows 
        an ADD instruction that adds (binary addition) two unpacked BCD values 
        and stores a byte result in the AL register. The AAA instruction then 
        adjusts the contents of the AL register to contain the correct 1-digit 
        unpacked BCD result.
        If the addition produces a decimal carry, the AH register is incremented 
        by 1, and the CF and AF flags are set. If there was no decimal carry, 
        the CF and AF flags are cleared and the AH register is unchanged. In either 
        case, bits 4 through 7 of the AL register are cleared to 0.
        
        This instruction executes as described in compatibility mode and legacy mode. 
        It is not valid in 64-bit mode.
        ::
                IF ((AL AND 0FH) > 9) OR (AF  =  1)
                THEN
                    AL  =  (AL + 6);
                    AH  =  AH + 1;
                    AF  =  1;
                    CF  =  1;
                ELSE
                    AF  =  0;
                    CF  =  0;
                FI;
                AL  =  AL AND 0FH;
        @param cpu: current CPU.
        '''
        if (cpu.AL & 0x0F > 9) or cpu.AF == 1:
            cpu.AL = cpu.AL + 6
            cpu.AH = cpu.AH + 1
            cpu.AF = 1
            cpu.CF = 1
        else:
            cpu.AF = 0
            cpu.CF = 0
        cpu.AL = cpu.AL & 0x0f

    @instruction
    def AAD(cpu):
        ''' 
        ASCII adjust AX before division.
        
        Adjusts two unpacked BCD digits (the least-significant digit in the 
        AL register and the most-significant digit in the AH register) so that 
        a division operation performed on the result will yield a correct unpacked 
        BCD value. The AAD instruction is only useful when it precedes a DIV instruction 
        that divides (binary division) the adjusted value in the AX register by 
        an unpacked BCD value.
        The AAD instruction sets the value in the AL register to (AL + (10 * AH)), and then 
        clears the AH register to 00H. The value in the AX register is then equal to the binary 
        equivalent of the original unpacked two-digit (base 10) number in registers AH and AL.
        
        The SF, ZF, and PF flags are set according to the resulting binary value in the AL register.
        
        This instruction executes as described in compatibility mode and legacy mode. 
        It is not valid in 64-bit mode.::

                tempAL  =  AL;
                tempAH  =  AH;
                AL  =  (tempAL + (tempAH * 10)) AND FFH;
                AH  =  0
        
        @param cpu: current CPU.
        '''
        cpu.AL += cpu.AH * 10
        cpu.AH = 0
        #Defined flags: ...sz.p.
        cpu.calculateFlags('LOGIC', 8, cpu.AL)

    @instruction
    def AAM(cpu):
        ''' 
        ASCII adjust AX after multiply.
        
        Adjusts the result of the multiplication of two unpacked BCD values 
        to create a pair of unpacked (base 10) BCD values. The AX register is 
        the implied source and destination operand for this instruction. The AAM 
        instruction is only useful when it follows a MUL instruction that multiplies 
        (binary multiplication) two unpacked BCD values and stores a word result 
        in the AX register. The AAM instruction then adjusts the contents of the 
        AX register to contain the correct 2-digit unpacked (base 10) BCD result.
        
        The SF, ZF, and PF flags are set according to the resulting binary value in the AL register.

        This instruction executes as described in compatibility mode and legacy mode. 
        It is not valid in 64-bit mode.::
        
                tempAL  =  AL;
                AH  =  tempAL / 10; 
                AL  =  tempAL MOD 10;
        
        @param cpu: current CPU.
        '''
        cpu.AH = cpu.AL // 10
        cpu.AL = cpu.AL % 10
        #Defined flags: ...sz.p.
        cpu.calculateFlags('LOGIC', 8, cpu.AL)

    @instruction
    def AAS(cpu):
        ''' 
        ASCII Adjust AL after subtraction.
        
        Adjusts the result of the subtraction of two unpacked BCD values to  create a unpacked
        BCD result. The AL register is the implied source and destination operand for this instruction. 
        The AAS instruction is only useful when it follows a SUB instruction that subtracts 
        (binary subtraction) one unpacked BCD value from another and stores a byte result in the AL
        register. The AAA instruction then adjusts the contents of the AL register to contain the 
        correct 1-digit unpacked BCD result. If the subtraction produced a decimal carry, the AH register
        is decremented by 1, and the CF and AF flags are set. If no decimal carry occurred, the CF and AF
        flags are cleared, and the AH register is unchanged. In either case, the AL register is left with
        its top nibble set to 0.
        
        The AF and CF flags are set to 1 if there is a decimal borrow; otherwise, they are cleared to 0.
        
        This instruction executes as described in compatibility mode and legacy mode. 
        It is not valid in 64-bit mode.::
        

                IF ((AL AND 0FH) > 9) OR (AF  =  1)
                THEN
                    AX  =  AX - 6;
                    AH  =  AH - 1;
                    AF  =  1;
                    CF  =  1;
                ELSE
                    CF  =  0;
                    AF  =  0;
                FI;
                AL  =  AL AND 0FH;
        
        @param cpu: current CPU.
        '''
        if (cpu.AL & 0x0F > 9) or cpu.AF == 1:
            cpu.AX = cpu.AX - 6
            cpu.AH = cpu.AH - 1
            cpu.AF = 1
            cpu.CF = 1
        else:
            cpu.AF = 0
            cpu.CF = 0
        cpu.AL = cpu.AL & 0x0f

    @instruction
    def ADC(cpu, dest, src):
        ''' 
        Adds with carry.
        
        Adds the destination operand (first operand), the source operand (second operand), 
        and the carry (CF) flag and stores the result in the destination operand. The state 
        of the CF flag represents a carry from a previous addition. When an immediate value
        is used as an operand, it is sign-extended to the length of the destination operand 
        format. The ADC instruction does not distinguish between signed or unsigned operands. 
        Instead, the processor evaluates the result for both data types and sets the OF and CF 
        flags to indicate a carry in the signed or unsigned result, respectively. The SF flag 
        indicates the sign of the signed result. The ADC instruction is usually executed as 
        part of a multibyte or multiword addition in which an ADD instruction is followed by an 
        ADC instruction::

                DEST  =  DEST + SRC + CF;
        
        The OF, SF, ZF, AF, CF, and PF flags are set according to the result.
        
        @param cpu: current CPU.
        @param dest: destination operand.
        @param src: source operand.
        '''
        arg0 = dest.read()
        arg1 = src.read()
        res = dest.write(arg0 + arg1 + ITE(dest.size,cpu.CF,1,0))
        #Affected Flags o..szapc
        cpu.calculateFlags('ADC', dest.size, res, arg0, arg1)

    @instruction
    def ADD(cpu, dest, src):
        ''' 
        Add.
        
        Adds the first operand (destination operand) and the second operand (source operand) 
        and stores the result in the destination operand. When an immediate value is used as 
        an operand, it is sign-extended to the length of the destination operand format.
        The ADD instruction does not distinguish between signed or unsigned operands. Instead, 
        the processor evaluates the result for both data types and sets the OF and CF flags to
        indicate a carry in the signed or unsigned result, respectively. The SF flag indicates
        the sign of the signed result::

                DEST  =  DEST + SRC;
        
        @param cpu: current CPU.
        @param dest: destination operand.
        @param src: source operand.
        '''
        arg0 = dest.read()
        arg1 = SEXTEND(src.read(), src.size, dest.size)
        res = dest.write(arg0 + arg1)
        #Affected flags: oszapc
        cpu.calculateFlags('ADD', dest.size, res, arg0, arg1)

    @instruction
    def ADX(cpu, base):
        '''
        ASCII adjusts AX before division generalized.
            
        The generalized version of AAD instruction allows adjustment of two unpacked digits of any number 
        base, by setting the imm8 byte to the selected number base (for example, 08H for octal, 0AH for decimal, 
        or 0CH for base 12 numbers). The AAD mnemonic is interpreted by all assemblers to mean adjust ASCII (base 10) 
        values. To adjust values in another number base, the instruction must be hand coded in machine code (D5 imm8)::

                tempAL  =  AL;
                tempAH  =  AH;
                AL  =  (tempAL + (tempAH * imm8)) AND FFH; (* imm8 is set to 0AH for the AAD mnemonic *)
                AH  =  0
        
        @param cpu: current CPU.
        @param base: number base.
        '''
        cpu.AL += cpu.AH * base.read()
        cpu.AH = 0
        #Defined flags: ...sz.p.
        cpu.calculateFlags('LOGIC', 8, cpu.AL)

    @instruction
    def AMX(cpu, base):
        ''' 
        ASCII adjusts AX after multiply generalized.
        
        The generalized version of AAM instruction allows adjustment of the contents of the AX to create two 
        unpacked digits of any number base. Here, the imm8 byte is set to the selected number base 
        (for example, 08H for octal, 0AH for decimal, or 0CH for base 12 numbers). The AAM mnemonic is interpreted 
        by all assemblers to mean adjust to ASCII (base 10) values. To adjust to values in another number base, 
        the instruction must be hand coded in machine code (D4 imm8)::

                tempAL  =  AL;
                AH  =  tempAL / imm8; (* imm8 is set to 0AH for the AAD mnemonic *)
                AL  =  tempAL MOD imm8;
        
        @param cpu: current CPU.
        @param base: number base.
        '''
        base = base.read()
        cpu.AH = cpu.AL // base #TODO: not sure about the signedness of the op
        cpu.AL = cpu.AL % base
        #Defined flags: ...sz.p.
        cpu.calculateFlags('LOGIC', 8, cpu.AL)

    @instruction
    def CMP(cpu, dest, src):
        ''' 
        Compares two operands.
        
        Compares the first source operand with the second source operand and sets the status flags 
        in the EFLAGS register according to the results. The comparison is performed by subtracting 
        the second operand from the first operand and then setting the status flags in the same manner
        as the SUB instruction. When an immediate value is used as an operand, it is sign-extended to
        the length of the first operand::
        
                temp  =  SRC1 - SignExtend(SRC2); 
                ModifyStatusFlags; (* Modify status flags in the same manner as the SUB instruction*)
        
        The CF, OF, SF, ZF, AF, and PF flags are set according to the result.
        
        @param cpu: current CPU.
        @param dest: destination operand.
        @param src: source operand.        
        '''
        arg0 = dest.read()
        arg1 = src.read()
        #Affected Flags o..szapc
        arg0 = SIMP(arg0)

        arg1 = SIMP(arg1)

        cpu.calculateFlags('CMP', dest.size, arg0-arg1, arg0, arg1)

    @instruction
    def CMPXCHG(cpu, dest, src):
        ''' 
        Compares and exchanges.
        
        Compares the value in the AL, AX, EAX or RAX register (depending on the size of the 
        operand) with the first operand (destination operand). If the two values are equal, 
        the second operand (source operand) is loaded into the destination operand. Otherwise, 
        the destination operand is loaded into the AL, AX, EAX or RAX register.
        
        The ZF flag is set if the values in the destination operand and register AL, AX, or EAX
        are equal; otherwise it is cleared. The CF, PF, AF, SF, and OF flags are set according to
        the results of the comparison operation::
        
                (* accumulator  =  AL, AX, EAX or RAX,  depending on whether *)
                (* a byte, word, a doubleword or a 64bit comparison is being performed*)
                IF accumulator  ==  DEST
                THEN
                    ZF  =  1
                    DEST  =  SRC
                ELSE
                    ZF  =  0
                    accumulator  =  DEST
                FI;
        
        @param cpu: current CPU.
        @param dest: destination operand.
        @param src: source operand.
        '''
        cpu.bad_inst = 1
        return
        size = dest.size
        reg_name = {8:'AL', 16:'AX', 32:'EAX', 64:'RAX'}[size]
        arg0 = cpu.getRegister(reg_name)
        arg1 = dest.read()

        dest.write(ITE(size, arg0 == arg1, src.read(), arg1))
        cpu.setRegister(reg_name, ITE(size, arg0 != arg1, arg1, arg0))

        #Affected Flags o..szapc
        cpu.calculateFlags('CMP', dest.size, arg0-arg1, arg0, arg1)

    @instruction
    def CMPXCHG8B(cpu, dest):
        '''
        Compares and exchanges bytes.
        
        Compares the 64-bit value in EDX:EAX (or 128-bit value in RDX:RAX if operand size is 
        128 bits) with the operand (destination operand). If the values are equal, the 64-bit 
        value in ECX:EBX (or 128-bit value in RCX:RBX) is stored in the destination operand. 
        Otherwise, the value in the destination operand is loaded into EDX:EAX (or RDX:RAX)::

                IF (64-Bit Mode and OperandSize = 64)
                THEN
                    IF (RDX:RAX = DEST)
                    THEN
                        ZF = 1;
                        DEST = RCX:RBX;
                    ELSE
                        ZF = 0;
                        RDX:RAX = DEST;
                    FI
                ELSE
                    IF (EDX:EAX = DEST)
                    THEN
                        ZF = 1;
                        DEST = ECX:EBX;
                    ELSE
                        ZF = 0;
                        EDX:EAX = DEST;
                    FI;
                FI;
        
        @param cpu: current CPU.
        @param dest: destination operand.    
        '''
        size = dest.size
        cmp_reg_name_l = { 64:'EAX', 128:'RAX'}[size]
        cmp_reg_name_h = { 64:'EDX', 128:'RDX'}[size]
        src_reg_name_l = { 64:'EBX', 128:'RBX'}[size]
        src_reg_name_h = { 64:'ECX', 128:'RCX'}[size]
        
        #EDX:EAX or RDX:RAX
        cmp0 = CONCAT(size//2, cpu.getRegister(cmp_reg_name_h), cpu.getRegister(cmp_reg_name_l))
        arg1 = dest.read()
        if cmp0 == arg1:
            #ECX:EBX or RCX:RBX
            dest.write(CONCAT(size//2, cpu.getRegister(src_reg_name_h), cpu.getRegister(src_reg_name_l)))
        else:
            cpu.setRegister(cmp_reg_name_l, arg1)
            cpu.setRegister(cmp_reg_name_h, arg1>>(size//2))

        #Affected Flags o..szapc
        cpu.calculateFlags('CMP', dest.size, cmp0-arg1, cmp0, arg1)

    @instruction
    def DAA(cpu):
        '''
        Decimal adjusts AL after addition.
        
        Adjusts the sum of two packed BCD values to create a packed BCD result. The AL register
        is the implied source and destination operand. If a decimal carry is detected, the CF 
        and AF flags are set accordingly.
        The CF and AF flags are set if the adjustment of the value results in a decimal carry in
        either digit of the result. The SF, ZF, and PF flags are set according to the result.
        
        This instruction is not valid in 64-bit mode.::

                IF (((AL AND 0FH) > 9) or AF  =  1)
                THEN
                    AL  =  AL + 6;
                    CF  =  CF OR CarryFromLastAddition; (* CF OR carry from AL  =  AL + 6 *)
                    AF  =  1;
                ELSE
                    AF  =  0;
                FI;
                IF ((AL AND F0H) > 90H) or CF  =  1)
                THEN
                    AL  =  AL + 60H;
                    CF  =  1;
                ELSE
                    CF  =  0;
                FI;
        
        @param cpu: current CPU.        
        '''
        if ((cpu.AL & 0x0f) > 9) or cpu.AF  ==  1:
            oldAL = cpu.AL
            cpu.AL =  cpu.AL + 6
            cpu.CF = cpu.CF |  cpu.AL < oldAL
            cpu.AF  =  1
        else:
            cpu.AF  =  0

        if ((cpu.AL & 0xf0) > 0x90) or cpu.CF  ==  1:
            cpu.AL  = cpu.AL + 0x60
            cpu.CF  =  1
        else:
            cpu.CF  =  0
        
        cpu.ZF = cpu.AL == 0
        cpu.SF = (cpu.AL & 0x80) != 0
        cpu.PF = (cpu.AL ^ cpu.AL>>1 ^ cpu.AL>>2 ^ cpu.AL>>3 ^ cpu.AL>>4 ^ cpu.AL>>5 ^ cpu.AL>>6 ^ cpu.AL>>7)&1 == 0
        

    @instruction
    def DAS(cpu):
        ''' 
        Decimal adjusts AL after subtraction.
        
        Adjusts the result of the subtraction of two packed BCD values to create a packed BCD result. 
        The AL register is the implied source and destination operand. If a decimal borrow is detected, 
        the CF and AF flags are set accordingly. This instruction is not valid in 64-bit mode.
        
        The SF, ZF, and PF flags are set according to the result.::
        
                IF (AL AND 0FH) > 9 OR AF  =  1
                THEN
                    AL  =  AL - 6;
                    CF  =  CF OR BorrowFromLastSubtraction; (* CF OR borrow from AL  =  AL - 6 *)
                    AF  =  1;
                ELSE 
                    AF  =  0;
                FI;
                IF ((AL > 99H) or OLD_CF  =  1)
                THEN
                    AL  =  AL - 60H;
                    CF  =  1;
        
        @param cpu: current CPU.
        '''
        oldAL = cpu.AL
        oldCF = cpu.CF
        cpu.CF = False
        if (cpu.AL & 0x0f) > 9 or cpu.AF:
            cpu.AL  =  cpu.AL - 6;
            cpu.CF  =  OR (oldCF, cpu.AL > oldAL)
            cpu.AF  = True
        else:
            cpu.AF  =  False

        if ((oldAL > 0x99) or oldCF):
            cpu.AL  =  cpu.AL - 0x60
            cpu.CF  =  True

        cpu.ZF = cpu.AL == 0
        cpu.SF = (cpu.AL & 0x80) != 0
        cpu.PF = (cpu.AL ^ cpu.AL>>1 ^ cpu.AL>>2 ^ cpu.AL>>3 ^ cpu.AL>>4 ^ cpu.AL>>5 ^ cpu.AL>>6 ^ cpu.AL>>7)&1 == 0


    @instruction
    def DEC(cpu, dest):
        ''' 
        Decrements by 1.
        
        Subtracts 1 from the destination operand, while preserving the state of the CF flag. The destination
        operand can be a register or a memory location. This instruction allows a loop counter to be updated
        without disturbing the CF flag. (To perform a decrement operation that updates the CF flag, use a SUB 
        instruction with an immediate operand of 1.)
        The instruction's 64-bit mode default operation size is 32 bits.

        The OF, SF, ZF, AF, and PF flags are set according to the result::
        
                DEST  =  DEST - 1;
        
        @param cpu: current CPU.
        @param dest: destination operand.
        '''
        arg0 = dest.read()
        res = dest.write(arg0-1)
        #Affected Flags o..szapc
        cpu.calculateFlags('DEC', dest.size, res)

    @instruction
    def DIV(cpu, src):
        ''' 
        Unsigned divide.
        
        Divides (unsigned) the value in the AX register, DX:AX register pair, or EDX:EAX or RDX:RAX register pair
        (dividend) by the source operand (divisor) and stores the result in the AX (AH:AL), DX:AX, EDX:EAX or RDX:RAX
        registers. The source operand can be a general-purpose register or a memory location. The action of this
        instruction depends of the operand size (dividend/divisor). Division using 64-bit operand is available only
        in 64-bit mode. Non-integral results are truncated (chopped) towards 0. The reminder is always less than the
        divisor in magnitude. Overflow is indicated with the #DE (divide error) exception rather than with the CF flag::

                IF SRC  =  0
                    THEN #DE; FI;(* divide error *)
                IF OpernadSize  =  8 (* word/byte operation *)
                    THEN
                        temp  =  AX / SRC;
                        IF temp > FFH
                            THEN #DE; (* divide error *) ;
                            ELSE
                                AL  =  temp;
                                AH  =  AX MOD SRC;
                        FI;
                    ELSE IF OperandSize  =  16 (* doubleword/word operation *)
                        THEN
                            temp  =  DX:AX / SRC;                    
                            IF temp > FFFFH
                                THEN #DE; (* divide error *) ;
                            ELSE
                                AX  =  temp;
                                DX  =  DX:AX MOD SRC;
                            FI;
                        FI;
                    ELSE If OperandSize = 32 (* quadword/doubleword operation *)
                        THEN
                            temp  =  EDX:EAX / SRC;
                            IF temp > FFFFFFFFH
                                THEN #DE; (* divide error *) ;
                            ELSE
                                EAX  =  temp;
                                EDX  =  EDX:EAX MOD SRC;
                            FI;
                        FI;
                    ELSE IF OperandSize = 64 (*Doublequadword/quadword operation*)
                        THEN
                            temp = RDX:RAX / SRC;
                            IF temp > FFFFFFFFFFFFFFFFH
                                THEN #DE; (* Divide error *)
                            ELSE
                                RAX = temp;
                                RDX = RDX:RAX MOD SRC;
                            FI;
                        FI;
                FI;

        @param cpu: current CPU.
        @param src: source operand.         
        '''
        size = src.size
        reg_name_h = { 8: 'AH', 16: 'DX', 32:'EDX', 64:'RDX'}[size]
        reg_name_l = { 8: 'AL', 16: 'AX', 32:'EAX', 64:'RAX'}[size]

        dividend = CONCAT(size, cpu.getRegister(reg_name_h), cpu.getRegister(reg_name_l))

        divisor = ZEXTEND(src.read(), size*2)

        divisor = SIMP(divisor)

        if divisor == 0:
            cpu.impossible = 1
            return 

        quotient = UDIV(dividend, divisor)

        MASK = (1<<size)-1

        if isinstance(quotient, (int)) and quotient > MASK:
            raise DivideError()
        reminder = UREM(dividend, divisor)

        cpu.setRegister(reg_name_l, EXTRACT(quotient,0,size))
        cpu.setRegister(reg_name_h, EXTRACT(reminder,0,size))
        #Flags Affected
        #The CF, OF, SF, ZF, AF, and PF flags are undefined.

    @instruction
    def IDIV(cpu, src):
        ''' 
        Signed divide.
        
        Divides (signed) the value in the AL, AX, or EAX register by the source operand and stores the result 
        in the AX, DX:AX, or EDX:EAX registers. The source operand can be a general-purpose register or a memory 
        location. The action of this instruction depends on the operand size.::

                IF SRC  =  0
                THEN #DE; (* divide error *) 
                FI;
                IF OpernadSize  =  8 (* word/byte operation *)
                THEN
                    temp  =  AX / SRC; (* signed division *)
                    IF (temp > 7FH) OR (temp < 80H) 
                    (* if a positive result is greater than 7FH or a negative result is less than 80H *)
                    THEN #DE; (* divide error *) ;
                    ELSE
                        AL  =  temp;
                        AH  =  AX SignedModulus SRC;
                    FI;
                ELSE
                    IF OpernadSize  =  16 (* doubleword/word operation *)
                    THEN
                        temp  =  DX:AX / SRC; (* signed division *)
                        IF (temp > 7FFFH) OR (temp < 8000H) 
                        (* if a positive result is greater than 7FFFH *)
                        (* or a negative result is less than 8000H *)
                        THEN #DE; (* divide error *) ;
                        ELSE
                            AX  =  temp;
                            DX  =  DX:AX SignedModulus SRC;
                        FI;
                    ELSE (* quadword/doubleword operation *)
                        temp  =  EDX:EAX / SRC; (* signed division *)
                        IF (temp > 7FFFFFFFH) OR (temp < 80000000H) 
                        (* if a positive result is greater than 7FFFFFFFH *)
                        (* or a negative result is less than 80000000H *)
                        THEN #DE; (* divide error *) ;
                        ELSE
                            EAX  =  temp;
                            EDX  =  EDX:EAX SignedModulus SRC;
                        FI;
                    FI;
                FI;
        
        @param cpu: current CPU.
        @param src: source operand.        
        '''

        reg_name_h = { 8: 'AH', 16: 'DX', 32:'EDX', 64:'RDX'}[src.size]
        reg_name_l = { 8: 'AL', 16: 'AX', 32:'EAX', 64:'RAX'}[src.size]
        dividend = CONCAT(src.size, cpu.getRegister(reg_name_h), cpu.getRegister(reg_name_l))
        
        divisor = SEXTEND(src.read(), src.size, src.size * 2)
        if isinstance(divisor, int) and divisor == 0:
            cpu.impossible = 1
            return

        divisor_sign = divisor >= (1<<(src.size*2-1))
        if type(divisor) is int:
            if divisor_sign:
                divisor -= 1<<(src.size*2) -1
                divisor = divisor & ((1<<(src.size*2))-1)

        dividend = SIMP(dividend)
        divisor = SIMP(divisor)

        if divisor == 0:
            cpu.impossible = 1
            return
        quotient = UDIV(dividend, divisor)
        reminder = dividend - (UDIV(dividend, divisor) *divisor)

        if (isinstance(divisor_sign,bool) and not divisor_sign) or FALSE(SIMP(divisor_sign)):
            reminder = -reminder 
        quotient = ITE(src.size * 2, reminder != 0, quotient +1, quotient)

        cpu.setRegister(reg_name_l, EXTRACT(quotient, 0, src.size))
        cpu.setRegister(reg_name_h, EXTRACT(reminder, 0, src.size))
        #Flags Affected
        #The CF, OF, SF, ZF, AF, and PF flags are undefined.

    @instruction
    def IMUL(cpu, *operands):
        ''' 
        Signed multiply.
        
        Performs a signed multiplication of two operands. This instruction has three forms, depending on 
        the number of operands. 
            - One-operand form. This form is identical to that used by the MUL instruction. Here, the source operand 
            (in a general-purpose register or memory location) is multiplied by the value in the AL, AX, or EAX register 
            (depending on the operand size) and the product is stored in the AX, DX:AX, or EDX:EAX registers, respectively. 
            - Two-operand form. With this form the destination operand (the first operand) is multiplied by the source operand 
            (second operand). The destination operand is a general-purpose register and the source operand is an immediate value, 
            a general-purpose register, or a memory location. The product is then stored in the destination operand location.
            - Three-operand form. This form requires a destination operand (the first operand) and two source operands (the second and 
            the third operands). Here, the first source operand (which can be a general-purpose register or a memory location) is multiplied 
            by the second source operand (an immediate value). The product is then stored in the destination operand (a general-purpose register). 
        
        When an immediate value is used as an 
        operand, it is sign-extended to the length of the destination operand format. The CF and OF flags are set 
        when significant bits are carried into the upper half of the result. The CF and OF flags are cleared when the 
        result fits exactly in the lower half of the result.The three forms of the IMUL instruction are similar in that
        the length of the product is calculated to twice the length of the operands. With the one-operand form, the product
        is stored exactly in the destination. With the two- and three- operand forms, however, result is truncated to 
        the length of the destination before it is stored in the destination register. Because of this truncation, the CF
        or OF flag should be tested to ensure that no significant bits are lost. The two- and three-operand forms may 
        also be used with unsigned operands because the lower half of the product is the same regardless if the operands 
        are signed or unsigned. The CF and OF flags, however, cannot be used to determine if the upper half of the result 
        is non-zero::

                IF (NumberOfOperands == 1)
                THEN 
                    IF (OperandSize == 8)
                    THEN
                        AX = AL * SRC (* Signed multiplication *)
                        IF AL == AX
                        THEN 
                            CF = 0; OF = 0;
                        ELSE 
                            CF = 1; OF = 1; 
                        FI;
                    ELSE 
                        IF OperandSize == 16
                        THEN
                            DX:AX = AX * SRC (* Signed multiplication *)
                            IF sign_extend_to_32 (AX) == DX:AX
                            THEN 
                                CF = 0; OF = 0;
                            ELSE 
                                CF = 1; OF = 1;
                            FI;
                        ELSE 
                            IF OperandSize == 32
                            THEN
                                EDX:EAX = EAX * SRC (* Signed multiplication *)
                                IF EAX == EDX:EAX
                                THEN
                                    CF = 0; OF = 0;
                                ELSE 
                                    CF = 1; OF = 1; 
                                FI;
                            ELSE (* OperandSize = 64 *)
                                RDX:RAX = RAX * SRC (* Signed multiplication *)
                                IF RAX == RDX:RAX
                                THEN 
                                    CF = 0; OF = 0;
                                ELSE 
                                   CF = 1; OF = 1;
                                FI;
                            FI;
                        FI;
                ELSE 
                    IF (NumberOfOperands = 2)
                    THEN
                        temp = DEST * SRC (* Signed multiplication; temp is double DEST size *)
                        DEST = DEST * SRC (* Signed multiplication *)
                        IF temp != DEST
                        THEN 
                            CF = 1; OF = 1;
                        ELSE
                            CF = 0; OF = 0; 
                        FI;
                    ELSE (* NumberOfOperands = 3 *)
                        DEST = SRC1 * SRC2 (* Signed multiplication *)
                        temp = SRC1 * SRC2 (* Signed multiplication; temp is double SRC1 size *)
                        IF temp != DEST
                        THEN
                            CF = 1; OF = 1;
                        ELSE    
                            CF = 0; OF = 0;
                        FI;
                    FI;
                FI;
        
        @param cpu: current CPU.
        @param operands: variable list of operands. 
        '''
        dest = operands[0]
        OperandSize = dest.size
        reg_name_h = { 8: 'AH', 16: 'DX', 32:'EDX', 64:'RDX'}[OperandSize]
        reg_name_l = { 8: 'AL', 16: 'AX', 32:'EAX', 64:'RAX'}[OperandSize]

        arg0 = dest.read()
        arg1 = None
        arg2 = None
        res = None
        if len(operands) == 1:
            arg1 = cpu.getRegister(reg_name_l)
            temp = SEXTEND(arg0,OperandSize,OperandSize*2) * SEXTEND(arg1,OperandSize,OperandSize*2)
            cpu.setRegister(reg_name_l, EXTRACT(temp,0,OperandSize))
            cpu.setRegister(reg_name_h, EXTRACT(temp,OperandSize,OperandSize))
            res = temp&((1<<OperandSize)-1)
        elif len(operands) == 2:
            arg1 = operands[1].read()
            temp = SEXTEND(arg0,OperandSize,OperandSize*2) * SEXTEND(arg1,OperandSize,OperandSize*2)
            res = dest.write(EXTRACT(temp,0,OperandSize))
        else:
            arg1 = operands[1].read()
            arg2 = operands[2].read()
            temp = SEXTEND(arg1,OperandSize,OperandSize*2) * SEXTEND(arg2,OperandSize,OperandSize*2)
            res = dest.write(EXTRACT(temp,0,OperandSize))
        
        cpu.CF = (SEXTEND(res, OperandSize, OperandSize*2) != temp)
        cpu.OF = cpu.CF
        cpu.ZF = False
        cpu.AF = False

        cpu.PF = (res ^ res>>1 ^ res>>2 ^ res>>3 ^ res>>4 ^ res>>5 ^ res>>6 ^ res>>7)&1 == 0
        SIGN_MASK = 1<<(OperandSize-1)
        cpu.SF = (res & SIGN_MASK)!=0

    @instruction
    def INC(cpu, dest):
        ''' 
        Increments by 1.
        
        Adds 1 to the destination operand, while preserving the state of the 
        CF flag. The destination operand can be a register or a memory location. 
        This instruction allows a loop counter to be updated without disturbing 
        the CF flag. (Use a ADD instruction with an immediate operand of 1 to 
        perform an increment operation that does updates the CF flag.)::

                DEST  =  DEST +1;
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        '''
        res = dest.write(dest.read()+1)
        cpu.calculateFlags('INC', dest.size, res)

    @instruction
    def MUL(cpu, src):
        ''' 
        Unsigned multiply.
        
        Performs an unsigned multiplication of the first operand (destination 
        operand) and the second operand (source operand) and stores the result 
        in the destination operand. The destination operand is an implied operand 
        located in register AL, AX or EAX (depending on the size of the operand); 
        the source operand is located in a general-purpose register or a memory location. 
        
        The result is stored in register AX, register pair DX:AX, or register 
        pair EDX:EAX (depending on the operand size), with the high-order bits 
        of the product contained in register AH, DX, or EDX, respectively. If 
        the high-order bits of the product are 0, the CF and OF flags are cleared; 
        otherwise, the flags are set::

                IF byte operation
                THEN 
                    AX  =  AL * SRC
                ELSE (* word or doubleword operation *)
                    IF OperandSize  =  16
                    THEN 
                        DX:AX  =  AX * SRC
                    ELSE (* OperandSize  =  32 *)
                        EDX:EAX  =  EAX * SRC
                    FI;
                FI;
        
        @param cpu: current CPU.
        @param src: source operand.        
        '''
        size = src.size
        reg_name_low, reg_name_high = { 8: ('AL','AH'),
                                        16: ('AX','DX'),
                                        32: ('EAX','EDX'),
                                        64: ('RAX','RDX')}[size]
        res = ( ZEXTEND(cpu.getRegister(reg_name_low), size*2)) * ZEXTEND(src.read(), size*2)
        cpu.setRegister(reg_name_low, EXTRACT(res,0,size))
        cpu.setRegister(reg_name_high, EXTRACT(res,size,size))
        cpu.OF = EXTRACT(res,size,size) != 0
        cpu.CF = cpu.OF

    @instruction
    def NEG(cpu, dest):
        ''' 
        Two's complement negation.
        
        Replaces the value of operand (the destination operand) with its two's complement. 
        (This operation is equivalent to subtracting the operand from 0.) The destination operand is 
        located in a general-purpose register or a memory location::

                IF DEST  =  0 
                THEN CF  =  0 
                ELSE CF  =  1; 
                FI;
                DEST  =  - (DEST)
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        '''
        source = dest.read()
        res = dest.write(-source)
        cpu.calculateFlags('LOGIC', dest.size, res)
        cpu.CF = source != 0
        cpu.AF = (res & 0x0f) != 0x00

    @instruction
    def SBB(cpu, dest, src):
        ''' 
        Integer subtraction with borrow.
        
        Adds the source operand (second operand) and the carry (CF) flag, and 
        subtracts the result from the destination operand (first operand). The 
        result of the subtraction is stored in the destination operand. The destination 
        operand can be a register or a memory location; the source operand can 
        be an immediate, a register, or a memory location. (However, two memory 
        operands cannot be used in one instruction.) The state of the CF flag 
        represents a borrow from a previous subtraction.
        When an immediate value is used as an operand, it is sign-extended to 
        the length of the destination operand format.
        The SBB instruction does not distinguish between signed or unsigned 
        operands. Instead, the processor evaluates the result for both data types 
        and sets the OF and CF flags to indicate a borrow in the signed or unsigned 
        result, respectively. The SF flag indicates the sign of the signed result.
        The SBB instruction is usually executed as part of a multibyte 
        or multiword 
        subtraction in which a SUB instruction is followed by a SBB instruction::

                DEST  =  DEST - (SRC + CF);

        @param cpu: current CPU.
        @param dest: destination operand.        
        @param src: source operand.        
        '''
        size = dest.size
        arg0 = dest.read()
        arg1 = SEXTEND(src.read(),src.size, size)
        res = dest.write( arg0 - (arg1 + ITE(size,cpu.CF,1,0)) )
        cpu.calculateFlags('SBB', size, res, arg0, arg1)

    @instruction
    def SUB(cpu, dest, src):
        ''' 
        Subtract.
        
        Subtracts the second operand (source operand) from the first operand 
        (destination operand) and stores the result in the destination operand. 
        The destination operand can be a register or a memory location; the source 
        operand can be an immediate, register, or memory location. (However, two 
        memory operands cannot be used in one instruction.) When an immediate 
        value is used as an operand, it is sign-extended to the length of the 
        destination operand format.
        The SUB instruction does not distinguish between signed or unsigned 
        operands. Instedef SUBad, the processor evaluates the result for both data types 
        and sets the OF and CF flags to indicate a borrow in the signed or unsigned 
        result, respectively. The SF flag indicates the sign of the signed result::

            DEST  =  DEST - SRC;

        @param cpu: current CPU.
        @param dest: destination operand.        
        @param src: source operand.        
        '''
        arg0 = dest.read()
        arg1 = SEXTEND(src.read(), src.size, dest.size)
        res = dest.write(arg0 - arg1)
        cpu.calculateFlags('SUB', dest.size, res, arg0, arg1)

    @instruction
    def XADD(cpu, dest, src):
        '''
        Exchanges and adds.
        
        Exchanges the first operand (destination operand) with the second operand 
        (source operand), then loads the sum of the two values into the destination 
        operand. The destination operand can be a register or a memory location; 
        the source operand is a register.
        This instruction can be used with a LOCK prefix::

                TEMP  =  SRC + DEST
                SRC  =  DEST
                DEST  =  TEMP
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        @param src: source operand.        
        '''
        arg0 = dest.read()
        temp = src.read() + arg0
        src.write(arg0)
        dest.write(temp)


########################################################################################
# Generic Operations
########################################################################################
# Move: BSWAP, CMOVB, CMOVBE, CMOVL, CMOVLE, CMOVNB, CMOVNBE, CMOVNL, CMOVNLE,
#       CMOVNO, CMOVNP, CMOVNS, CMOVNZ, CMOVO, CMOVP, CMOVS, CMOVZ, LAHF, LDS,
#       LEA, LES, LFS, LGS, LSS, MOV, MOVBE, SAHF, SETB, SETBE,
#       SETL, SETLE, SETNB, SETNBE, SETNL, SETNLE, SETNO, SETNP, SETNS, SETNZ, 
#       SETO, SETP, SETS, SETZ, XADD, XCHG, XLAT
########################################################################################
    @instruction
    def BSWAP(cpu, dest):
        ''' 
        Byte swap.
        
        Reverses the byte order of a 32-bit (destination) register: bits 0 through 
        7 are swapped with bits 24 through 31, and bits 8 through 15 are swapped 
        with bits 16 through 23. This instruction is provided for converting little-endian 
        values to big-endian format and vice versa.
        To swap bytes in a word value (16-bit register), use the XCHG instruction. 
        When the BSWAP instruction references a 16-bit register, the result is 
        undefined::

            TEMP  =  DEST
            DEST[7..0]  =  TEMP(31..24]
            DEST[15..8]  =  TEMP(23..16]
            DEST[23..16]  =  TEMP(15..8]
            DEST[31..24]  =  TEMP(7..0]

        @param cpu: current CPU.
        @param dest: destination operand.        
        '''
        size = dest.size
        arg0 = dest.read()
        temp = 0
        for pos in range(0,size,8):
            temp = (temp << 8) | (arg0&0xff)
            arg0 = arg0 >> 8
        dest.write(arg0)

########################################################################################
# Generic Operations -- Moves -- Conditional moves
########################################################################################
#  Unsigned Conditional Moves: CMOVB CMOVNAE CMOVC CMOVB CMOVNBE CMOVA CMOVNB CMOVNC
#                              CMOVAE CMOVNA CMOVBE CMOVNZ CMOVE CMOVNZ CMOVNE CMOVPE
#                              CMOVP CMOVPO CMOVNP
########################################################################################
    ##CMOVcc
    #CMOVB CMOVNAE CMOVC 
    @instruction
    def CMOVB(cpu, dest, src):
        ''' 
        Conditional move - Below/not above or equal.
        
        Tests the status flags in the EFLAGS register and moves the source operand 
        (second operand) to the destination operand (first operand) if the given 
        test condition is true.
        
        @param cpu: current CPU.
        @param dest: destination operand.
        @param src: source operand. 
        '''
        dest.write(ITE(dest.size, cpu.CF, src.read(), dest.read()))

    #CMOVNBE
    @instruction
    def CMOVA(cpu, dest, src):
        ''' 
        Conditional move - Above/not below or equal.
        
        Tests the status flags in the EFLAGS register and moves the source operand 
        (second operand) to the destination operand (first operand) if the given 
        test condition is true.
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        @param src: source operand.
        '''
        dest.write(ITE(dest.size, AND(cpu.CF==False, cpu.ZF==False), src.read(), dest.read()))

    #CMOVNB CMOVNC 
    @instruction
    def CMOVAE(cpu, dest, src):
        ''' 
        Conditional move - Above or equal/not below.
        
        Tests the status flags in the EFLAGS register and moves the source operand 
        (second operand) to the destination operand (first operand) if the given 
        test condition is true.

        @param cpu: current CPU.
        @param dest: destination operand.        
        @param src: source operand.
        '''
        dest.write(ITE(dest.size, cpu.CF==False, src.read(), dest.read()))

    #CMOVNA
    @instruction
    def CMOVBE(cpu, dest, src):
        ''' 
        Conditional move - Below or equal/not above.
        
        Tests the status flags in the EFLAGS register and moves the source operand 
        (second operand) to the destination operand (first operand) if the given 
        test condition is true.

        @param cpu: current CPU.
        @param dest: destination operand.        
        @param src: source operand.
        '''
        dest.write(ITE(dest.size, OR(cpu.CF, cpu.ZF), src.read(), dest.read()))

    @instruction
    def CMOVZ(cpu, dest, src):
        ''' 
        Conditional move - Equal/zero.
        
        Tests the status flags in the EFLAGS register and moves the source operand 
        (second operand) to the destination operand (first operand) if the given 
        test condition is true.
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        @param src: source operand.
        '''
        dest.write(ITE(dest.size, cpu.ZF, src.read(), dest.read()))

    @instruction
    def CMOVNZ(cpu, dest, src):
        ''' 
        Conditional move - Not equal/not zero.
        
        Tests the status flags in the EFLAGS register and moves the source operand 
        (second operand) to the destination operand (first operand) if the given 
        test condition is true.
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        @param src: source operand.
        '''
        dest.write(ITE(dest.size, cpu.ZF==False, src.read(), dest.read()))

    #CMOVPE
    @instruction
    def CMOVP(cpu, dest, src):
        ''' 
        Conditional move - Parity/parity even.
        
        Tests the status flags in the EFLAGS register and moves the source operand 
        (second operand) to the destination operand (first operand) if the given 
        test condition is true.
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        @param src: source operand.
        '''
        dest.write(ITE(dest.size, cpu.PF, src.read(), dest.read()))
    #CMOVPO
    @instruction
    def CMOVNP(cpu, dest, src):
        ''' 
        Conditional move - Not parity/parity odd.
        
        Tests the status flags in the EFLAGS register and moves the source operand 
        (second operand) to the destination operand (first operand) if the given 
        test condition is true.
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        @param src: source operand.
        '''
        dest.write(ITE(dest.size, cpu.PF==False, src.read(), dest.read()))

########################################################################################
# Generic Operations -- Moves -- Signed Conditional Moves
########################################################################################
#  Unsigned Conditional Moves: CMOVGE CMOVNL CMOVL CMOVNGE CMOVLE CMOVNG CMOVO CMOVNO 
#                              CMOVS CMOVNS 
########################################################################################
    #CMOVNL
    @instruction
    def CMOVGE(cpu, dest, src):
        ''' 
        Conditional move - Greater or equal/not less.
        
        Tests the status flags in the EFLAGS register and moves the source operand 
        (second operand) to the destination operand (first operand) if the given 
        test condition is true.
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        @param src: source operand.
        '''
        if type(cpu.SF) is int:
            cpu.SF = BitVecVal(cpu.SF,1)
        if type(cpu.OF) is int:
            cpu.OF = BitVecVal(cpu.OF,1)
        dest.write(ITE(dest.size, XOR(cpu.SF , cpu.OF)==False, src.read(), dest.read()))


    #CMOVNGE
    @instruction
    def CMOVL(cpu, dest, src):
        ''' 
        Conditional move - Less/not greater or equal.
        
        Tests the status flags in the EFLAGS register and moves the source operand 
        (second operand) to the destination operand (first operand) if the given 
        test condition is true.
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        @param src: source operand.
        '''
        if type(cpu.SF) is int:
            cpu.SF = BitVecVal(cpu.SF,1)
        if type(cpu.OF) is int:
            cpu.OF = BitVecVal(cpu.OF,1)
        dest.write(ITE(dest.size, XOR(cpu.SF , cpu.OF)==True, src.read(), dest.read()))

    #CMOVNG
    @instruction
    def CMOVLE(cpu, dest, src):
        ''' 
        Conditional move - Less or equal/not greater.
        
        Tests the status flags in the EFLAGS register and moves the source operand 
        (second operand) to the destination operand (first operand) if the given 
        test condition is true.
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        @param src: source operand.
        '''
        if type(cpu.SF) is int:
            cpu.SF = BitVecVal(cpu.SF,1)
        if type(cpu.OF) is int:
            cpu.OF = BitVecVal(cpu.OF,1)
        if type(cpu.ZF) is int:
            cpu.ZF = BitVecVal(cpu.ZF,1)
        dest.write(ITE(dest.size, OR((XOR(cpu.SF, cpu.OF)), cpu.ZF)==True, src.read(), dest.read()))

    @instruction
    def CMOVO(cpu, dest, src):
        ''' 
        Conditional move - Overflow.
        
        Tests the status flags in the EFLAGS register and moves the source operand 
        (second operand) to the destination operand (first operand) if the given 
        test condition is true.
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        @param src: source operand.
        '''
        dest.write(ITE(dest.size, cpu.OF, src.read(), dest.read()))

    @instruction
    def CMOVNO(cpu, dest, src):
        ''' 
        Conditional move - Not overflow.
        
        Tests the status flags in the EFLAGS register and moves the source operand 
        (second operand) to the destination operand (first operand) if the given 
        test condition is true.
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        @param src: source operand.
        '''
        dest.write(ITE(dest.size, cpu.OF==False, src.read(), dest.read()))

    @instruction
    def CMOVS(cpu, dest, src):
        ''' 
        Conditional move - Sign (negative).
        
        Tests the status flags in the EFLAGS register and moves the source operand 
        (second operand) to the destination operand (first operand) if the given 
        test condition is true.
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        @param src: source operand.
        '''
        dest.write(ITE(dest.size, cpu.SF, src.read(), dest.read()))

    @instruction
    def CMOVNS(cpu, dest, src):
        ''' 
        Conditional move - Not sign (non-negative).
        
        Tests the status flags in the EFLAGS register and moves the source operand 
        (second operand) to the destination operand (first operand) if the given 
        test condition is true.
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        @param src: source operand.
        '''
        dest.write(ITE(dest.size, cpu.SF==False, src.read(), dest.read()))

    @instruction
    def LAHF(cpu, dest, src):
        ''' 
        Loads status flags into AH register.
        
        Moves the low byte of the EFLAGS register (which includes status flags 
        SF, ZF, AF, PF, and CF) to the AH register. Reserved bits 1, 3, and 5 
        of the EFLAGS register are set in the AH register::

                AH  =  EFLAGS(SF:ZF:0:AF:0:PF:1:CF);
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        @param src: source operand.
        '''
        cpu.AH = cpu.EFLAGS

    @instruction
    def LDS(cpu, dest, src):
        """
        Not implemented.
        
        @raise NotImplemented: 
        """
        raise NotImplemented() #TODO
    @instruction
    def LES(cpu, dest, src):
        """
        Not implemented.
        
        @raise NotImplemented: 
        """
        raise NotImplemented() #TODO
    @instruction
    def LFS(cpu, dest, src):
        """
        Not implemented.
        
        @raise NotImplemented: 
        """
        raise NotImplemented() #TODO
    @instruction
    def LGS(cpu, dest, src):
        """
        Not implemented.
        
        @raise NotImplemented: 
        """
        raise NotImplemented() #TODO
    @instruction
    def LSS(cpu, dest, src):
        ''' 
        Loads far pointer.
        
        Loads a far pointer (segment selector and offset) from the second operand 
        (source operand) into a segment register and the first operand (destination 
        operand). The source operand specifies a 48-bit or a 32-bit pointer in 
        memory depending on the current setting of the operand-size attribute 
        (32 bits or 16 bits, respectively). The instruction opcode and the destination 
        operand specify a segment register/general-purpose register pair. The 
        16-bit segment selector from the source operand is loaded into the segment 
        register specified with the opcode (DS, SS, ES, FS, or GS). The 32-bit 
        or 16-bit offset is loaded into the register specified with the destination 
        operand.
        In 64-bit mode, the instruction's default operation size is 32 bits. Using a 
        REX prefix in the form of REX.W promotes operation to specify a source operand
        referencing an 80-bit pointer (16-bit selector, 64-bit offset) in memory.
        If one of these instructions is executed in protected mode, additional 
        information from the segment descriptor pointed to by the segment selector 
        in the source operand is loaded in the hidden part of the selected segment 
        register.
        Also in protected mode, a null selector (values 0000 through 0003) can 
        be loaded into DS, ES, FS, or GS registers without causing a protection 
        exception. (Any subsequent reference to a segment whose corresponding 
        segment register is loaded with a null selector, causes a general-protection 
        exception (#GP) and no memory reference to the segment occurs.)::

                IF ProtectedMode
                THEN IF SS is loaded 
                    THEN IF SegementSelector  =  null
                        THEN #GP(0); 
                        FI;
                    ELSE IF Segment selector index is not within descriptor table limits
                        OR Segment selector RPL  CPL
                        OR Access rights indicate nonwritable data segment
                        OR DPL  CPL
                        THEN #GP(selector);
                        FI;
                    ELSE IF Segment marked not present
                        THEN #SS(selector);
                        FI;
                        SS  =  SegmentSelector(SRC);
                        SS  =  SegmentDescriptor([SRC]);
                    ELSE IF DS, ES, FS, or GS is loaded with non-null segment selector
                        THEN IF Segment selector index is not within descriptor table limits
                            OR Access rights indicate segment neither data nor readable code segment
                            OR (Segment is data or nonconforming-code segment 
                            AND both RPL and CPL > DPL)
                            THEN #GP(selector);
                            FI;
                        ELSE IF Segment marked not present
                            THEN #NP(selector);
                            FI;
                            SegmentRegister  =  SegmentSelector(SRC) AND RPL;
                            SegmentRegister  =  SegmentDescriptor([SRC]);
                        ELSE IF DS, ES, FS, or GS is loaded with a null selector:
                            SegmentRegister  =  NullSelector;
                            SegmentRegister(DescriptorValidBit)  =  0; (*hidden flag; not accessible by software*)
                        FI;
                    FI;
                    IF (Real-Address or Virtual-8086 Mode)
                    THEN
                        SegmentRegister  =  SegmentSelector(SRC);
                    FI;
                    DEST  =  Offset(SRC);
        @raise NotImplemented: 
        '''
        raise NotImplemented()
 
    @instruction
    def LEA(cpu, dest, src):
        ''' 
        Loads effective address.
        
        Computes the effective address of the second operand (the source operand) and stores it in the first operand
        (destination operand). The source operand is a memory address (offset part) specified with one of the processors
        addressing modes; the destination operand is a general-purpose register. The address-size and operand-size
        attributes affect the action performed by this instruction. The operand-size
        attribute of the instruction is determined by the chosen register; the address-size attribute is determined by the
        attribute of the code segment.
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        @param src: source operand.
        '''
        dest.write(EXTRACT(src.address(),0,dest.size))


    @instruction
    def MOV(cpu, dest, src):
        ''' 
        Move.
        
        Copies the second operand (source operand) to the first operand (destination 
        operand). The source operand can be an immediate value, general-purpose 
        register, segment register, or memory location; the destination register 
        can be a general-purpose register, segment register, or memory location. 
        Both operands must be the same size, which can be a byte, a word, or a 
        doubleword.
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        @param src: source operand.
        '''
        dest.write(src.read())

    @instruction
    def MOVBE(cpu, dest, src):
        ''' 
        Moves data after swapping bytes.
        
        Performs a byte swap operation on the data copied from the second operand (source operand) and store the result
        in the first operand (destination operand). The source operand can be a general-purpose register, or memory location; the destination register can be a general-purpose register, or a memory location; however, both operands can
        not be registers, and only one operand can be a memory location. Both operands must be the same size, which can
        be a word, a doubleword or quadword.
        The MOVBE instruction is provided for swapping the bytes on a read from memory or on a write to memory; thus
        providing support for converting little-endian values to big-endian format and vice versa.
        In 64-bit mode, the instruction's default operation size is 32 bits. Use of the REX.R prefix permits access to additional registers (R8-R15). Use of the REX.W prefix promotes operation to 64 bits::

                TEMP = SRC
                IF ( OperandSize = 16)
                THEN
                    DEST[7:0] = TEMP[15:8];
                    DEST[15:8] = TEMP[7:0];
                ELSE IF ( OperandSize = 32)
                    DEST[7:0] = TEMP[31:24];
                    DEST[15:8] = TEMP[23:16];
                    DEST[23:16] = TEMP[15:8];
                    DEST[31:23] = TEMP[7:0];
                ELSE IF ( OperandSize = 64)
                    DEST[7:0] = TEMP[63:56];
                    DEST[15:8] = TEMP[55:48];
                    DEST[23:16] = TEMP[47:40];
                    DEST[31:24] = TEMP[39:32];
                    DEST[39:32] = TEMP[31:24];
                    DEST[47:40] = TEMP[23:16];
                    DEST[55:48] = TEMP[15:8];
                    DEST[63:56] = TEMP[7:0];
                FI;
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        @param src: source operand.
        '''
        size = dest.size
        arg0 = dest.read()
        temp = 0
        for pos in range(0,size,8):
            temp = (temp << 8) | (arg0&0xff)
            arg0 = arg0 >> 8
        dest.write(arg0)

    @instruction
    def SAHF(cpu, dest, src):
        ''' 
        Stores AH into flags.
        
        Loads the SF, ZF, AF, PF, and CF flags of the EFLAGS register with values 
        from the corresponding bits in the AH register (bits 7, 6, 4, 2, and 0, 
        respectively). Bits 1, 3, and 5 of register AH are ignored; the corresponding 
        reserved bits (1, 3, and 5) in the EFLAGS register remain as shown below::

                EFLAGS(SF:ZF:0:AF:0:PF:1:CF)  =  AH;
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        @param src: source operand.
        '''
        cpu.EFLAGS = (cpu.AH &  0xD5) | 0x02

    @instruction
    def SETA(cpu, dest):
        '''
        Sets byte if above. 
        
        Sets the destination operand to 0 or 1 depending on the settings of the status flags (CF, SF, OF, ZF, and PF, 1, 0) in the
        EFLAGS register. The destination operand points to a byte register or a byte in memory. The condition code suffix
        (cc, 1, 0) indicates the condition being tested for::
                IF condition
                THEN 
                    DEST = 1;
                ELSE 
                    DEST = 0;
                FI;
        
        @param cpu: current CPU.
        @param dest: destination operand.        
         '''
        dest.write(ITE(dest.size, OR(cpu.CF , cpu.ZF)==False, 1, 0))

    @instruction
    def SETAE(cpu, dest):
        '''
        Sets byte if above or equal. 

        @param cpu: current CPU.
        @param dest: destination operand.        
        '''
        dest.write(ITE(dest.size, cpu.CF==False, 1, 0))

    @instruction
    def SETB(cpu, dest):
        '''
        Sets byte if below. 
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        '''
        dest.write(ITE(dest.size, cpu.CF, 1, 0))

    @instruction
    def SETBE(cpu, dest):
        '''
        Sets byte if below or equal.
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        '''
        dest.write(ITE(dest.size, OR(cpu.CF , cpu.ZF), 1, 0))

    @instruction
    def SETC(cpu, dest):
        '''
        Sets if carry. 
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        '''
        dest.write(ITE(dest.size, cpu.CF, 1, 0))

    @instruction
    def SETE(cpu, dest):
        '''
        Sets byte if equal.
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        '''
        dest.write(ITE(dest.size, cpu.ZF, 1, 0))

    @instruction
    def SETG(cpu, dest):
        '''
        Sets byte if greater. 
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        '''
        dest.write(ITE(dest.size, AND(cpu.ZF==False, cpu.SF==cpu.OF), 1, 0))

    @instruction
    def SETGE(cpu, dest):
        '''
        Sets byte if greater or equal.
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        '''
        dest.write(ITE(dest.size, cpu.SF==cpu.OF, 1, 0))

    @instruction
    def SETL(cpu, dest):
        '''
        Sets byte if less. 
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        '''
        dest.write(ITE(dest.size, cpu.SF!=cpu.OF, 1, 0))

    @instruction
    def SETLE(cpu, dest):
        '''
        Sets byte if less or equal. 
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        '''
        dest.write(ITE(dest.size, cpu.ZF | cpu.SF!=cpu.OF, 1, 0))

    @instruction
    def SETNA(cpu, dest):
        '''
        Sets byte if not above.
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        '''
        dest.write(ITE(dest.size, cpu.CF | cpu.ZF, 1, 0))

    @instruction
    def SETNAE(cpu, dest):
        '''
        Sets byte if not above or equal. 
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        '''
        dest.write(ITE(dest.size, cpu.CF, 1, 0))

    @instruction
    def SETNB(cpu, dest):
        '''
        Sets byte if not below.         
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        '''
        dest.write(ITE(dest.size, cpu.CF==False, 1, 0))

    @instruction
    def SETNBE(cpu, dest):
        '''
        Sets byte if not below or equal. 
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        '''
        dest.write(ITE(dest.size, cpu.CF==False and cpu.ZF==False, 1, 0))

    @instruction
    def SETNC(cpu, dest):
        '''
        Sets byte if not carry. 
       
        @param cpu: current CPU.
        @param dest: destination operand. 
        '''
        dest.write(ITE(dest.size, cpu.CF==False, 1, 0))

    @instruction
    def SETNE(cpu, dest):
        '''
        Sets byte if not equal.

        @param cpu: current CPU.
        @param dest: destination operand. 
        '''
        dest.write(ITE(dest.size, cpu.ZF==False, 1, 0))

    @instruction
    def SETNG(cpu, dest):
        '''
        Sets byte if not greater. 

        @param cpu: current CPU.
        @param dest: destination operand.        
        '''
        dest.write(ITE(dest.size, cpu.ZF | cpu.SF!=cpu.OF, 1, 0))

    @instruction
    def SETNGE(cpu, dest):
        '''
        Sets if not greater or equal.

        @param cpu: current CPU.
        @param dest: destination operand.        
        '''
        dest.write(ITE(dest.size, cpu.SF!=cpu.OF, 1, 0))

    @instruction
    def SETNL(cpu, dest):
        '''
        Sets byte if not less. 

        @param cpu: current CPU.
        @param dest: destination operand.        
        '''
        dest.write(ITE(dest.size, cpu.SF==cpu.OF, 1, 0))

    @instruction
    def SETNLE(cpu, dest):
        '''
        Sets byte if not less or equal. 

        @param cpu: current CPU.
        @param dest: destination operand.        
        '''
        dest.write(ITE(dest.size, cpu.ZF==False & cpu.SF==cpu.OF, 1, 0))

    @instruction
    def SETNO(cpu, dest):
        '''
        Sets byte if not overflow. 

        @param cpu: current CPU.
        @param dest: destination operand.        
        '''
        dest.write(ITE(dest.size, cpu.OF==False, 1, 0))

    @instruction
    def SETNP(cpu, dest):
        '''
        Sets byte if not parity. 

        @param cpu: current CPU.
        @param dest: destination operand.        
        '''
        dest.write(ITE(dest.size, cpu.PF==False, 1, 0))

    @instruction
    def SETNS(cpu, dest):
        '''
        Sets byte if not sign. 

        @param cpu: current CPU.
        @param dest: destination operand.        
        '''
        dest.write(ITE(dest.size, cpu.SF==False, 1, 0))

    @instruction
    def SETNZ(cpu, dest):
        '''
        Sets byte if not zero. 

        @param cpu: current CPU.
        @param dest: destination operand.        
        '''
        dest.write(ITE(dest.size, cpu.ZF==False, 1, 0))

    @instruction
    def SETO(cpu, dest):
        '''
        Sets byte if overflow. 

        @param cpu: current CPU.
        @param dest: destination operand.        
        '''
        dest.write(ITE(dest.size, cpu.OF, 1, 0))

    @instruction
    def SETP(cpu, dest):
        '''
        Sets byte if parity. 

        @param cpu: current CPU.
        @param dest: destination operand.        
        '''
        dest.write(ITE(dest.size, cpu.PF, 1, 0))

    @instruction
    def SETPE(cpu, dest):
        '''
        Sets byte if parity even.

        @param cpu: current CPU.
        @param dest: destination operand.        
        '''
        dest.write(ITE(dest.size, cpu.PF, 1, 0))

    @instruction
    def SETPO(cpu, dest):
        '''
        Sets byte if parity odd. 

        @param cpu: current CPU.
        @param dest: destination operand.        
        '''
        dest.write(ITE(dest.size, cpu.PF==False, 1, 0))

    @instruction
    def SETS(cpu, dest):
        '''
        Sets byte if sign. 

        @param cpu: current CPU.
        @param dest: destination operand.        
        '''
        dest.write(ITE(dest.size, cpu.SF, 1, 0))

    @instruction
    def SETZ(cpu, dest):
        '''
        Sets byte if zero.

        @param cpu: current CPU.
        @param dest: destination operand.        
        '''
        dest.write(ITE(dest.size, cpu.ZF, 1, 0))

    @instruction
    def XCHG(cpu, dest, src):
        ''' 
        Exchanges register/memory with register.
        
        Exchanges the contents of the destination (first) and source (second) 
        operands. The operands can be two general-purpose registers or a register 
        and a memory location. If a memory operand is referenced, the processor's 
        locking protocol is automatically implemented for the duration of the 
        exchange operation, regardless of the presence or absence of the LOCK 
        prefix or of the value of the IOPL. 
        This instruction is useful for implementing semaphores or similar data 
        structures for process synchronization. 
        The XCHG instruction can also be used instead of the BSWAP instruction 
        for 16-bit operands::

                TEMP  =  DEST
                DEST  =  SRC
                SRC  =  TEMP
        
        @param cpu: current CPU.
        @param dest: destination operand.        
        @param src: source operand. 
        '''
        temp = dest.read()
        dest.write(src.read())
        src.write(temp)

    @instruction
    def XLAT(cpu, dest):
        ''' 
        Table look-up translation.
        
        Locates a byte entry in a table in memory, using the contents of the 
        AL register as a table index, then copies the contents of the table entry 
        back into the AL register. The index in the AL register is treated as 
        an unsigned integer. The XLAT and XLATB instructions get the base address 
        of the table in memory from either the DS:EBX or the DS:BX registers. 
        In 64-bit mode, operation is similar to that in legacy or compatibility mode.
        AL is used to specify the table index (the operand size is fixed at 8 bits). 
        RBX, however, is used to specify the table's base address::
        
                IF AddressSize = 16
                THEN
                    AL = (DS:BX + ZeroExtend(AL));
                ELSE IF (AddressSize = 32)
                    AL = (DS:EBX + ZeroExtend(AL)); FI;
                ELSE (AddressSize = 64)
                    AL = (RBX + ZeroExtend(AL));
                FI;

        @param cpu: current CPU.
        @param dest: destination operand.  
        '''
        raise NotImplemented()
        base_reg = {16: 'BX', 32:'EBX', 64: 'RBX'}
        cpu.AL = dest.read() 

########################################################################################
# Generic Operations
########################################################################################
# Stack: LEAVE, POP, PUSH, POPF, PUSHF, INT
#
# Not Implemented: BOUND, ENTER, INT1, INTO, IRET, IRETD, POPA, POPAD, POPFD,
#                  PUSHA, PUSHAD, PUSHFD
########################################################################################
    @instruction
    def LEAVE(cpu):
        ''' 
        High level procedure exit.
        
        Releases the stack frame set up by an earlier ENTER instruction. The 
        LEAVE instruction copies the frame pointer (in the EBP register) into 
        the stack pointer register (ESP), which releases the stack space allocated 
        to the stack frame. The old frame pointer (the frame pointer for the calling 
        procedure that was saved by the ENTER instruction) is then popped from 
        the stack into the EBP register, restoring the calling procedure's stack 
        frame.
        A RET instruction is commonly executed following a LEAVE instruction 
        to return program control to the calling procedure::
        
                IF StackAddressSize  =  32
                THEN
                    ESP  =  EBP;
                ELSE (* StackAddressSize  =  16*)
                    SP  =  BP;
                FI;
                IF OperandSize  =  32
                THEN
                    EBP  =  Pop();
                ELSE (* OperandSize  =  16*)
                    BP  =  Pop();
                FI;
        
        @param cpu: current CPU.
        '''
        #cpu.STACK = cpu.RBP
        cpu.RBP = SIMP(cpu.RBP)

        cpu.STACK = cpu.FRAME
        cpu.FRAME = cpu.pop(64)

    @instruction
    def POP(cpu, dest):
        ''' 
        Pops a value from the stack.
        
        Loads the value from the top of the stack to the location specified 
        with the destination operand and then increments the stack pointer. 
        
        @param cpu: current CPU.
        @param dest: destination operand.
        '''
        dest.write(cpu.pop(dest.size))

    @instruction
    def PUSH(cpu, src):
        '''
        Pushes a value onto the stack.
        
        Decrements the stack pointer and then stores the source operand on the top of the stack.
        
        @param cpu: current CPU.
        @param src: source operand.
        '''
        #http://stackoverflow.com/questions/11291151/how-push-imm-encodes
        size = src.size
        if size != 8 and size != cpu.AddressSize//2 :
            size = cpu.AddressSize
        cpu.push(src.read(), size)

    @instruction
    def POPF(cpu):
        ''' 
        Pops stack into EFLAGS register. 
        
        @param cpu: current CPU.
        '''
        mask =0x00000001 | 0x00000004 | 0x00000010 | 0x00000040 | 0x00000080 | 0x00000400 | 0x00000800
        cpu.EFLAGS = cpu.pop(16) & mask

    @instruction
    def POPFD(cpu):
        ''' 
        Pops stack into EFLAGS register.
        
        @param cpu: current CPU.
        '''
        mask =0x00000001 | 0x00000004 | 0x00000010 | 0x00000040 | 0x00000080 | 0x00000400 | 0x00000800
        cpu.EFLAGS = cpu.pop(32) & mask

    @instruction
    def POPFQ(cpu):
        ''' 
        Pops stack into EFLAGS register.
        
        @param cpu: current CPU.
        '''
        mask =0x00000001 | 0x00000004 | 0x00000010 | 0x00000040 | 0x00000080 | 0x00000400 | 0x00000800
        cpu.EFLAGS = (cpu.EFLAGS& ~mask) | cpu.pop(64) & mask

    @instruction
    def PUSHF(cpu):
        ''' 
        Pushes FLAGS register onto the stack.
        
        @param cpu: current CPU.
        '''
        cpu.push(cpu.FLAGS, 16)

    @instruction
    def PUSHFD(cpu):
        ''' 
        Pushes EFLAGS register onto the stack.
        
        @param cpu: current CPU.
        '''
        cpu.push(cpu.EFLAGS, 32)

    @instruction
    def PUSHFQ(cpu):
        ''' 
        Pushes RFLAGS register onto the stack.
        
        @param cpu: current CPU.
        '''
        cpu.push(cpu.EFLAGS, 64)

    @instruction
    def INT(cpu, op0):
        ''' 
        Calls to interrupt procedure.
        
        The INT n instruction generates a call to the interrupt or exception handler specified 
        with the destination operand. The INT n instruction is the  general mnemonic for executing
        a software-generated call to an interrupt handler. The INTO instruction is a special 
        mnemonic for calling overflow exception (#OF), interrupt vector number 4. The overflow
        interrupt checks the OF flag in the EFLAGS register and calls the overflow interrupt handler 
        if the OF flag is set to 1.

        @param cpu: current CPU.
        @param op0: destination operand. 
        '''
        raise Interruption(op0.read())

########################################################################################
# Generic Operations
########################################################################################
# Branch: CALL, RETN, JB, JBE, JCXZ, JECXZ, JL, JLE, JMP, JNB, JNBE, JNL, JNLE,
#         JNO, JNP, JNS, JNZ, JO, JP, JS, JZ, LOOP, LOOPNZ, LOOPZ
#
# Not Implemented: CALLF, RETF, JMPF
########################################################################################
    @instruction
    def CALL(cpu, op0):
        '''
        Procedure call.
        
        Saves procedure linking information on the stack and branches to the called procedure specified using the target
        operand. The target operand specifies the address of the first instruction in the called procedure. The operand can
        be an immediate value, a general-purpose register, or a memory location.
        
        @param cpu: current CPU.
        @param op0: target operand.         
        '''
        proc = op0.read()

        if cpu.instruction.op_str[0] != '0' and type(proc) is BitVecRef : #symbolic call
            cpu.done = 1
            cpu.target = proc
            cpu.PC = 0xCAFEBABEDEADBEEF
        elif cpu.instruction.op_str[0] != '0': #Reg call but we didn't track it so kill here
            cpu.impossible = 1
            return
        else:
            cpu.push(cpu.PC, cpu.AddressSize)
            cpu.PC=proc

    @instruction
    def RET(cpu,*operands):
        ''' 
        Returns from procedure.
        
        Transfers program control to a return address located on the top of 
        the stack. The address is usually placed on the stack by a CALL instruction, 
        and the return is made to the instruction that follows the CALL instruction.
        The optional source operand specifies the number of stack bytes to be 
        released after the return address is popped; the default is none.
        
        @param cpu: current CPU.
        @param operands: variable operands list. 
        '''
        N = 0
        if len(operands) > 0:
            N = operands[0].read()
        cpu.PC = cpu.pop(cpu.AddressSize)
        try:
            cpu.PC = cpu.PC.as_long()
        except:
            cpu.done=1
        cpu.STACK += N

        if cpu.PC == 0xdeadbeefcafebabe:
            cpu.done=1
    
    #used as a helper to all the jumps, since they all have the same layout
    def jumpy(self, target, condition, symbol):
        #only display true jumps, never will hit a constraint

        condition = SIMP(condition)

        if self.true_jumps:
            if type(condition) is bool and condition == True:
                self.PC = target.read()
            elif type(condition) is BoolRef and TRUE(condition):
                self.PC = target.read()
            else:
                self.impossible = 1
        else:
            #takes jumps that could be true depending on constraints
            if type(condition) is bool and condition == False:
                self.impossible = 1
            elif type(condition) is BoolRef and FALSE(condition):
                self.impossible = 1
            elif type(condition) is BoolRef and TRUE(condition):
                self.PC = target.read()
            else:
                if self.flag_constraints != ():
                    self.jump_constraints.append(f'{self.size_lookup[self.flag_constraints[3]]} {self.flag_constraints[1]} {symbol} {self.flag_constraints[2]}')
                elif type(condition) in [BitVecRef, BoolRef]:
                    self.jump_constraints.append(f'{condition} {symbol}')
                self.PC = target.read()

    #basing these on https://faydoc.tripod.com/cpu/jcxz.htm
    @instruction
    def JA(cpu, target):
        '''
        Jumps short if above.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''
        cpu.jumpy(target, cpu.CF == False and cpu.ZF == False, 'U>')

    @instruction
    def JAE(cpu, target):
        '''
        Jumps short if above or equal.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''
        cpu.jumpy(target, cpu.CF == False, 'U>=')

    @instruction
    def JB(cpu, target):
        '''
        Jumps short if below.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''
        cpu.jumpy(target, cpu.CF, 'U<')

    @instruction
    def JBE(cpu, target):
        '''
        Jumps short if below or equal.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''
        cpu.jumpy(target, OR(cpu.CF, cpu.ZF), 'U<=')

    @instruction
    def JC(cpu, target):
        '''
        Jumps short if carry.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''
        cpu.JB(target)

    #I CAN'T HANDLE THESE WITH THE WAY I AM HANDLING JUMPS
    #I could attempt to handle them as only true,
    #But I can't guarentee both paths for the jump
    #@instruction
    #def JCXZ(cpu, target):
        '''
        Jumps short if CX register is 0.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''
        #cpu.PC = ITE(cpu.AddressSize, cpu.CX == 0, target.read(), cpu.PC)

    #@instruction
    #def JECXZ(cpu, target):
        '''
        Jumps short if ECX register is 0.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''
        #cpu.PC = ITE(cpu.AddressSize, cpu.ECX == 0, target.read(), cpu.PC)

    #@instruction
    #def JRCXZ(cpu, target):
        '''
        Jumps short if RCX register is 0.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''

    @instruction
    def JE(cpu, target):
        '''
        Jumps short if equal.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''
        cpu.jumpy(target,cpu.ZF, '==')

    @instruction
    def JG(cpu, target):
        '''
        Jumps short if greater.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''
        cpu.jumpy(target,cpu.ZF == False and cpu.SF == cpu.OF, '>')

    @instruction
    def JGE(cpu, target):
        '''
        Jumps short if greater or equal.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''
        cpu.jumpy(target,cpu.SF == cpu.OF,'>=')

    @instruction
    def JL(cpu, target):
        '''
        Jumps short if less.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''
        cpu.jumpy(target,cpu.SF != cpu.OF,'<')

    @instruction
    def JLE(cpu, target):
        '''
        Jumps short if less or equal.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''
        cpu.jumpy(target,cpu.ZF==True or cpu.SF != cpu.OF,'<=')

    @instruction
    def JNA(cpu, target):
        '''
        Jumps short if not above.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''
        cpu.JBE(target)

    @instruction
    def JNAE(cpu, target):
        '''
        Jumps short if not above or equal.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''
        cpu.JB(target)

    @instruction
    def JNB(cpu, target):
        '''
        Jumps short if not below.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''
        cpu.JAE(target)

    @instruction
    def JNBE(cpu, target):
        '''
        Jumps short if not below or equal.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''
        cpu.JA(target)

    @instruction
    def JNC(cpu, target):
        '''
        Jumps short if not carry.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''
        cpu.JAE(target)

    @instruction
    def JNE(cpu, target):
        '''
        Jumps short if not equal.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''
        cpu.jumpy(target, cpu.ZF == False, '!=')

    @instruction
    def JNG(cpu, target):
        '''
        Jumps short if not greater.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''
        cpu.JLE(target)

    @instruction
    def JNGE(cpu, target):
        '''
        Jumps short if not greater or equal.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''
        cpu.JL( target)

    @instruction
    def JNL(cpu, target):
        '''
        Jumps short if not less.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''
        cpu.JGE(target)

    @instruction
    def JNLE(cpu, target):
        '''
        Jumps short if not less or equal.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''
        cpu.JG(target)

    @instruction
    def JNO(cpu, target):
        '''
        Jumps short if not overflow.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''
        cpu.jumpy(target, cpu.OF == False, 'NO')

    @instruction
    def JNP(cpu, target):
        '''
        Jumps short if not parity.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''
        cpu.jumpy(target, cpu.PF == False, 'NP')

    @instruction
    def JNS(cpu, target):
        '''
        Jumps short if not sign.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''
        cpu.jumpy(target, cpu.SF == False, 'NS')

    def JNZ(cpu, target):
        '''
        Jumps short if not zero.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''

        cpu.JNE(target)

    @instruction
    def JO(cpu, target):
        '''
        Jumps short if overflow.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''
        cpu.jumpy(target, cpu.OF, 'O')

    @instruction
    def JP(cpu, target):
        '''
        Jumps short if parity.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''
        cpu.jumpy(target, cpu.PF, 'P')

    @instruction
    def JPE(cpu, target):
        '''
        Jumps short if parity even.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''
        cpu.JP(target)

    @instruction
    def JPO(cpu, target):
        '''
        Jumps short if parity odd.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''
        cpu.JO( target)

    @instruction
    def JS(cpu, target):
        '''
        Jumps short if sign.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''
        cpu.jumpy(target, cpu.SF, 'S')

    @instruction
    def JZ(cpu, target):
        '''
        Jumps short if zero.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''
        cpu.JE(target)

    @instruction
    def JMP(cpu, target):
        '''
        Jump.
        
        Transfers program control to a different point in the instruction stream without
        recording return information. The destination (target) operand specifies the address
        of the instruction being jumped to. This operand can be an immediate value, a general-purpose register, or a memory location.
        
        @param cpu: current CPU.
        @param target: destination operand.         
        '''
        cpu.PC=target.read()

    #LOOPZ
    def LOOP(cpu, dest):
        ''' 
        Loops according to ECX counter.
        
        Performs a loop operation using the ECX or CX register as a counter. 
        Each time the LOOP instruction is executed, the count register is decremented, 
        then checked for 0. If the count is 0, the loop is terminated and program 
        execution continues with the instruction following the LOOP instruction. 
        If the count is not zero, a near jump is performed to the destination 
        (target) operand, which is presumably the instruction at the beginning 
        of the loop. If the address-size attribute is 32 bits, the ECX register 
        is used as the count register; otherwise the CX register is used::

                IF AddressSize  =  32
                THEN 
                    Count is ECX; 
                ELSE (* AddressSize  =  16 *) 
                    Count is CX;
                FI;
                Count  =  Count - 1;
            
                IF (Count  0)  =  1
                THEN
                    EIP  =  EIP + SignExtend(DEST);
                    IF OperandSize  =  16
                    THEN 
                        EIP  =  EIP AND 0000FFFFH;
                    FI;
                ELSE
                    Terminate loop and continue program execution at EIP;
                FI;
        
        @param cpu: current CPU.
        @param dest: destination operand.
        '''
        counter_name = {16: 'CX', 32: 'ECX', 64: 'RCX'}[self.AddressSize]
        counter = cpu.setRegister(counter_name, cpu.getRegister(counter_name)-1)


    def LOOPNZ(cpu, target):
        '''
        Loops if ECX counter is nonzero.
        
        @param cpu: current CPU.
        @param target: destination operand.
        '''
        counter_name = {16: 'CX', 32: 'ECX', 64: 'RCX'}[self.AddressSize]
        counter = cpu.setRegister(counter_name, cpu.getRegister(counter_name)-1)


########################################################################################
# Generic Operations
########################################################################################
# Shifts: RCL, RCR, ROL, ROR, SAL, SAR, SHL, SHLD, SHR, SHRD
#
########################################################################################

    @instruction
    def RCL(cpu, dest, src):
        '''
        Rotates through carry left. 
        
        Shifts (rotates) the bits of the first operand (destination operand) the number of bit positions specified in the
        second operand (count operand) and stores the result in the destination operand. The destination operand can be
        a register or a memory location; the count operand is an unsigned integer that can be an immediate or a value in
        the CL register. In legacy and compatibility mode, the processor restricts the count to a number between 0 and 31
        by masking all the bits in the count operand except the 5 least-significant bits.

        The RCL instruction shifts the CF flag into the least-significant bit and shifts the most-significant bit into the CF flag.
        
        @param cpu: current CPU.
        @param dest: destination operand.
        @param src: count operand.
        '''
        OperandSize = dest.size
        count = src.read()
        tempCount = { 8 : (count & 0x1f) % 9,
                      16: (count & 0x1f) % 17,
                      32: (count & 0x1f),
                      64: (count & 0x3f) }[OperandSize]
        value = dest.read()
        if type(tempCount) is not int:
            cpu.impossible = 1
            return
        while tempCount != 0:
            tempCF = (value >> (OperandSize-1))&0x1 #MSB
            value = value<<1 + cpu.CF
            cpu.CF = tempCF
            tempCount = tempCount-1
        dest.write(value)
        if count == 1:
            cpu.OF = ((value >> (OperandSize-1))&0x1) ^ cpu.CF

    @instruction
    def RCR(cpu, dest, src):
        '''
        Rotates through carry right (RCR).
        
        Shifts (rotates) the bits of the first operand (destination operand) the number of bit positions specified in the
        second operand (count operand) and stores the result in the destination operand. The destination operand can be
        a register or a memory location; the count operand is an unsigned integer that can be an immediate or a value in
        the CL register. In legacy and compatibility mode, the processor restricts the count to a number between 0 and 31
        by masking all the bits in the count operand except the 5 least-significant bits.

        Rotate through carry right (RCR) instructions shift all the bits toward less significant bit positions, except
        for the least-significant bit, which is rotated to the most-significant bit location. The RCR instruction shifts the 
        CF flag into the most-significant bit and shifts the least-significant bit into the CF flag. 
        
        @param cpu: current CPU.
        @param dest: destination operand.
        @param src: count operand.        
        '''
        OperandSize = dest.size
        count = src.read()
        tempCount = { 8 : (count & 0x1f) % 9,
                      16: (count & 0x1f) % 17,
                      32: (count & 0x1f),
                      64: (count & 0x3f) }[OperandSize]
        value = dest.read()

        if count == 1:
            cpu.OF = ((value >> (OperandSize-1))&0x1) ^ cpu.CF

        if type(tempCount) is not int:
            cpu.impossible = 1
            return
        while tempCount != 0:
            tempCF = value&0x1 #LSB
            value = value>>1 + ITE(dest.size, cpu.CF, 1<<(OperandSize-1), 0)
            cpu.CF = tempCF
            tempCount = tempCount-1
        dest.write(value)

    @instruction
    def ROL(cpu, dest, src):
        '''
        Rotates left (ROL).
        
        Shifts (rotates) the bits of the first operand (destination operand) the number of bit positions specified in the
        second operand (count operand) and stores the result in the destination operand. The destination operand can be
        a register or a memory location; the count operand is an unsigned integer that can be an immediate or a value in
        the CL register. In legacy and compatibility mode, the processor restricts the count to a number between 0 and 31
        by masking all the bits in the count operand except the 5 least-significant bits.

        The rotate left shift all the bits toward more-significant bit positions, except for the most-significant bit, which
        is rotated to the least-significant bit location.
        
        @param cpu: current CPU.
        @param dest: destination operand.
        @param src: count operand.
        '''
        OperandSize = dest.size
        count = src.read()

        countMask = { 8 : 0x1f,
                      16: 0x1f,
                      32: 0x1f,
                      64: 0x3f }[OperandSize]
        tempCount = ( count & countMask ) % OperandSize

        value = dest.read()
        if type(tempCount) is not int: #I don't want to think of the logic at the moment
            cpu.impossible = 1
            return
        while tempCount != 0:
            tempCF = (value >> (OperandSize-1))&1 #MSB
            value = (value<<1) + tempCF
            cpu.CF = tempCF != 0
            tempCount = tempCount-1
        dest.write(value)

        if tempCount == 1:
            cpu.CF = value&1 != 0
            if count & countMask == 1:
                #the OF flag is set to the XOR of the CF bit (after the rotate) and the most-significant bit of the result
                cpu.OF = ((value >> (OperandSize-1))&0x1 ) ^ cpu.CF

    @instruction
    def ROR(cpu, dest, src):
        '''
        Rotates rigth (ROR).
        
        Shifts (rotates) the bits of the first operand (destination operand) the number of bit positions specified in the
        second operand (count operand) and stores the result in the destination operand. The destination operand can be
        a register or a memory location; the count operand is an unsigned integer that can be an immediate or a value in
        the CL register. In legacy and compatibility mode, the processor restricts the count to a number between 0 and 31
        by masking all the bits in the count operand except the 5 least-significant bits.

        The rotate right (ROR) instruction shift all the bits toward less significant bit positions, except
        for the least-significant bit, which is rotated to the most-significant bit location.
        
        @param cpu: current CPU.
        @param dest: destination operand.
        @param src: count operand.
        '''
        OperandSize = dest.size
        count = src.read()

        countMask = { 8 : 0x1f,
                      16: 0x1f,
                      32: 0x1f,
                      64: 0x3f }[OperandSize]
        tempCount = ( count & countMask ) % OperandSize

        value = dest.read()

        tempCF = value&((1<<count)-1)
        value = (value>>count) + (tempCF<<(OperandSize-count))

        dest.write(value)

        cpu.CF = (value >> (OperandSize-1))&0x1==1 #MSB
        if count & countMask == 1:
            #the OF flag is set to the XOR of the two most-significant bits of the result
            cpu.OF = ((value >> (OperandSize-1))&0x1 ) ^ ((value >> (OperandSize-2))&0x1 ) 

    @instruction
    def SAL(cpu, dest, src):
        '''
        The shift arithmetic left.
        
        Shifts the bits in the first operand (destination operand) to the left or right by the number of bits specified in the
        second operand (count operand). Bits shifted beyond the destination operand boundary are first shifted into the CF
        flag, then discarded. At the end of the shift operation, the CF flag contains the last bit shifted out of the destination
        operand.
        
        @param cpu: current CPU.
        @param dest: destination operand.
        @param src: count operand.
        '''
        OperandSize = dest.size
        count = src.read()
        countMask = { 8 : 0x1f,
                      16: 0x1f,
                      32: 0x1f,
                      64: 0x3f }[OperandSize]
        tempCount = ZEXTEND(count & countMask , dest.size)

        tempDest = value = dest.read()
        res = dest.write(ITE(dest.size, tempCount == 0, tempDest, value << tempCount))

        #Should not modify flags if tempcount == 0
        MASK = (1<<OperandSize)-1
        SIGN_MASK = 1<<(OperandSize-1)

        check = AND(tempCount==0, cpu.CF)
        check2 = AND(tempCount!=0,tempDest&(1<<(OperandSize-tempCount))!=0)

        #cpu.CF = (tempCount==0) & cpu.CF | (tempCount!=0) & (tempDest & (1<< (OperandSize-tempCount)) != 0)
        cpu.CF = OR(check,AND(tempCount!=0 , tempDest & (1<< (OperandSize-tempCount) )!=0))
        #cpu.OF = (tempCount==0) & cpu.OF | (tempCount!=0) & ( (res & SIGN_MASK  ^ cpu.CF) )
        cpu.SF = OR(check, AND(tempCount!=0,(res & SIGN_MASK)!=0))
        #cpu.SF = (tempCount==0) & cpu.SF | (tempCount!=0) & ((res & SIGN_MASK) != 0)
        cpu.ZF = OR(check, AND(tempCount!=0,res ==0))
        #cpu.ZF = (tempCount==0) & cpu.ZF | (tempCount!=0) & (res == 0)
        cpu.PF = OR(check, AND(tempCount!=0,((res ^ res>>1 ^ res>>2 ^ res>>3 ^ res>>4 ^ res>>5 ^ res>>6 ^ res>>7)&1 == 0)))
        #cpu.PF = (tempCount==0) & cpu.PF | (tempCount!=0) & ((res ^ res>>1 ^ res>>2 ^ res>>3 ^ res>>4 ^ res>>5 ^ res>>6 ^ res>>7)&1 == 0)

    def SHL(cpu, dest, src):
        '''
        The shift logical left.
            
        The shift arithmetic left (SAL) and shift logical left (SHL) instructions perform the same operation.
        
        @param cpu: current cpu.
        @param dest: destination operand.
        @param src: source operand.
        '''
        return cpu.SAL(dest,src)

    @instruction
    def SAR(cpu, dest, src):
        ''' 
        Shift arithmetic right.
        
        The shift arithmetic right (SAR) and shift logical right (SHR) instructions shift the bits of the destination operand to
        the right (toward less significant bit locations). For each shift count, the least significant bit of the destination
        operand is shifted into the CF flag, and the most significant bit is either set or cleared depending on the instruction
        type. The SHR instruction clears the most significant bit. the SAR instruction sets or clears the most significant bit 
        to correspond to the sign (most significant bit) of the original value in the destination operand. In effect, the SAR 
        instruction fills the empty bit position's shifted value with the sign of the unshifted value
        
        @param cpu: current CPU.
        @param dest: destination operand.
        @param src: source operand.
        '''
        OperandSize = dest.size
        count = src.read()
        countMask = { 8 : 0x1f,
                      16: 0x1f,
                      32: 0x1f,
                      64: 0x3f }[OperandSize]
        tempCount =  count & countMask 
        tempDest = value = dest.read()

        sign = value & (1<<(OperandSize-1))
        if type(tempCount) is not int:
            cpu.impossible = 1
            return
        while tempCount != 0:
            cpu.CF = (value & 0x1) != 0 #LSB
            value = (value >> 1 ) | sign
            tempCount = tempCount-1
        res = dest.write(value)

        cpu.calculateFlags('SAR', OperandSize, res, tempDest, tempCount)
        if count & countMask == 1:
            cpu.OF = 0

    @instruction
    def SHR(cpu, dest, src):
        '''
        Shift logical right. 
        
        The shift arithmetic right (SAR) and shift logical right (SHR) instructions shift the bits of the destination operand to
        the right (toward less significant bit locations). For each shift count, the least significant bit of the destination
        operand is shifted into the CF flag, and the most significant bit is either set or cleared depending on the instruction
        type. The SHR instruction clears the most significant bit. 
        
        @param cpu: current CPU.
        @param dest: destination operand.
        @param src: count operand.
        '''
        OperandSize = dest.size
        count = ZEXTEND(src.read() & (OperandSize-1) , OperandSize)
        value = SIMP(dest.read())

        count = SIMP(count)

        res = dest.write(value >> count) #UNSIGNED UDIV2 !! TODO Check

        MASK = (1<<OperandSize)-1
        SIGN_MASK = 1<<(OperandSize-1)
        if isinstance(count,(int)):
            if count > 0 : #Fix negative shift count
                cpu.CF = 0 != ((value >> (count - 1))&1) #Shift one less than normally and keep LSB
        else:
            cpu.CF = OR(AND((count > 0), (0 != ((value >> (count - 1))&1))), AND((count <= 0) , cpu.CF))

        cpu.PF = (res ^ res>>1 ^ res>>2 ^ res>>3 ^ res>>4 ^ res>>5 ^ res>>6 ^ res>>7)&1 == 0
        cpu.SF = (res & SIGN_MASK)!=0
        cpu.ZF = (res == 0)
        cpu.OF = ((value >> (OperandSize-1))&0x1) == 1 #MSB

    @instruction
    def SHRD(cpu, dest, src, count):
        ''' 
        DOES NOT OPPERATE CORRECTLY WITH BOOLREFS
        Double precision shift right.
        
        Shifts the first operand (destination operand) to the right the number of bits specified by the third operand 
        (count operand). The second operand (source operand) provides bits to shift in from the left (starting with 
        the most significant bit of the destination operand). 
        
        @param cpu: current CPU.
        @param dest: destination operand.
        @param src: source operand.
        @param count: count operand 
        '''
        OperandSize = dest.size
        tempCount =  ZEXTEND(count.read(), OperandSize) & (OperandSize - 1)
        arg0 = dest.read()
        arg1 = src.read()

        res = ITE(OperandSize, tempCount == 0, arg0,  (arg0 >> tempCount) | (arg1 << (dest.size-tempCount)))
        dest.write(res)

        #cpu.calculateFlags('SHR', OperandSize, res, tempDest, tempCount)
        MASK = (1<<OperandSize)-1
        SIGN_MASK = 1<<(OperandSize-1)
        if type(tempCount) is not int:
            cpu.impossible = 1
            return 0
        if tempCount:
            cpu.CF = 0 != ((arg0 >> (tempCount - 1))&1) #Shift one less than normally and keep LSB

        cpu.PF = (res ^ res>>1 ^ res>>2 ^ res>>3 ^ res>>4 ^ res>>5 ^ res>>6 ^ res>>7)&1 == 0
        cpu.SF = (res & SIGN_MASK)!=0
        cpu.ZF = (tempCount == 0) & cpu.ZF |  (tempCount)&(res == 0)


    @instruction
    def SHLD(cpu, dest, src, count):
        ''' 
        Double precision shift right.
        
        Shifts the first operand (destination operand) to the left the number of bits specified by the third operand 
        (count operand). The second operand (source operand) provides bits to shift in from the right (starting with 
        the least significant bit of the destination operand). 
        
        @param cpu: current CPU.
        @param dest: destination operand.
        @param src: source operand.
        @param count: count operand 
        '''
        OperandSize = dest.size
        tempCount =  ZEXTEND(count.read(), OperandSize) & (OperandSize - 1)
        arg0 = dest.read()
        arg1 = src.read()

        res = ITE(OperandSize, tempCount == 0, arg0,  (arg0 << tempCount) | (arg1 >> (dest.size-tempCount)))
        dest.write(res)

        MASK = (1<<OperandSize)-1
        SIGN_MASK = 1<<(OperandSize-1)
        if type(tempCount) is not int:
            cpu.impossible = 1
            return 0
        if tempCount > 0 :
            cpu.CF = 0 != ((arg0 << (tempCount - 1))&SIGN_MASK) #Shift one less than normally and keep LSB

        cpu.PF = (res ^ res>>1 ^ res>>2 ^ res>>3 ^ res>>4 ^ res>>5 ^ res>>6 ^ res>>7)&1 == 0
        cpu.SF = (res & SIGN_MASK)!=0
        cpu.ZF = (tempCount == 0) & cpu.ZF |  (tempCount != 0)&(res == 0)

########################################################################################
# Generic Operations
########################################################################################
# Bits: BSF, BSR, BT, BTC, BTR, BTS, POPCNT
#
########################################################################################
    @instruction
    def BSF(cpu, dest, src):
        ''' 
        Bit scan forward.
        
        Searches the source operand (second operand) for the least significant 
        set bit (1 bit). If a least significant 1 bit is found, its bit index 
        is stored in the destination operand (first operand). The source operand 
        can be a register or a memory location; the destination operand is a register. 
        The bit index is an unsigned offset from bit 0 of the source operand. 
        If the contents source operand are 0, the contents of the destination 
        operand is undefined::

                    IF SRC  =  0
                    THEN
                        ZF  =  1;
                        DEST is undefined;
                    ELSE
                        ZF  =  0;
                        temp  =  0;
                        WHILE Bit(SRC, temp)  =  0
                        DO
                            temp  =  temp + 1;
                            DEST  =  temp;
                        OD;
                    FI;
        
        @param cpu: current CPU.
        @param dest: destination operand.
        @param src: source operand.  
        '''
        value = src.read()
        flag = EXTRACT(value, 0, 1) == 1
        res = 0
        for pos in range(0, src.size):
            res = ITE(dest.size, flag, res, pos)
            flag = OR(flag,  (EXTRACT(value, pos, 1) == 1))

        cpu.ZF = value == 0
        dest.write(ITE(dest.size, cpu.ZF, dest.read(), res))
        res = value
        cpu.PF = (res ^ res>>1 ^ res>>2 ^ res>>3 ^ res>>4 ^ res>>5 ^ res>>6 ^ res>>7)&1 == 0

    @instruction
    def BSR(cpu, dest, src):
        ''' 
        Bit scan reverse.
        
        Searches the source operand (second operand) for the most significant 
        set bit (1 bit). If a most significant 1 bit is found, its bit index is 
        stored in the destination operand (first operand). The source operand 
        can be a register or a memory location; the destination operand is a register. 
        The bit index is an unsigned offset from bit 0 of the source operand. 
        If the contents source operand are 0, the contents of the destination 
        operand is undefined::

                IF SRC  =  0
                THEN
                    ZF  =  1;
                    DEST is undefined;
                ELSE
                    ZF  =  0;
                    temp  =  OperandSize - 1;
                    WHILE Bit(SRC, temp)  =  0
                    DO
                        temp  =  temp - 1;
                        DEST  =  temp;
                    OD;
                FI;
        
        @param cpu: current CPU.
        @param dest: destination operand.
        @param src: source operand.
        '''
        value = src.read()
        flag = EXTRACT(value, src.size-1, 1) == 1
        res = 0

        for pos in reversed(range(0, src.size)):
            res = ITE(dest.size, flag, res, pos)
            flag = OR(flag,  (EXTRACT(value, pos, 1) == 1))

        cpu.PF = (res ^ res>>1 ^ res>>2 ^ res>>3 ^ res>>4 ^ res>>5 ^ res>>6 ^ res>>7)&1 == 0
        cpu.ZF = value == 0
        dest.write(ITE(dest.size, cpu.ZF, dest.read(), res))

    @instruction
    def BT(cpu, dest, src):
        ''' 
        Bit Test.
        
        Selects the bit in a bit string (specified with the first operand, called the bit base) at the 
        bit-position designated by the bit offset (specified by the second operand) and stores the value 
        of the bit in the CF flag. The bit base operand can be a register or a memory location; the bit 
        offset operand can be a register or an immediate value:
            - If the bit base operand specifies a register, the instruction takes the modulo 16, 32, or 64 
              of the bit offset operand (modulo size depends on the mode and register size; 64-bit operands 
              are available only in 64-bit mode).
            - If the bit base operand specifies a memory location, the operand represents the address of the 
              byte in memory that contains the bit base (bit 0 of the specified byte) of the bit string. The 
              range of the bit position that can be referenced by the offset operand depends on the operand size.
        
        @param cpu: current CPU.
        @param dest: bit base.
        @param src: bit offset.
        '''
        cpu.CF = ((dest.read() >> (src.read()%dest.size) ) &1) !=0

    @instruction
    def BTC(cpu, dest, src):
        ''' 
        Bit test and complement.
        
        Selects the bit in a bit string (specified with the first operand, called 
        the bit base) at the bit-position designated by the bit offset operand 
        (second operand), stores the value of the bit in the CF flag, and complements 
        the selected bit in the bit string.
        
        @param cpu: current CPU.
        @param dest: bit base operand.
        @param src: bit offset operand.
        '''
        value = dest.read()
        pos = src.read()%dest.size
        cpu.CF = value & (1<<pos) == 1<<pos
        dest.write(value ^ (1 << pos))

    @instruction
    def BTR(cpu, dest, src):
        ''' 
        Bit test and reset.
        
        Selects the bit in a bit string (specified with the first operand, called 
        the bit base) at the bit-position designated by the bit offset operand 
        (second operand), stores the value of the bit in the CF flag, and clears 
        the selected bit in the bit string to 0. 
        
        @param cpu: current CPU.
        @param dest: bit base operand.
        @param src: bit offset operand.
        '''
        assert dest.type == 1
        value = dest.read()
        pos = src.read()%dest.size
        cpu.CF = value & (1<<pos) == 1<<pos
        dest.write(value & ~(1 << pos))

    @instruction
    def BTS(cpu, dest, src):
        ''' 
        Bit test and set.
        
        Selects the bit in a bit string (specified with the first operand, called 
        the bit base) at the bit-position designated by the bit offset operand 
        (second operand), stores the value of the bit in the CF flag, and sets 
        the selected bit in the bit string to 1.
        
        @param cpu: current CPU.
        @param dest: bit base operand.
        @param src: bit offset operand.
        '''
        value = dest.read()
        pos = src.read()%dest.size
        cpu.CF = value & (1<<pos) == 1<<pos
        dest.write(value | (1 << pos))

########################################################################################
# Generic Operations
########################################################################################
# Bits: CMPS, INS, LODS, MOVS, OUTS, SCAS, STOS
#
########################################################################################
    @rep
    def CMPS(cpu, dest, src):
        '''
        Compares string operands.
        
        Compares the byte, word, double word or quad specified with the first source 
        operand with the byte, word, double or quad word specified with the second 
        source operand and sets the status flags in the EFLAGS register according 
        to the results. Both the source operands are located in memory:: 

                temp  = SRC1 - SRC2;
                SetStatusFlags(temp);
                IF (byte comparison)
                THEN IF DF  =  0
                    THEN 
                        (E)SI  =  (E)SI + 1; 
                        (E)DI  =  (E)DI + 1; 
                    ELSE 
                        (E)SI  =  (E)SI - 1; 
                        (E)DI  =  (E)DI - 1; 
                    FI;
                ELSE IF (word comparison)
                    THEN IF DF  =  0
                        (E)SI  =  (E)SI + 2; 
                        (E)DI  =  (E)DI + 2; 
                    ELSE 
                        (E)SI  =  (E)SI - 2; 
                        (E)DI  =  (E)DI - 2; 
                    FI;
                ELSE (* doubleword comparison*)
                    THEN IF DF  =  0
                        (E)SI  =  (E)SI + 4; 
                        (E)DI  =  (E)DI + 4; 
                    ELSE 
                        (E)SI  =  (E)SI - 4; 
                        (E)DI  =  (E)DI - 4; 
                    FI;
                FI;
        
        @param cpu: current CPU.
        @param dest: first source operand.
        @param src: second source operand.
        '''
        src_reg = {8: 'SI', 32: 'ESI', 64: 'RSI'}[cpu.AddressSize]
        dest_reg = {8: 'DI', 32: 'EDI', 64: 'RDI'}[cpu.AddressSize]
        src_addr = cpu.getRegister(src_reg)
        dest_addr = cpu.getRegister(dest_reg)
        size = dest.size

        #Compare
        arg0 = cpu.load(dest_addr, size)
        arg1 = cpu.load(src_addr, size)
        res = arg0 - arg1
        cpu.calculateFlags('CMP', size, res, arg0, arg1)

        #Advance EDI/ESI pointers
        increment = ITE(size, cpu.DF, -size//8, size//8)
        cpu.setRegister(src_reg, cpu.getRegister(src_reg) + increment)
        cpu.setRegister(dest_reg, cpu.getRegister(dest_reg) + increment)

    '''
    @rep
    def CMPSB(cpu):
         
        Compares string operands.
        
        Compares the byte, word, double word or quad specified with the first source 
        operand with the byte, word, double or quad word specified with the second 
        source operand and sets the status flags in the EFLAGS register according 
        to the results. Both the source operands are located in memory:: 

            temp  = SRC1 - SRC2;
            SetStatusFlags(temp);
            Advance pointers
        
        @param cpu: current CPU.
        @param dest: first source operand.
        @param src: second source operand.    
        
        
        src_reg = {8: 'SI', 32: 'ESI', 64: 'RSI'}[cpu.AddressSize]
        dest_reg = {8: 'DI', 32: 'EDI', 64: 'RDI'}[cpu.AddressSize]

        src_addr = cpu.getRegister(src_reg)
        dest_addr = cpu.getRegister(dest_reg)
        size = 8 #Selected by opcode

        sys.stdin.readline()
        #Compare
        arg0 = cpu.load(dest_addr, size)
        arg1 = cpu.load(src_addr, size)
        res = arg0 - arg1
        cpu.calculateFlags('CMP', size, res, arg0, arg1)

        #Advance EDI/ESI pointers
        increment = ITE(size, cpu.DF, -size//8, size//8)

        cpu.setRegister(src_reg, src_addr + increment)
        cpu.setRegister(dest_reg, dest_addr + increment)
        '''

    def LODS(cpu, dest):
        ''' 
        Loads string.
        
        Loads a byte, word, or doubleword from the source operand into the AL, AX, or EAX register, respectively. The
        source operand is a memory location, the address of which is read from the DS:ESI or the DS:SI registers
        (depending on the address-size attribute of the instruction, 32 or 16, respectively). The DS segment may be over-
        ridden with a segment override prefix.
        After the byte, word, or doubleword is transferred from the memory location into the AL, AX, or EAX register, the
        (E)SI register is incremented or decremented automatically according to the setting of the DF flag in the EFLAGS
        register. (If the DF flag is 0, the (E)SI register is incremented; if the DF flag is 1, the ESI register is decremented.)
        The (E)SI register is incremented or decremented by 1 for byte operations, by 2 for word operations, or by 4 for
        doubleword operations.
        
        @param cpu: current CPU.
        @param dest: source operand.    
        '''
        size = dest.size
        raise NotImplemented()

    def MOVSB(cpu, dest, src):
        cpu.MOVS(dest, src)

    def MOVSW(cpu, dest, src):
        cpu.MOVS(dest, src)

    @rep
    def MOVS(cpu, dest, src):
        ''' 
        Moves data from string to string.
        
        Moves the byte, word, or doubleword specified with the second operand (source operand) to the location specified
        with the first operand (destination operand). Both the source and destination operands are located in memory. The
        address of the source operand is read from the DS:ESI or the DS:SI registers (depending on the address-size
        attribute of the instruction, 32 or 16, respectively). The address of the destination operand is read from the ES:EDI
        or the ES:DI registers (again depending on the address-size attribute of the instruction). The DS segment may be
        overridden with a segment override prefix, but the ES segment cannot be overridden.
        
        @param cpu: current CPU.
        @param dest: destination operand.
        @param src: source operand.
        '''
        src_addr = src.address()
        dest_addr = dest.address()

#        src_reg = Registers[src.index]
#        dest_reg = Registers[dest.index]

        src_reg = CapRegisters[src.mem.base]
        dest_reg = CapRegisters[dest.mem.base]
        size = dest.size

        #Copy the data
        dest.write(src.read())

        #Advance EDI/ESI pointers
        increment = ITE(size, cpu.DF, -size//8, size//8)
        cpu.setRegister(src_reg, cpu.getRegister(src_reg) + increment)
        cpu.setRegister(dest_reg, cpu.getRegister(dest_reg) + increment)

    @rep
    def SCAS(cpu, dest, src):
        ''' 
        Scans String.
        
        Compares the byte, word, or double word specified with the memory operand 
        with the value in the AL, AX, EAX, or RAX register, and sets the status flags 
        according to the results. The memory operand address is read from either
        the ES:RDI, ES:EDI or the ES:DI registers (depending on the address-size 
        attribute of the instruction, 32 or 16, respectively)::

                IF (byte cmparison)
                THEN
                    temp  =  AL - SRC;
                    SetStatusFlags(temp);
                    THEN IF DF  =  0
                        THEN (E)DI  =  (E)DI + 1; 
                        ELSE (E)DI  =  (E)DI - 1; 
                        FI;
                    ELSE IF (word comparison)
                        THEN
                            temp  =  AX - SRC;
                            SetStatusFlags(temp)
                            THEN IF DF  =  0
                                THEN (E)DI  =  (E)DI + 2; 
                                ELSE (E)DI  =  (E)DI - 2; 
                                FI;
                     ELSE (* doubleword comparison *)
                           temp  =  EAX - SRC;
                           SetStatusFlags(temp)
                           THEN IF DF  =  0
                                THEN 
                                    (E)DI  =  (E)DI + 4; 
                                ELSE 
                                    (E)DI  =  (E)DI - 4; 
                                FI;
                           FI;
                     FI;
        
        @param cpu: current CPU.
        @param dest: destination operand.
        @param src: source operand.
        '''
        dest_reg = CapRegisters[dest.reg]
        mem_reg = CapRegisters[src.mem.base] #, src.type, src.read()
        size = dest.size
        arg0 = dest.read()
        arg1 = src.read()
        res = arg0 - arg1
        cpu.calculateFlags('SUB', size, res, arg1, arg0)

        increment = ITE(cpu.AddressSize, cpu.DF, -size//8, size//8)
        cpu.setRegister(mem_reg, cpu.getRegister(mem_reg) + increment)

    @rep
    def STOS(cpu, dest, src):
        ''' 
        Stores String.
        
        Stores a byte, word, or doubleword from the AL, AX, or EAX register, 
        respectively, into the destination operand. The destination operand is 
        a memory location, the address of which is read from either the ES:EDI 
        or the ES:DI registers (depending on the address-size attribute of the 
        instruction, 32 or 16, respectively). The ES segment cannot be overridden 
        with a segment override prefix.
        
        @param cpu: current CPU.
        @param dest: destination operand.
        @param src: source operand.
        '''
        size = dest.size
        
        dest.write(src.read())

        increment = ITE(size, cpu.DF, -size//8, size//8)


        dest_reg = CapRegisters[dest.mem.base]
        cpu.setRegister(dest_reg, cpu.getRegister(dest_reg) + increment)


########################################################################################
# MMX Operations
########################################################################################
# State Management: EMMS
#
########################################################################################
    @instruction
    def EMMS(cpu, dest, src):
        '''
        Empty MMX Technology State

        Sets the values of all the tags in the x87 FPU tag word to empty (all 
        1s). This operation marks the x87 FPU data registers (which are aliased 
        to the MMX technology registers) as available for use by x87 FPU 
        floating-point instructions.

            x87FPUTagWord <- FFFFH;
        '''
        raise NotImplemented()

#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
#@@@@@@@@@@@@@@@@@ compulsive coding after this @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

    @instruction
    def PXOR(cpu, dest, src):
        ''' 
        Logical exclusive OR.
        
        Performs a bitwise logical exclusive-OR (XOR) operation on the quadword 
        source (second) and destination (first) operands and stores the result 
        in the destination operand location. The source operand can be an MMX(TM)
        technology register or a quadword memory location; the destination operand
        must be an MMX register. Each bit of the result is 1 if the corresponding 
        bits of the two operands are different; each bit is 0 if the corresponding 
        bits of the operands are the same::
        
            DEST  =  DEST XOR SRC;
        
        @param cpu: current CPU.
        @param dest: destination operand.
        @param src: quadword source operand.
        '''
        res = dest.write(dest.read() ^ src.read())

    @instruction
    def PUNPCKLBW(cpu, op0, op1):
        '''
        Interleaves the low-order bytes of the source and destination operands.
        
        Unpacks and interleaves the low-order data elements (bytes, words, doublewords, and quadwords)
        of the destination operand (first operand) and source operand (second operand) into the 
        destination operand.

        @param cpu: current CPU.
        @param op0: destination operand.
        @param op1: source operand.
        '''
        size = op0.size
        arg0 = op0.read()
        arg1 = op1.read()

        res = 0
        for pos in reversed(range(0, size//2, 8)):
            byte0 = ZEXTEND( ( arg0 >> pos )& 0xff, size)
            byte1 = ZEXTEND( ( arg1 >> pos )& 0xff, size)
            res = res << 8
            res |= byte1
            res = res << 8
            res |= byte0
        op0.write(res)

    @instruction
    def PUNPCKLWD(cpu, dest, src):
        '''
        Interleaves the low-order bytes of the source and destination operands.
        
        Unpacks and interleaves the low-order data elements (bytes, words, doublewords, and quadwords)
        of the destination operand (first operand) and source operand (second operand) into the 
        destination operand.

        @param cpu: current CPU.
        @param op0: destination operand.
        @param op1: source operand.
        '''
        size = dest.size
        arg0 = dest.read()
        arg1 = src.read()

        res = 0
        for pos in reversed(range(0, size//2, 8)):
            elem0 = ZEXTEND( ( arg0 >> pos )& ((1 << size//2)-1), size)
            elem1 = ZEXTEND( ( arg1 >> pos )& ((1 << size//2)-1), size)
            res = res << (size//2)
            res |= elem1
            res = res << (size//2)
            res |= elem0
        dest.write(res)

    @instruction
    def PUNPCKLQDQ(cpu, dest, src):
        '''
        Interleaves the low-order quad-words of the source and destination operands.
        
        Unpacks and interleaves the low-order data elements (bytes, words, doublewords, and quadwords)
        of the destination operand (first operand) and source operand (second operand) into the 
        destination operand.

        @param cpu: current CPU.
        @param op0: destination operand.
        @param op1: source operand.
        '''
        size = dest.size
        arg0 = dest.read()
        arg1 = src.read()

        res = 0
        for pos in reversed(range(0, size//2, 8)):
            elem0 = ZEXTEND( ( arg0 >> pos )& ((1 << size//2)-1), size)
            elem1 = ZEXTEND( ( arg1 >> pos )& ((1 << size//2)-1), size)
            res = res << (size//2)
            res |= elem1
            res = res << (size//2)
            res |= elem0
        dest.write(res)

    @instruction
    def PSHUFD(cpu, op0, op1, op3):
        '''
        Packed shuffle doublewords.
        
        Copies doublewords from source operand (second operand) and inserts them in the destination operand 
        (first operand) at locations selected with the order operand (third operand). 
        
        @param cpu: current CPU. 
        @param op0: destination operand.
        @param op1: source operand.
        @param op3: order operand.
         '''
        size = op0.size
        arg0 = op0.read()
        arg1 = op1.read()
        arg3 = ZEXTEND(op3.read(),size)
        arg0 = arg0&0xffffffffffffffffffffffffffffffff00000000000000000000000000000000
        arg0 |= ((arg1 >> ((arg3>>0)&3 * 32))&0xffffffff)
        arg0 |= ((arg1 >> ((arg3>>2)&3 * 32))&0xffffffff)<<32
        arg0 |= ((arg1 >> ((arg3>>4)&3 * 32))&0xffffffff)<<64
        arg0 |= ((arg1 >> ((arg3>>6)&3 * 32))&0xffffffff)<<96
        op0.write(arg0)

    @instruction
    def MOVDQU(cpu, op0, op1):
        ''' 
        Moves unaligned double quadword.
        
        Moves a double quadword from the source operand (second operand) to the destination operand 
        (first operand)::

            OP0  =  OP1;
    
        @param cpu: current CPU.
        @param op0: destination operand.
        @param op1: source operand.
        '''
        
        op0.write(op1.read())

    @instruction
    def MOVDQA(cpu, op0, op1):
        ''' 
        Moves aligned double quadword.
        
        Moves a double quadword from the source operand (second operand) to the destination operand 
        (first operand)::
            OP0  =  OP1;
        
        @param cpu: current CPU.
        @param op0: destination operand.
        @param op1: source operand.
        @todo: check alingment.
        '''
        op0.write(op1.read())

    @instruction
    def PCMPEQB(cpu, op0, op1):
        '''
        Packed compare for equal.
        
        Performs a SIMD compare for equality of the packed bytes, words, or doublewords in the 
        destination operand (first operand) and the source operand (second operand). If a pair of 
        data elements are equal, the corresponding data element in the destination operand is set 
        to all 1s; otherwise, it is set to all 0s. The source operand can be an MMX(TM) technology 
        register or a 64-bit memory location, or it can be an XMM register or a 128-bit memory location. 
        The destination operand can be an MMX or an XMM register.
        The PCMPEQB instruction compares the bytes in the destination operand to the corresponding bytes 
        in the source operand.
 
        @param cpu: current CPU.
        @param op0: destination operand.
        @param op1: source operand.   
        '''
        arg0 = op0.read()
        arg1 = op1.read()

        res = 0
        for i in range(0,op0.size,8):
            res = ITE(op0.size, EXTRACT((arg0>>i),0,8) == EXTRACT((arg1>>i),0,8), res | (0xff << i), res)
        op0.write(res)

    @instruction
    def PMOVMSKB(cpu, op0, op1):
        '''
        Moves byte mask to general-purpose register.
        
        Creates an 8-bit mask made up of the most significant bit of each byte of the source operand 
        (second operand) and stores the result in the low byte or word of the destination operand 
        (first operand). The source operand is an MMX(TM) technology or an XXM register; the destination 
        operand is a general-purpose register.
        
        @param cpu: current CPU.
        @param op0: destination operand.
        @param op1: source operand.
        '''
        arg0 = op0.read()
        arg1 = op1.read()

        res = 0
        for i in reversed(range(7,op1.size,8)):
            res = (res<<1) | ((arg1>>i)&1)
        op0.write(EXTRACT(res,0,op0.size))

    @instruction
    def PSRLDQ(cpu, dest, src):
        '''
        Packed shift right logical double quadword.
        
        Shifts the destination operand (first operand) to the right by the number 
        of bytes specified in the count operand (second operand). The empty high-order 
        bytes are cleared (set to all 0s). If the value specified by the count 
        operand is greater than 15, the destination operand is set to all 0s. 
        The destination operand is an XMM register. The count operand is an 8-bit 
        immediate::

            TEMP  =  SRC;
            if (TEMP > 15) TEMP  =  16;
            DEST  =  DEST >> (temp * 8);

        @param cpu: current CPU.
        @param dest: destination operand.
        @param src: count operand.
        '''
        temp = src.read()
        temp = ITE(src.size, temp > 15, 16, temp)
        dest.write(dest.read()>>(temp*8))

    @instruction
    def NOP(cpu, arg0=None):
        '''
        No Operation.
        
        Performs no operation. This instruction is a one-byte instruction that  takes up space in the 
        instruction stream but does not affect the machine.
        The NOP instruction is an alias mnemonic for the XCHG (E)AX, (E)AX instruction.
        
        @param cpu: current CPU. 
        @param arg0: this argument is ignored. 
        '''
        pass

    @instruction
    def NOPL(cpu, arg0=None):
        '''
        No Operation.
        
        Performs no operation. This instruction is a one-byte instruction that  takes up space in the 
        instruction stream but does not affect the machine.
        The NOP instruction is an alias mnemonic for the XCHG (E)AX, (E)AX instruction.
        
        @param cpu: current CPU. 
        @param arg0: this argument is ignored. 
        '''
        pass

    @instruction
    def NOPW(cpu, arg0=None):
        '''
        No Operation.
        
        Performs no operation. This instruction is a one-byte instruction that  takes up space in the 
        instruction stream but does not affect the machine.
        The NOP instruction is an alias mnemonic for the XCHG (E)AX, (E)AX instruction.
        
        @param cpu: current CPU. 
        @param arg0: this argument is ignored. 
        '''
        pass


    @instruction
    def MOVD(cpu, op0, op1):
        if op1.size < op0.size:
            op0.write(ZEXTEND(op1.read(), op0.size))
        else:
            op0.write(EXTRACT(op1.read(), 0, op0.size))

    @instruction
    def MOVZX(cpu, op0, op1):
        '''
        Moves with zero-extend.
        
        Copies the contents of the source operand (register or memory location) to the destination 
        operand (register) and zero extends the value to 16 or 32 bits. The size of the converted value 
        depends on the operand-size attribute::

                OP0  =  ZeroExtend(OP1);
        
        @param cpu: current CPU.
        @param op0: destination operand.
        @param op1: source operand.
        '''
        op0.write(ZEXTEND(op1.read(), op0.size))

    @instruction
    def MOVSX(cpu, op0, op1):
        '''
        Moves with sign-extension.
        
        Copies the contents of the source operand (register or memory location) to the destination 
        operand (register) and sign extends the value to 16:: 

                OP0  =  SignExtend(OP1);
    
        @param cpu: current CPU.
        @param op0: destination operand.
        @param op1: source operand. 
        '''
        op0.write(SEXTEND(op1.read(), op1.size, op0.size))

    @instruction
    def MOVSXD(cpu, op0, op1):
        '''Move DWORD with sign extension to QWORD.'''
        op0.write(SEXTEND(op1.read(), op1.size, op0.size))

    @instruction
    def CLD(cpu):
        ''' 
        Clears direction flag.
        Clears the DF flag in the EFLAGS register. When the DF flag is set to 0, string operations 
        increment the index registers (ESI and/or EDI)::

            DF  =  0;
        
        @param cpu: current CPU.
        '''
        cpu.DF = False

    @instruction
    def STD(cpu):
        ''' 
        Sets direction flag.
        
        Sets the DF flag in the EFLAGS register. When the DF flag is set to 1, string operations decrement 
        the index registers (ESI and/or EDI)::

            DF  =  1;
        
        @param cpu: current CPU. 
        '''
        cpu.DF = True

    @instruction
    def CQO(cpu):
        ''' 
        RDX:RAX = sign-extend of RAX.
        '''
        res = SEXTEND(cpu.RAX,64,128)
        cpu.RDX = (res >> 64) & 0xffffffffffffffff

    @instruction
    def CDQE(cpu):
        ''' 
        RAX = sign-extend of EAX.
        '''
        cpu.RAX = SEXTEND(cpu.EAX,32,64)

    @instruction
    def CDQ(cpu):
        '''
        EDX:EAX = sign-extend of EAX
        '''
        cpu.EDX = EXTRACT(SEXTEND(cpu.EAX, 32, 64), 32, 32)


    @instruction
    def CWDE(cpu):
        ''' 
        Converts word to doubleword.
        
        ::
            EAX = sign-extend of AX.
            
        @param cpu: current CPU. 
        '''
        cpu.EAX = SEXTEND(cpu.EAX,16,32)

    @instruction
    def CBW(cpu):
        ''' 
        Converts byte to word.
        
        Double the size of the source operand by means of sign extension:: 
        
                AX = sign-extend of AL.
        
        @param cpu: current CPU. 
        '''
        cpu.AX = SEXTEND(cpu.AL,8,16)

    @instruction
    def RDTSC(cpu):
        ''' 
        Reads time-stamp counter.
        
        Loads the current value of the processor's time-stamp counter into the EDX:EAX registers. 
        The time-stamp counter is contained in a 64-bit MSR. The high-order 32 bits of the MSR are 
        loaded into the EDX register, and the low-order 32 bits are loaded into the EAX register. 
        The processor increments the time-stamp counter MSR every clock cycle and resets it to 0 whenever 
        the processor is reset.
        
        @param cpu: current CPU. 
        '''
        val = cpu.icount
        cpu.RAX = val&0xffffffff
        cpu.RDX = (val>>32)&0xffffffff


    #MMX
    @instruction
    def VMOVD(cpu, op0, op1):
        arg1 = op1.read()
        op0.write(arg1)
    #MMX
    @instruction
    def VMOVUPS(cpu, op0, op1):
        arg1 = op1.read()
        op0.write(arg1)
    @instruction
    def VMOVAPS(cpu, op0, op1):
        arg1 = op1.read()
        op0.write(arg1)


    @instruction
    def VMOVQ(cpu, op0, op1):
        arg1 = op1.read()
        if op0.size > op1.size:
            op0.write(ZEXTEND(arg1, op0.size))
        else:
            op0.write(EXTRACT(arg1, 0, op0.size))

    #FPU:
    @instruction
    def FNSTCW(cpu, dest):
        ''' 
        Stores x87 FPU Control Word.
        
        Stores the current value of the FPU control word at the specified destination in memory. 
        The FSTCW instruction checks for and handles pending unmasked floating-point exceptions 
        before storing the control word; the FNSTCW instruction does not::

            DEST  =  FPUControlWord;
        
        @param cpu: current CPU.
        @param dest: destination operand.
        '''
        cpu.store(dest.address(), 0x037f, 16)

    @instruction
    def FLDCW(cpu, op0):
        '''
        Not implemented.
        
        Performs no operation.
        '''
        pass

    @instruction
    def SYSCALL(cpu):
        ''' 
        Calls to interrupt procedure.
        
        The INT n instruction generates a call to the interrupt or exception handler specified 
        with the destination operand. The INT n instruction is the  general mnemonic for executing
        a software-generated call to an interrupt handler. The INTO instruction is a special 
        mnemonic for calling overflow exception (#OF), interrupt vector number 4. The overflow
        interrupt checks the OF flag in the EFLAGS register and calls the overflow interrupt handler 
        if the OF flag is set to 1.
        
        @param cpu: current CPU. 
        '''
        sys = cpu.RAX
        sys = SIMP(sys)
        cpu.syscall.append(sys)
        cpu.RAX = -1
        #raise Syscall()

    @instruction
    def MOVLPD(cpu, dest, src):
        ''' 
        Moves low packed double-precision floating-point value.
        
        Moves a double-precision floating-point value from the source operand (second operand) and the 
        destination operand (first operand). The source and destination operands can be an XMM register 
        or a 64-bit memory location. This instruction allows double-precision floating-point values to be moved 
        to and from the low quadword of an XMM register and memory. It cannot be used for register to register 
        or memory to memory moves. When the destination operand is an XMM register, the high quadword of the 
        register remains unchanged.
        
        @param cpu: current CPU.
        @param dest: destination operand.
        @param src: source operand.
        '''
        if dest.size > src.size: 
            high = dest.read()                    &     (((1<< (dest.size//2))-1) << (dest.size//2))
            low  = ZEXTEND(src.read(), dest.size) &     ((1<< (dest.size//2))-1)
            dest.write(high|low)
        else:
            dest.write(EXTRACT(0,dest.size,src.read()))


    @instruction
    def MOVHPD(cpu, dest, src):
        '''
        Moves high packed double-precision floating-point value.
        
        Moves a double-precision floating-point value from the source operand (second operand) and the 
        destination operand (first operand). The source and destination operands can be an XMM register 
        or a 64-bit memory location. This instruction allows double-precision floating-point values to be moved 
        to and from the high quadword of an XMM register and memory. It cannot be used for register to 
        register or memory to memory moves. When the destination operand is an XMM register, the low quadword 
        of the register remains unchanged.
        
        @param cpu: current CPU.
        @param dest: destination operand.
        @param src: source operand.
        '''
        if src.size == 128 and dest.size == 64:
            dest.write(EXTRACT(src.read(), 64, 64))
        elif src.size == 64 and dest.size == 128:
            value = dest.read() & ((1<<64)-1) #low part
            dest.write(CONCAT(64, value , EXTRACT( src.read(), 0, 64)))
        else:
            raise NotImplemented()

    @instruction
    def PSUBB(cpu, dest, src):
        ''' 
        Packed subtract.
        
        Performs a SIMD subtract of the packed integers of the source operand (second operand) from the packed 
        integers of the destpination operand (first operand), and stores the packed integer results in the 
        destination operand. The source operand can be an MMX(TM) technology register or a 64-bit memory location, 
        or it can be an XMM register or a 128-bit memory location. The destination operand can be an MMX or an XMM 
        register.
        The PSUBB instruction subtracts packed byte integers. When an individual result is too large or too small 
        to be represented in a byte, the result is wrapped around and the low 8 bits are written to the 
        destination element.
        
        @param cpu: current CPU.
        @param dest: destination operand.
        @param src: source operand.
        '''
        result = []
        value_a = dest.read()
        value_b = src.read()
        for i in reversed(range(0,dest.size,8)):
            a = EXTRACT(value_a, i, 8)
            b = EXTRACT(value_b, i, 8)
            result.append((a-b)&0xff)
        dest.write(CONCAT(8, *result))

    @instruction
    def POR(cpu, dest, src):
        '''
        Performs a bitwise logical OR operation on the source operand (second operand) and the destination operand 
        (first operand) and stores the result in the destination operand. The source operand can be an MMX technology 
        register or a 64-bit memory location or it can be an XMM register or a 128-bit memory location. The destination 
        operand can be an MMX technology register or an XMM register. Each bit of the result is set to 1 if either 
        or both of the corresponding bits of the first and second operands are 1; otherwise, it is set to 0.
        '''
        res = dest.write(dest.read()|src.read())
    @instruction
    def XORPS(cpu, dest, src):
        '''
        Performs a bitwise logical OR operation on the source operand (second operand) and the destination operand 
        (first operand) and stores the result in the destination operand. The source operand can be an MMX technology 
        register or a 64-bit memory location or it can be an XMM register or a 128-bit memory location. The destination 
        operand can be an MMX technology register or an XMM register. Each bit of the result is set to 1 if either 
        or both of the corresponding bits of the first and second operands are 1; otherwise, it is set to 0.
        '''
        res = dest.write(dest.read()^src.read())

 
    @instruction
    def PTEST(cpu, dest, src):
        ''' PTEST
         PTEST set the ZF flag if all bits in the result are 0 of the bitwise AND
         of the first source operand (first operand) and the second source operand 
         (second operand). Also this sets the CF flag if all bits in the result 
         are 0 of the bitwise AND of the second source operand (second operand) 
         and the logical NOT of the destination operand.
        '''
        cpu.OF = False
        cpu.AF = False
        cpu.PF = False
        cpu.SF = False
        cpu.ZF = dest.read() & src.read() == 0
        cpu.CF = dest.read() & ~src.read() == 0

    @instruction
    def MOVAPS(cpu, dest, src):
        ''' 
        Moves aligned packed single-precision floating-point values.
        
        Moves a double quadword containing four packed single-precision floating-point numbers from the 
        source operand (second operand) to the destination operand (first operand). This instruction can be 
        used to load an XMM register from a 128-bit memory location, to store the contents of an XMM register 
        into a 128-bit memory location, or move data between two XMM registers. 
        When the source or destination operand is a memory operand, the operand must be aligned on a 16-byte 
        boundary or a general-protection exception (#GP) will be generated::

                DEST  =  SRC;

        @param cpu: current CPU.
        @param dest: destination operand.
        @param src: source operand.
        '''
        dest.write(src.read())

    @instruction
    def MOVQ(cpu, dest, src):
        ''' 
        Move quadword.
        
        Copies a quadword from the source operand (second operand) to the destination operand (first operand). 
        The source and destination operands can be MMX(TM) technology registers, XMM registers, or 64-bit memory 
        locations. This instruction can be used to move a between two MMX registers or between an MMX register 
        and a 64-bit memory location, or to move data between two XMM registers or between an XMM register and 
        a 64-bit memory location. The instruction cannot be used to transfer data between memory locations.
        When the source operand is an XMM register, the low quadword is moved; when the destination operand is 
        an XMM register, the quadword is stored to the low quadword of the register, and the high quadword is 
        cleared to all 0s::

            MOVQ instruction when operating on MMX registers and memory locations:
            
            DEST  =  SRC;
            
            MOVQ instruction when source and destination operands are XMM registers:
            
            DEST[63-0]  =  SRC[63-0];
            
            MOVQ instruction when source operand is XMM register and destination operand is memory location:
            
            DEST  =  SRC[63-0];
            
            MOVQ instruction when source operand is memory location and destination operand is XMM register:
            
            DEST[63-0]  =  SRC;
            DEST[127-64]  =  0000000000000000H;
        
        @param cpu: current CPU.
        @param dest: destination operand.
        @param src: source operand.
        '''
        if dest.size == src.size:
            dest.write(src.read())
        elif dest.size > src.size:
            dest.write(ZEXTEND(src.read(), dest.size))
        elif dest.size < src.size:
            dest.write(EXTRACT(src.read(),0, dest.size))


    def VMOVSD(cpu, dest, src):
        cpu.MOVSD(dest, src)

    @instruction
    def MOVSD(cpu, dest, src):
        ''' 
        Move Scalar Double-Precision Floating-Point Value
        
        Moves a scalar double-precision floating-point value from the source 
        operand (second operand) to the destination operand (first operand). 
        The source and destination operands can be XMM registers or 64-bit memory
        locations. This instruction can be used to move a double-precision 
        floating-point value to and from the low quadword of an XMM register and
        a 64-bit memory location, or to move a double-precision floating-point
        value between the low quadwords of two XMM registers. The instruction 
        cannot be used to transfer data between memory locations.
        When the source and destination operands are XMM registers, the high 
        quadword of the destination operand remains unchanged. When the source 
        operand is a memory location and destination operand is an XMM registers,
        the high quadword of the destination operand is cleared to all 0s.

        @param cpu: current CPU.
        @param dest: destination operand.
        @param src: source operand.
        '''
        result = dest.read()
        if dest.size > src.size:
            result &= (~((1<<src.size)-1) ) & ((1 << dest.size )-1)
            result |= ZEXTEND(src.read(), dest.size)
            result = EXTRACT(result, 0, dest.size)
            dest.write(result)
        elif dest.size < src.size:
            dest.write( EXTRACT(src.read(), 0, dest.size) )
        else:
            dest.write(src.read())
    @instruction
    def VMOVDQA(cpu, dest, src):
        '''
        Move Aligned Double Quadword

        Moves 128 bits of packed integer values from the source operand (second 
        operand) to the destination operand (first operand). This instruction 
        can be used to load an XMM register from a 128-bit memory location, to 
        store the contents of an XMM register into a 128-bit memory location, or
        to move data between two XMM registers. 

        When the source or destination operand is a memory operand, the operand 
        must be aligned on a 16-byte boundaryor a general-protection exception 
        (#GP) will be generated. To move integer data to and from unaligned 
        memorylocations, use the VMOVDQU instruction.'''
        #TODO raise exception when unaligned!
        dest.write(src.read())

    @instruction
    def VMOVDQU(cpu, dest, src):
        '''
        Move Unaligned Double Quadword

        Moves 128 bits of packed integer values from the source operand (second operand) to the destination operand
(first operand). This instruction can be used to load an XMM register from a 128-bit memory location, to store the
contents of an XMM register into a 128-bit memory location, or to move data between two XMM registers. When
the source or destination operand is a memory operand, the operand may be unaligned on a 16-byte boundary
without causing a general-protection exception (#GP) to be generated.
    
VMOVDQU (VEX.128 encoded version)
DEST[127:0] <- SRC[127:0]
DEST[VLMAX-1:128] <- 0
VMOVDQU (VEX.256 encoded version)
DEST[255:0] <- SRC[255:0]
'''
        dest.write(src.read())

    @instruction
    def VEXTRACTF128(cpu, dest, src, offset):
        '''Extract Packed Floating-Point Values

        Extracts 128-bits of packed floating-point values from the source 
        operand (second operand) at an 128-bit offset from imm8[0] into the 
        destination operand (first operand). The destination may be either an 
        XMM register or an 128-bit memory location. 
        '''
        offset=offset.read()
        dest.write(EXTRACT(src.read(), offset*128 , (offset+1)*128))

    @instruction
    def PREFETCHT0(cpu, arg):
        '''
        Not implemented.
        
        Performs no operation.
        '''
        pass
    @instruction
    def PREFETCHT1(cpu, arg):
        '''
        Not implemented.
        
        Performs no operation.
        '''
        pass
    @instruction
    def PREFETCHT2(cpu, arg):
        '''
        Not implemented.
        
        Performs no operation.
        '''        
        pass
    @instruction
    def PREFETCHTNTA(cpu, arg):
        '''
        Not implemented.
        
        Performs no operation.
        '''        
        pass
    @instruction
    def POPCNT(cpu, arg1, arg2):
        '''
        Not implemented.
        
        Performs no operation.
        '''
        pass


    @instruction
    def CVTSI2SD(cpu, dest, src):
        #raise NotImplemented()
        pass
        
    @instruction
    def PINSRW(cpu, dest, src, count):
        if dest.size == 64:
            #PINSRW instruction with 64-bit source operand:
            sel = count.read() & 3
            mask = [0x000000000000FFFF, 0x00000000FFFF0000, 0x0000FFFF00000000, 0xFFFF000000000000 ][sel]
        else:
            #PINSRW instruction with 128-bit source operand
            assert dest.size == 128
            sel = count.read() & 7
            mask = [0x0000000000000000000000000000FFFF,0x000000000000000000000000FFFF0000,0x00000000000000000000FFFF00000000,0x0000000000000000FFFF000000000000,0x000000000000FFFF0000000000000000,0x00000000FFFF00000000000000000000,0x0000FFFF000000000000000000000000,0xFFFF0000000000000000000000000000][sel]
        dest.write( (dest.read() & ~mask) |  ((ZEXTEND(src.read(),dest.size) << (sel * 16)) & mask) )

    @instruction
    def PEXTRW(cpu, dest, src, count):
        if src.size == 64:
            sel = EXTRACT(count.read(), 0, 2)
        else:
            sel = EXTRACT(count.read(), 0, 3)
        dest.write(ZEXTEND( ((src.read() >> (sel * 16)) & 0xffff), dest.size))

    @instruction
    def PALIGNR(cpu, dest, src, offset):
        '''ALIGNR concatenates the destination operand (the first operand) and the source
            operand (the second operand) into an intermediate composite, shifts the composite
            at byte granularity to the right by a constant immediate, and extracts the right-
            aligned result into the destination.'''
        dest.write( EXTRACT( CONCAT( dest.size, dest.read(), src.read()), offset.read(), dest.size ))
    @instruction
    def PSLLDQ(cpu, dest, src):
        ''' Packed Shift Left Logical Double Quadword
        Shifts the destination operand (first operand) to the left by the number 
         of bytes specified in the count operand (second operand). The empty low-order 
         bytes are cleared (set to all 0s). If the value specified by the count 
         operand is greater than 15, the destination operand is set to all 0s. 
         The destination operand is an XMM register. The count operand is an 8-bit 
         immediate.

            TEMP  =  COUNT;
            if (TEMP > 15) TEMP  =  16;
            DEST  =  DEST << (TEMP * 8);
        '''
        dest.write(dest.read() << (ZEXTEND(src.read(), dest.size)))
    @instruction
    def PCMPISTRI(cpu, op1, op2, ctrl):
        ""
        ''' 
        Packed compare implicit length strings.
        
        The instruction compares data from two strings based on the encoded value in the Imm8 Control Byte 
        and generates an index stored to ECX.
            
        Each input byte/word is augmented with a valid/invalid tag. A byte/word is considered valid only if 
        it has a lower index than the least significant null byte/word. (The least significant null byte/word 
        is also considered invalid.)
            
        - Flags:
            - CFlag - Reset if IntRes2 is equal to zero, set otherwise
            - ZFlag - Set if any byte/word of xmm2/mem128 is null, reset otherwise
            - SFlag - Set if any byte/word of xmm1 is null, reset otherwise
            - OFlag - IntRes2[0]
            - AFlag - Reset
            - PFlag - Reset

        - Imm8 Description
            -------0b 128-bit sources treated as 16 packed bytes.
            -------1b 128-bit sources treated as 8 packed words.
            ------0-b Packed bytes/words are unsigned.
            ------1-b Packed bytes/words are signed.
            ----00--b Mode is equal any.
            ----01--b Mode is ranges.
            ----10--b Mode is equal each.
            ----11--b Mode is equal ordered.
            ---0----b IntRes1 is unmodified.
            ---1----b IntRes1 is negated (1's complement).
            --0-----b Negation of IntRes1 is for all 16 (8) bits.
            --1-----b Negation of IntRes1 is masked by reg/mem validity.
            -0------b Index of the least significant, set, bit is used (regardless of corresponding input element validity).
                      IntRes2 is returned in least significant bits of XMM0.
            -1------b Index of the most significant, set, bit is used (regardless of corresponding input element validity).
                      Each bit of IntRes2 is expanded to byte/word.
            0-------b This bit currently has no defined effect, should be 0.
            1-------b This bit currently has no defined effect, should be 0.

        '''
        ctrl = ctrl.read()

        pack = None
        if ctrl & 1 != 0:
            pack = 16
        else:
            pack = 8

        signed = None
        if ctrl>>1 & 1 != 0:
            signed = False
        else:
            signed = True

        mode = None
        if ctrl>>2 & 3 == 0:
            mode = 'equal any'
        elif ctrl>>2 & 3 == 1:
            mode = 'ranges'
        elif ctrl>>2 & 3 == 2:
            mode = 'equal each'
        elif ctrl>>2 & 3 == 3:
            mode = 'equal ordered'

        polarity = None
        if ctrl>>4 & 1 == 0:
            polarity = 'unmodified'
        else:
            polarity = '1complement'

        masked = None
        if ctrl>>5 & 1 == 0:
            masked = False
        else:
            masked = True

        output = None
        if ctrl>>6 & 1 == 0:
            output = 'lsb'
        else:
            output = 'msb'


        op1_value = op1.read()
        op2_value = op2.read()
        if type(op1_value) is not int or type(op2_value) is not int: #ignore symbolic example here
            cpu.impossible = 1
            return

        op1l = [ EXTRACT(op1_value, i, pack) for i in range(op1.size//pack)]
        op2l = [ EXTRACT(op2_value, i, pack) for i in range(op2.size//pack)]

        ret = pack
        for i in range(len(op1l)):
            if op1l[i] != op2l[i] or op1l[i] == 0 or op1l[i] == 0:
                ret = i
                break

        sys.stdin.readline()
        cpu.ECX = ret
        return 


        valid1l = []
        for i in range(len(op1l)):
            if i > 0:
                validl.append(AND(valid1l[i-1], op1l[i] != 0))
            else:
                validl.append(op1l[i] != 0)
        valid2l = []
        for i in range(op2l):
            if i > 0:
                validl.append(AND(valid2l[i-1], op2l[i] != 0))
            else:
                validl.append(op2l[i] != 0)

        assert mode == 'equal each'
        IntRes1 = 0;
        for i in range(len(op1l)):
            IntRes1 |= OR(AND(valid1l == False, valid2l == False), AND(AND(valid1l, valid2l), op1l[i] == op2l[i] )) << i

        IntRes2 = IntRes1
        assert polarity == 'unmodified'
        #masked da igual


        assert output == 'lsb'
        ret = pack
        for i in range(len(op1l)):
            if op1l[i] != op2l[i] or op1l[i] == 0 or op1l[i] == 0:
                ret = i
                break

        sys.stdin.readline()
        cpu.ECX = ret
