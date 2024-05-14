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
from capstone.arm64 import *
#THIS IS NOT CORRECT
#Maybe the version I am using is different
CapRegisters = ["(INVALID)","X29","X30","NZCV","SP","WSP","WZR","XZR","B0","B1","B2","B3","B4","B5","B6","B7","B8","B9","B10","B11","B12","B13","B14","B15","B16","B17","B18","B19","B20","B21","B22","B23","B24","B25","B26","B27","B28","B29","B30","B31","D0","D1","D2","D3","D4","D5","D6","D7","D8","D9","D10","D11","D12","D13","D14","D15","D16","D17","D18","D19","D20","D21","D22","D23","D24","D25","D26","D27","D28","D29","D30","D31","H0","H1","H2","H3","H4","H5","H6","H7","H8","H9","H10","H11","H12","H13","H14","H15","H16","H17","H18","H19","H20","H21","H22","H23","H24","H25","H26","H27","H28","H29","H30","H31","Q0","Q1","Q2","Q3","Q4","Q5","Q6","Q7","Q8","Q9","Q10","Q11","Q12","Q13","Q14","Q15","Q16","Q17","Q18","Q19","Q20","Q21","Q22","Q23","Q24","Q25","Q26","Q27","Q28","Q29","Q30","Q31","S0","S1","S2","S3","S4","S5","S6","S7","S8","S9","S10","S11","S12","S13","S14","S15","S16","S17","S18","S19","S20","S21","S22","S23","S24","S25","S26","S27","S28","S29","S30","S31","W0","W1","W2","W3","W4","W5","W6","W7","W8","W9","W10","W11","W12","W13","W14","W15","W16","W17","W18","W19","W20","W21","W22","W23","W24","W25","W26","W27","W28","W29","W30","X0","X1","X2","X3","X4","X5","X6","X7","X8","X9","X10","X11","X12","X13","X14","X15","X16","X17","X18","X19","X20","X21","X22","X23","X24","X25","X26","X27","X28","V0","V1","V2","V3","V4","V5","V6","V7","V8","V9","V10","V11","V12","V13","V14","V15","V16","V17","V18","V19","V20","V21","V22","V23","V24","V25","V26","V27","V28","V29","V30","V31","ENDING"]

lookup = {"JE":"JZ","CMOVE":"CMOVZ","CMOVNE":"CMOVNZ","MOVUPS":"MOV","MOVABS":"MOV", "REP MOVSB":"MOVS", "REP MOVSW":"MOVS", "REP MOVSD":"MOVS","SETNE":"SETNZ","SETE":"SETZ","STOSD":"STOS","STOSB":"STOS","STOSW":"STOS","STOSQ":"STOS","SCASD":"SCAS","SCASB":"SCAS","SCASW":"SCAS","SCASQ":"SCAS"}

from smtlib import ITEBV as ITE, ZEXTEND, SEXTEND, ord, chr, OR, AND, CONCAT, UDIV, XOR, UREM, ULT, UGT, ULE, EXTRACT, TRUE, FALSE, SIMP, BitVecRef, BoolRef, BitVecNumRef, BitVecVal, BitVec, BoolVal, Bool

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
        cpu.IP += cpu.instruction.size
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

                cpu.IP = ITE(cpu.AddressSize, cpu.IF, cpu.IP, cpu.IP + cpu.instruction.size)

            #Advance!
            else:
                cpu.IP = cpu.IP + cpu.instruction.size

        else:
            cpu.IP += cpu.instruction.size
            old_method(cpu, *args,**kw_args)
    return new_method

###############################################################################
class Register128(object):
    def __init__(self):
        self._Q = 0
        self._cache = {} 
    
    def setV(self, val):
        self._Q = val
        self._cache = {}
    def getV(self):
        return self._Q

    def setD(self, val):
        self._Q = ZEXTEND(val, 128)
        self._cache = { 'D': val}
        return self._Q
    def getD(self):
        return self._cache.setdefault('D', EXTRACT(self._Q,0,64) )

    def setS(self, val):
        self._Q = ZEXTEND(val,128) 
        self._cache = { 'S': val }
        return val
    def getS(self):
        return self._cache.setdefault('S', EXTRACT(self._Q,0,32) )

    def setH(self, val):
        self._Q = ZEXTEND(val,128) 
        self._cache = { 'H': val }
        return val
    def getH(self):
        return self._cache.setdefault('H', EXTRACT(self._Q,0,16) )

    def setB(self, val):
        self._Q = ZEXTEND(val,128) 
        self._cache = { 'B': val }
        return val
    def getB(self):
        return self._cache.setdefault('B', EXTRACT(self._Q,0,8) )

class Register64(object):
    ''' 
    64 bit register. 
    '''
    def __init__(self):
        self._X = 0
        self._cache = {} 

    def setX(self, val):

        i = isinstance(val,BitVecRef)
        if not i or (i and val.size() > 64) :
            val = EXTRACT(val, 0, 64)
        if i:
            if val.size() < 64:
                val = ZEXTEND(val, 64)
            val = SIMP(val)

        self._X = val
        self._cache = {}
        return val
    def getX(self):
        return self._X

    def setW(self,val):

        i = isinstance(val,BitVecRef)
        if not i or (i and val.size() > 32) :
            val = EXTRACT(val, 0, 32)
        if i:
            if val.size() < 32:
                val = ZEXTEND(val, 32)
            val = SIMP(val)
        self._X = ZEXTEND(val,64)
        self._cache = { 'W': EXTRACT(val, 0,32) }
        return val

    def getW(self):
        return self._cache.setdefault('W', EXTRACT(self._X, 0,32))

    def setHH(self, val):
        i = isinstance(val,BitVecRef)
        if not i or (i and val.size() > 16) :
            val = EXTRACT(val, 0, 16)
        if i:
            if val.size() < 16:
                val = ZEXTEND(val, 16)
            val = SIMP(val)
        val = EXTRACT(val, 0,16)
        self._X = ZEXTEND(val,64)
        self._cache = { 'H': val}
        return val
    def getHH(self):
        return self._cache.setdefault('H', EXTRACT(self._X, 0,16))

    def setBB(self, val):
        i = isinstance(val,BitVecRef)
        if not i or (i and val.size() > 8) :
            val = EXTRACT(val, 0, 8)
        if i:
            if val.size() < 8:
                val = ZEXTEND(val, 8)
            val = SIMP(val)
        val = EXTRACT(val, 0,8)
        #self._X = self._X & 0xFFFFFFFFFFFFFF00 | ZEXTEND(val,64)
        self._X = ZEXTEND(val,64)
        self._cache = {'B': val}
        return val
    def getBB(self):
        return self._cache.setdefault('B', EXTRACT(self._X, 0,8))

class ZRegister64(object):
    ''' 
    64 bit Zero register. 
    '''
    def __init__(self):
        self._X = 0

    def setX(self, val):
        return 0

    def getX(self):
        return 0

    def setW(self, val):
        return 0

    def getW(self):
        return 0


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
    def __init__(self, memory, machine, truejump, noread, nowrite, noseg, cycles, loop_max, no_constraints):
        '''
        Builds a CPU model.
        @param memory: memory object for this CPU.
        @param machine:  machine code name. Supported machines: C{'i386'} and C{'amd64'}.
        '''
        assert machine in ['amd64', 'aarch64']
        self.mem            = memory #Shall have getchar and putchar methods.
        self.icount         = 0
        self.machine        = machine
        self.done           = 0
        self.bad_inst       = 0
        self.impossible     = 0
        self.const_counter  = 0
        self.true_jumps     = truejump
        self.noread         = noread
        self.nowrite        = nowrite
        self.noseg          = noseg
        self.cycles         = cycles
        self.loop_max       = loop_max
        self.nc             = no_constraints

        self.AddressSize    = 64 
        self.IP_name        = 'PC'
        self.STACK_name     = 'SP' 
        self.FRAME_name     = 'X29' 
        self.segments       = {}

        self.constraints = {}           #Overall Constraints to keep track of memory references
        self.jump_constraints  = ['Jump Constraints']     #Constraints to keep track of comparisons or flag altering instructions
        self.read_constraints  = ['Read Constraints']
        self.write_constraints = ['Write Constraints']
        self.seg_constraints   = ['Segment Constraints']
        self.condition_condition = ['Conditions']
        self.syscall           = ['Syscall']
        
        self.flag_constraints = ()      #Last constraint used, as we don't want all possible flag altering instructions
        self.size_lookup = {8:'Byte',16:'Word',32:'Dword',64:'Qword'}

        #caches
        self.instruction_cache  = {}
        # cache[where] => (value,size)
        self.mem_cache          = {}
        self.mem_cache_used     = {}

        self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.md.detail = True
        self.md.syntax = 0

        # Adding convenience methods to Cpu class for accessing registers
        for reg in range(31):
            setattr(self, f'_X{reg}', Register64())

        for reg in range(32):
            setattr(self, f'_V{reg}', Register128())

        setattr(self, '_XZR', ZRegister64())
        setattr(self, '_PC', Register64())
        setattr(self, '_SP', Register64())
        self.tpidr_el0 = 0

        for reg in ['N','Z','C','V']:
            setattr(self, reg, BoolVal(True))

        logger.info("Cpu Initialized.")

    PC   = prop('_PC', 'X')

    SP   = prop('_SP', 'X')
    W31   = prop('_SP', 'W')
    TPIDR_EL0 = prop("_TPIDR_EL0", 'X')

    XZR = prop('_XZR', 'X')
    WZR = prop('_XZR', 'W')
    
    #There is something nice about seeing the instructions laid out like this
    X0 = prop('_X0', 'X')
    W0 = prop('_X0', 'W')
    HH0 = prop('_X0', 'HH')
    BB0 = prop('_X0', 'BB')

    X1 = prop('_X1', 'X')
    W1 = prop('_X1', 'W')
    HH1 = prop('_X1', 'HH')
    BB1 = prop('_X1', 'BB')

    X2 = prop('_X2', 'X')
    W2 = prop('_X2', 'W')
    HH2 = prop('_X2', 'HH')
    BB2 = prop('_X2', 'BB')
    
    X3 = prop('_X3', 'X')
    W3 = prop('_X3', 'W')
    HH3 = prop('_X3', 'HH')
    BB3 = prop('_X3', 'BB')
    
    X4 = prop('_X4', 'X')
    W4 = prop('_X4', 'W')
    HH4 = prop('_X4', 'HH')
    BB4 = prop('_X4', 'BB')
    
    X5 = prop('_X5', 'X')
    W5 = prop('_X5', 'W')
    HH5 = prop('_X5', 'HH')
    BB5 = prop('_X5', 'BB')
    
    X6 = prop('_X6', 'X')
    W6 = prop('_X6', 'W')
    HH6 = prop('_X6', 'HH')
    BB6 = prop('_X6', 'BB')
    
    X7 = prop('_X7', 'X')
    W7 = prop('_X7', 'W')
    HH7 = prop('_X7', 'HH')
    BB7 = prop('_X7', 'BB')
    
    X8 = prop('_X8', 'X')
    W8 = prop('_X8', 'W')
    HH8 = prop('_X8', 'HH')
    BB8 = prop('_X8', 'BB')
    
    X9 = prop('_X9', 'X')
    W9 = prop('_X9', 'W')
    HH9 = prop('_X9', 'HH')
    BB9 = prop('_X9', 'BB')
    
    X10 = prop('_X10', 'X')
    W10 = prop('_X10', 'W')
    HH10 = prop('_X10', 'HH')
    BB10 = prop('_X10', 'BB')
    
    X11 = prop('_X11', 'X')
    W11 = prop('_X11', 'W')
    HH11 = prop('_X11', 'HH')
    BB11 = prop('_X11', 'BB')
    
    X12 = prop('_X12', 'X')
    W12 = prop('_X12', 'W')
    HH12 = prop('_X12', 'HH')
    BB12 = prop('_X12', 'BB')
    
    X13 = prop('_X13', 'X')
    W13 = prop('_X13', 'W')
    HH13 = prop('_X13', 'HH')
    BB13 = prop('_X13', 'BB')
    
    X14 = prop('_X14', 'X')
    W14 = prop('_X14', 'W')
    HH14 = prop('_X14', 'HH')
    BB14 = prop('_X14', 'BB')
    
    X15 = prop('_X15', 'X')
    W15 = prop('_X15', 'W')
    HH15 = prop('_X15', 'HH')
    BB15 = prop('_X15', 'BB')
    
    X16 = prop('_X16', 'X')
    W16 = prop('_X16', 'W')
    HH16 = prop('_X16', 'HH')
    BB16 = prop('_X16', 'BB')
    
    X17 = prop('_X17', 'X')
    W17 = prop('_X17', 'W')
    HH17 = prop('_X17', 'HH')
    BB17 = prop('_X17', 'BB')
    
    X18 = prop('_X18', 'X')
    W18 = prop('_X18', 'W')
    HH18 = prop('_X18', 'HH')
    BB18 = prop('_X18', 'BB')
    
    X19 = prop('_X19', 'X')
    W19 = prop('_X19', 'W')
    HH19 = prop('_X19', 'HH')
    BB19 = prop('_X19', 'BB')
    
    X20 = prop('_X20', 'X')
    W20 = prop('_X20', 'W')
    HH20 = prop('_X20', 'HH')
    BB20 = prop('_X20', 'BB')
    
    X21 = prop('_X21', 'X')
    W21 = prop('_X21', 'W')
    HH21 = prop('_X21', 'HH')
    BB21 = prop('_X21', 'BB')
    
    X22 = prop('_X22', 'X')
    W22 = prop('_X22', 'W')
    HH22 = prop('_X22', 'HH')
    BB22 = prop('_X22', 'BB')
    
    X23 = prop('_X23', 'X')
    W23 = prop('_X23', 'W')
    HH23 = prop('_X23', 'HH')
    BB23 = prop('_X23', 'BB')
    
    X24 = prop('_X24', 'X')
    W24 = prop('_X24', 'W')
    HH24 = prop('_X24', 'HH')
    BB24 = prop('_X24', 'BB')
    
    X25 = prop('_X25', 'X')
    W25 = prop('_X25', 'W')
    HH25 = prop('_X25', 'HH')
    BB25 = prop('_X25', 'BB')
    
    X26 = prop('_X26', 'X')
    W26 = prop('_X26', 'W')
    HH26 = prop('_X26', 'HH')
    BB26 = prop('_X26', 'BB')
    
    X27 = prop('_X27', 'X')
    W27 = prop('_X27', 'W')
    HH27 = prop('_X27', 'HH')
    BB27 = prop('_X27', 'BB')
    
    X28 = prop('_X28', 'X')
    W28 = prop('_X28', 'W')
    HH28 = prop('_X28', 'HH')
    BB28 = prop('_X28', 'BB')
    
    FP = prop('_X29', 'X')
    X29 = prop('_X29', 'X')
    W29 = prop('_X29', 'W')
    HH29 = prop('_X29', 'HH')
    BB29 = prop('_X29', 'BB')
    
    LR = prop('_X29', 'X')
    X30  = prop('_X30', 'X')
    W30  = prop('_X30', 'W')
    HH30  = prop('_X30', 'HH')
    BB30  = prop('_X30', 'BB')

    #Floating point registers
    V0 = prop('_V0', 'V')
    Q0 = prop('_V0', 'V')
    D0 = prop('_V0', 'D')
    S0 = prop('_V0', 'S')
    H0 = prop('_V0', 'H')
    V1 = prop('_V1', 'V')
    Q1 = prop('_V1', 'V')
    D1 = prop('_V1', 'D')
    S1 = prop('_V1', 'S')
    H1 = prop('_V1', 'H')
    V2 = prop('_V2', 'V')
    Q2 = prop('_V2', 'V')
    D2 = prop('_V2', 'D')
    S2 = prop('_V2', 'S')
    H2 = prop('_V2', 'H')
    V3 = prop('_V3', 'V')
    Q3 = prop('_V3', 'V')
    D3 = prop('_V3', 'D')
    S3 = prop('_V3', 'S')
    H3 = prop('_V3', 'H')
    V4 = prop('_V4', 'V')
    Q4 = prop('_V4', 'V')
    D4 = prop('_V4', 'D')
    S4 = prop('_V4', 'S')
    H4 = prop('_V4', 'H')
    V5 = prop('_V5', 'V')
    Q5 = prop('_V5', 'V')
    D5 = prop('_V5', 'D')
    S5 = prop('_V5', 'S')
    H5 = prop('_V5', 'H')
    V6 = prop('_V6', 'V')
    Q6 = prop('_V6', 'V')
    D6 = prop('_V6', 'D')
    S6 = prop('_V6', 'S')
    H6 = prop('_V6', 'H')
    V7 = prop('_V7', 'V')
    Q7 = prop('_V7', 'V')
    D7 = prop('_V7', 'D')
    S7 = prop('_V7', 'S')
    H7 = prop('_V7', 'H')
    V8 = prop('_V8', 'V')
    Q8 = prop('_V8', 'V')
    D8 = prop('_V8', 'D')
    S8 = prop('_V8', 'S')
    H8 = prop('_V8', 'H')
    V9 = prop('_V9', 'V')
    Q9 = prop('_V9', 'V')
    D9 = prop('_V9', 'D')
    S9 = prop('_V9', 'S')
    H9 = prop('_V9', 'H')
    V10 = prop('_V10', 'V')
    Q10 = prop('_V10', 'V')
    D10 = prop('_V10', 'D')
    S10 = prop('_V10', 'S')
    H10 = prop('_V10', 'H')
    V11 = prop('_V11', 'V')
    Q11 = prop('_V11', 'V')
    D11 = prop('_V11', 'D')
    S11 = prop('_V11', 'S')
    H11 = prop('_V11', 'H')
    V12 = prop('_V12', 'V')
    Q12 = prop('_V12', 'V')
    D12 = prop('_V12', 'D')
    S12 = prop('_V12', 'S')
    H12 = prop('_V12', 'H')
    V13 = prop('_V13', 'V')
    Q13 = prop('_V13', 'V')
    D13 = prop('_V13', 'D')
    S13 = prop('_V13', 'S')
    H13 = prop('_V13', 'H')
    V14 = prop('_V14', 'V')
    Q14 = prop('_V14', 'V')
    D14 = prop('_V14', 'D')
    S14 = prop('_V14', 'S')
    H14 = prop('_V14', 'H')
    V15 = prop('_V15', 'V')
    Q15 = prop('_V15', 'V')
    D15 = prop('_V15', 'D')
    S15 = prop('_V15', 'S')
    H15 = prop('_V15', 'H')
    V16 = prop('_V16', 'V')
    Q16 = prop('_V16', 'V')
    D16 = prop('_V16', 'D')
    S16 = prop('_V16', 'S')
    H16 = prop('_V16', 'H')
    V17 = prop('_V17', 'V')
    Q17 = prop('_V17', 'V')
    D17 = prop('_V17', 'D')
    S17 = prop('_V17', 'S')
    H17 = prop('_V17', 'H')
    V18 = prop('_V18', 'V')
    Q18 = prop('_V18', 'V')
    D18 = prop('_V18', 'D')
    S18 = prop('_V18', 'S')
    H18 = prop('_V18', 'H')
    V19 = prop('_V19', 'V')
    Q19 = prop('_V19', 'V')
    D19 = prop('_V19', 'D')
    S19 = prop('_V19', 'S')
    H19 = prop('_V19', 'H')
    V20 = prop('_V20', 'V')
    Q20 = prop('_V20', 'V')
    D20 = prop('_V20', 'D')
    S20 = prop('_V20', 'S')
    H20 = prop('_V20', 'H')
    V21 = prop('_V21', 'V')
    Q21 = prop('_V21', 'V')
    D21 = prop('_V21', 'D')
    S21 = prop('_V21', 'S')
    H21 = prop('_V21', 'H')
    V22 = prop('_V22', 'V')
    Q22 = prop('_V22', 'V')
    D22 = prop('_V22', 'D')
    S22 = prop('_V22', 'S')
    H22 = prop('_V22', 'H')
    V23 = prop('_V23', 'V')
    Q23 = prop('_V23', 'V')
    D23 = prop('_V23', 'D')
    S23 = prop('_V23', 'S')
    H23 = prop('_V23', 'H')
    V24 = prop('_V24', 'V')
    Q24 = prop('_V24', 'V')
    D24 = prop('_V24', 'D')
    S24 = prop('_V24', 'S')
    H24 = prop('_V24', 'H')
    V25 = prop('_V25', 'V')
    Q25 = prop('_V25', 'V')
    D25 = prop('_V25', 'D')
    S25 = prop('_V25', 'S')
    H25 = prop('_V25', 'H')
    V26 = prop('_V26', 'V')
    Q26 = prop('_V26', 'V')
    D26 = prop('_V26', 'D')
    S26 = prop('_V26', 'S')
    H26 = prop('_V26', 'H')
    V27 = prop('_V27', 'V')
    Q27 = prop('_V27', 'V')
    D27 = prop('_V27', 'D')
    S27 = prop('_V27', 'S')
    H27 = prop('_V27', 'H')
    V28 = prop('_V28', 'V')
    Q28 = prop('_V28', 'V')
    D28 = prop('_V28', 'D')
    S28 = prop('_V28', 'S')
    H28 = prop('_V28', 'H')
    V29 = prop('_V29', 'V')
    Q29 = prop('_V29', 'V')
    D29 = prop('_V29', 'D')
    S29 = prop('_V29', 'S')
    H29 = prop('_V29', 'H')
    V30 = prop('_V30', 'V')
    Q30 = prop('_V30', 'V')
    D30 = prop('_V30', 'D')
    S30 = prop('_V30', 'S')
    H30 = prop('_V30', 'H')
    V31 = prop('_V31', 'V')
    Q31 = prop('_V31', 'V')
    D31 = prop('_V31', 'D')
    S31 = prop('_V31', 'S')
    H31 = prop('_V31', 'H')

    def setRegister(self, name, value):
        '''
        Updates a register value
        @param name: the register name to update its value
        @param value: the new value for the register.
        '''
        #assert name in self.listRegisters()
        setattr(self, name, value)
        return value

    def getRegister(self, name):
        '''
        Obtains the current value of a register
        @rtype: int
        @param name: the register name to obtain its value
        @return: the value of the register
        '''
        #assert name in self.listRegisters()
        return getattr(self, name)

    _flags={
        'N': 1<<3,
        'Z': 1<<2,
        'C': 1<<1,
        'V': 1,
    }
    base_flags = 0
    def setNZCV(self, value):
        for name, mask in self._flags.items():
            setattr(self, name, value & mask !=0)
        self.base_flags = value

    def getNZCV(self):
        reg = 0
        for name, mask in self._flags.items():
            reg |= ITE(64, getattr(self, name), mask, 0)
        return reg | ZEXTEND(self.base_flags & ~ (1<<3|1<<2|1<<1|1), 64)

    FLAGS = property(getNZCV, setNZCV)
    FLAGS = property(getNZCV, setNZCV)

    #Special Registers
    def getPC(self):
        '''
        Returns the current program counter.
        
        @rtype: int
        @return: the current program counter value. 
        '''
        return getattr(self, self.IP_name)
    def setPC(self, value):
        '''
        Changes the program counter value.
        
        @param value: the new value for the program counter.
        '''
        return setattr(self, self.IP_name, value)
    IP = property(getPC,setPC)

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

    def dumpregs(self):
        '''
        Returns the current registers values.
        
        @rtype: str
        @return: a string containing the name and current value for all the registers. 
        '''
        final = {}
        for reg_name in ["X0","X1","X2","X3","X4","X5","X6","X7","X8","X9","X10","X11","X12","X13","X14","X15","X16","X17","X18","X19","X20","X21","X22","X23","X24","X25","X26","X27","X28","X29","X30","PC"]:
            value = getattr(self, reg_name)
            final[reg_name] = value

        #for reg_name in ['CF','SF','ZF','OF','AF', 'PF', 'IF']:
        #    value = getattr(self, reg_name)
        #    final[reg_name] = value

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
            self.store(where, ord(c), 8)
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
            raise "Why are you 0, you crazy bugger"
        assert size in [8, 16, 32, 64, 128, 256, 512]

        where = SIMP(where)
        
        expr = SIMP(expr)

        for i in range(size-8,-1,-8):
            if type(where) is BitVecRef:
                if self.nowrite:
                    self.impossible = 1
                addr = str(uuid.uuid1())
                self.mem.issym[addr] = 1
                self.constraints[addr] = where + i//8

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
            return self.constraints[where]

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

    @memoized('instruction_cache') 
    def getInstructionCapstone(cpu, pc):
        text = b''
        try:
            for i in range(0,4):
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
            #op.size *= 8
            op.size = 32 #capstone doesn't carry this?
        return instruction


    def getOperandAddressCapstone(cpu,o):
        address = 0
        
        if o.mem.base != 0:
            base = cpu.instruction.reg_name(o.mem.base).upper()
            address += cpu.getRegister(base)
        if o.mem.index != 0:
            index = 'X' + cpu.instruction.reg_name(o.mem.index).upper()[1:]
            address += cpu.getRegister(index)
        if o.mem.disp != 0:
            address += o.mem.disp
 
        address = address & ((1<<cpu.AddressSize)-1)

        return address

    def shift(cpu, val, o):
        if type(val) is BitVecRef and val.size() < 64:
            val = ZEXTEND(val, 64) 
        t = o.shift.type
        s = o.shift.value
        ext = o.ext
        if ext < 5:
            if t == 1: #LSL
                val = val << s
            elif t == 2: #MSL
                val = (val << s) | ((1<<s)-1)
            elif t == 3: #LSR
                val = val >> s
            elif t == 4: #ASR
                #TODO figure out the correct way to fix this, pretty sure it normally fails on
                #add x21, x25, x21, asr #2
                #treas x21 as 32 bits long which is incorrect?
                if hasattr(val, "size"):
                    if o.size>val.size():
                        size = o.size
                    else:
                        size = val.size()
                else:
                    size = o.size
                val = val >> s 
                val = SEXTEND(EXTRACT(val, 0,size-s), size-s, 64)
            elif t == 5: #ROR
                size = o.size
                #https://stackoverflow.com/questions/27176317/bitwise-rotate-right
                val = (val>>s) | (v<<(size-bits));
        else: #extend with sign
            size = o.size
            tmp = val & (1<<(size-1))
            val = EXTRACT(val, 0, size)
            val = SEXTEND(val, size, 64)

            val = val << s

        return EXTRACT(val,0,o.size)
    
    def readOperandCapstone(cpu, o):

        if o.type == ARM64_OP_REG:
            if o.shift.type or o.ext:
                return cpu.shift(cpu.getRegister(cpu.instruction.reg_name(o.reg).upper()),o)
            else:
                return cpu.getRegister(cpu.instruction.reg_name(o.reg).upper())

        elif o.type == ARM64_OP_IMM:
            if o.shift.type:
                return cpu.shift(o.imm,o)
            else:
                return o.imm
        elif o.type == ARM64_OP_MEM:
            if o.shift.type:
                return cpu.load(cpu.shift(o.address(),o), o.size)
            else:
                return cpu.load(o.address(), o.size)
        elif o.type == ARM64_OP_SYS:
            if o.reg == ARM64_SYSREG_TPIDR_EL0:
                return cpu._TPIDR_EL0
            else:
                cpu.impossible = 1
                return 0
        else:
            cpu.impossible = 1
            return 0
            raise NotImplemented("readOperand unknown type", o.type)

    def writeOperandCapstone(cpu, o, value):
        
        if o.type == ARM64_OP_REG:
            reg = cpu.instruction.reg_name(o.reg).upper()
            if reg[0] == 'W':
                size = {8:'BB',16:'HH',32:'W',64:'X'}[o.size]
                reg = f'{size}{reg[1:]}'
            cpu.setRegister(reg, value)
        elif o.type == ARM64_OP_MEM:
            if o.shift.type:
                cpu.store(cpu.shift(o.address(),o), value, o.size)
            else:
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
            The carry (C) flag is set when an operation results in a carry,
            or when a subtraction results in no borrow.
        '''

        if op in ['CMP', 'SUBS']:
            #results in a carry when, an overflow occurs or no borrow
            self.C = arg0 >= arg1
        elif op in ['ADDS']:
            #is carry if unsigned arg0 + unsigned arg1 != unsigned res, so it carries over 0, I think
            self.C = (arg0 + arg1) != res
        elif op in ['SUBS']:
            #is carry if unsigned arg0 + unsigned arg1 != unsigned res, so it carries over 0, I think
            self.C = (arg0 - arg1) != res
        elif op in ['TST', 'ANDS']:
            self.C = False
        else:
            raise NotImplemented()

        '''Zero flag.
            Set if the result is zero; cleared otherwise.
        '''
        if op in ['CMP', 'SUBS', 'ADDS', 'TST', 'SUBS', 'ANDS']:
            self.Z = res == 0
        else:
            raise NotImplemented()

        '''Negative flag.
            Set equal to the most-significant bit of the result, which is the
            sign bit of a signed integer. (0 indicates a positive value and 1 indicates a
            negative value.)
        '''
        if op in ['CMP', 'SUBS', 'ADDS', 'TST', 'SUBS', 'ANDS']:
            self.N = (res & SIGN_MASK)!=0
        else:
            raise NotImplemented()

        '''Overflow flag.
            Set if the integer result is too large a positive number or
            too small a negative number (excluding the sign-bit) to fit in the destina-
            tion operand; cleared otherwise. This flag indicates an overflow condition
            for signed-integer (two's complement) arithmetic.
        '''
        if op in ['CMP', 'SUBS', 'ADDS', 'SUBS']:
            sign0 = (arg0 & SIGN_MASK) ==SIGN_MASK
            sign1 = (arg1 & SIGN_MASK) ==SIGN_MASK
            signr = (res & SIGN_MASK) ==SIGN_MASK
            self.V = AND(XOR(sign0, sign1), XOR(sign0, signr))
        elif op in ['TST', 'ANDS']:
            self.V = False
        else:
            raise NotImplemented()

        for x in ['N','V','C','Z']:
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
            #remove the data from executable pages as we handle all the instructions that get set in the future
            if val[2] == 7:
                val[3] = None

            self.mem.mmap(val[0],val[1],val[2],val[3])

        
        stack_base = 0x7ffffffde000
        stack = self.mem.mmap(stack_base,0x21000,'rw')+0x21000-1

    def reset(self, insts, knownvalues):

        self.icount         = 0
        self.done           = 0
        self.bad_inst       = 0
        self.impossible     = 0
        self.const_counter  = 0

        self.segments       = {}

        self.constraints = {}           #Overall Constraints to keep track of memory references
        self.jump_constraints  = ['Jump Constraints']     #Constraints to keep track of comparisons or flag altering instructions
        self.read_constraints  = ['Read Constraints']
        self.write_constraints = ['Write Constraints']
        self.seg_constraints   = ['Segment Constraints']
        self.condition_condition = ['Conditions']
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

        if self.tpidr_el0 == 0:
            self._TPIDR_EL0 = BitVec("TPIDR_EL0", 64)
        else:
            self._TPIDR_EL0 = self.tpidr_el0

        #end envp marker empty string
        stack-=1
        self.write(stack,'\x00')

        stack = ((stack - bsz) //bsz )*bsz      # [ padding ]

        stack-=bsz
        self.store(stack,0,addressbitsize)
        stack-=bsz
        self.store(stack,0,addressbitsize)

        for x in insts:
            #print(hex(x.address)+self.entry)
            self.write(x.address,x.bytes)

        logger.info("Setting initial cpu state")
        #set initial CPU state
        self.setRegister('SP',stack)
        for x in range(30): 
            x = f'X{x}'
            if knownvalues and x in knownvalues:
                self.setRegister(x, BitVecVal(knownvalues[x],64))
            else:
                self.setRegister(x, BitVec(x,64))
        self.setRegister('X30', BitVecVal(0xbeefcafebabe,64))

        for reg in ['N','Z','C','V']:
            setattr(self, reg, Bool(reg))

        for x in range(0,32):
            self.setRegister(f"Q{x}", BitVec(x,128))

        self.setRegister('PC',            insts[0].address)

    def execute(cpu):
        ''' Decode, and execute one intruction pointed by register PC'''

        #for now I will not try to simplify PC, mostly because it would get costly to do it on every iteration
        try:
            #if not cpu.mem.isExecutable(cpu.IP):
            #    print(cpu.IP)
            #    print(hex(cpu.IP))
            #    print(cpu.mem)
            #    raise InvalidPCException(cpu.IP)

            instruction = cpu.getInstructionCapstone(cpu.IP)
        except:
            raise SymbolicPCException(cpu.IP)

        cpu.instruction = instruction
        #print(instruction)

        #Check if we already have an implementation...
        name = instruction.insn_name().upper()

        try:
            implementation = getattr(cpu, name)
        except:
            cpu.impossible=1
            return

        implementation(*instruction.operands)

        #housekeeping
        cpu.icount += 1

        if cpu.icount > cpu.cycles:
            cpu.impossible = 1

    def bit_is_set(cpu, index):
        inst = cpu.instruction.bytes
        i = index//8
        return inst[i] & (1<<(index%8))

    def get_reg(cpu,o):
        return cpu.instruction.reg_name(o.reg).upper()

    def condition_set(cpu):

        cond = cpu.instruction.cc

        if cond == ARM64_CC_EQ: #EQUAL
            cond = cpu.Z == True
            symbol = "=="
        elif cond == ARM64_CC_NE: #NOT EQUAL
            cond = cpu.Z == False
            symbol = "!="
        elif cond == ARM64_CC_HS: #UNSIGNED HIGHER OR SAME
            cond = cpu.C == True
            symbol = "HS"
        elif cond == ARM64_CC_LO: #UNSIGNED LOWER
            cond = cpu.C == False
            symbol = "LO"
        elif cond == ARM64_CC_MI: #NEGATIVE
            cond = cpu.N == True
            symbol = "N"
        elif cond == ARM64_CC_PL: #POSITIVE OR ZERO
            cond = cpu.N == False
            symbol = "!N"
        elif cond == ARM64_CC_VS: #SIGNED OVERFLOW
            cond = cpu.V == True
            symbol = "V"
        elif cond == ARM64_CC_VC: #NO SIGNED OVERFLOW
            cond = cpu.V == False
            symbol = "!V"
        elif cond == ARM64_CC_HI: #UNSIGNED HIGHER
            cond = cpu.C == True and cpu.Z == False
            symbol = "HI"
        elif cond == ARM64_CC_LS: #UNSIGNED LOWER OR SAME
            cond = not (cpu.C == True and cpu.Z == False)
            symbol = "LS"
        elif cond == ARM64_CC_GE: #SIGNED GREATER THAN OR EQUAL
            cond = cpu.N == cpu.V
            symbol = ">="
        elif cond == ARM64_CC_LT: #SIGNED LESS THAN
            cond = cpu.N != cpu.V
            symbol = "<"
        elif cond == ARM64_CC_GT: #SIGNED GREATER THAN
            cond = cpu.Z == False and cpu.N == cpu.V
            symbol = ">"
        elif cond == ARM64_CC_LE: #SIGNED LESS THAN OR EQUAL
            cond = cpu.Z == True or cpu.N != cpu.V
            symbol = "<="
        elif cond == 0:
            cond = True
            symbol = 0
        else:
            NotImplemented("condition_set is not implemented")

        if symbol:
            return (cond, symbol)
        else:
            return cond


############################################################################
# General LOGIC Operations                                                 #
############################################################################
# AND, ANDS, ORR, EOR, NOT, NEG, TST                                                   #
############################################################################

    @instruction
    def AND(cpu, dest, src1, src2):
        
        #AND Instruction

        src1 = SIMP(src1.read())
        src2 = SIMP(src2.read())

        dest.write(src1 & src2)

    @instruction
    def ANDS(cpu, dest, src1, src2):

        #ANDS Instruction

        if cpu.bit_is_set(31):
            size = 64
        else:
            size = 32

        src1 = SIMP(src1.read())
        src2 = SIMP(src2.read())
        res = src1 & src2

        cpu.calculateFlags('ANDS', size, res, src1, src2)

        dest.write(res)


    @instruction
    def ORR(cpu, dest, src1, src2):

        #ORR Instruction

        if cpu.bit_is_set(31):
            size = 64
        else:
            size = 32

        src1.size = size
        src2.size = size

        src1 = SIMP(src1.read())
        src2 = SIMP(src2.read())

        res = src1 | src2

        dest.write(res)

    @instruction
    def TST(cpu, op1, op2):

        #TST Instruction

        if cpu.bit_is_set(31):
            size = 64
        else:
            size = 32

        op1 = SIMP(op1.read())
        #Fix the size incase it is needed for a shift
        op2.size = size
        op2 = SIMP(op2.read())

        cpu.calculateFlags('TST', size, op1 & op2, op1, op2)

    @instruction
    def NEG(cpu, op1, op2):

        #NEG Instruction

        if cpu.bit_is_set(31):
            size = 64
        else:
            size = 32

        val = (0 - op2.read()) + (1<<size)
        op1.write(val)

    @instruction
    def EOR(cpu, dest, op1, op2):

        #EOR Instruction

        #bit = [BitVecRef, BitVecNumRef]
        val1 = SEXTEND(SIMP(op1.read()), op1.size, 64)
        val2 = SEXTEND(SIMP(op2.read()), op2.size, 64)
       
        #if type(val1) in bit and type(val2) in bit:
        #    print(type(val1))
        #    print(type(val2), )
        #    dest.write(XOR(val1, val2))
        #else:
        test = val1 ^ val2
        dest.write(test)

############################################################################
# General MATH Operations                                                  #
############################################################################
# ADD, SUB, MUL, MSUB, MADD, UDIV, ADDS, SUBS                              #
############################################################################

    @instruction
    def ADD(cpu, dest, src, src2, shift=0):

        #ADD instruction

        if cpu.bit_is_set(31):
            size = 64
        else:
            size = 32
        src.size = size
        src2.size = size

        dest.write(src.read() + (src2.read()<<shift))

    def ADDS(cpu, dest, op1, op2, shift=0, cmn=0):

        #ADDS instruction

        arg0 = SIMP(op1.read())
        arg1 = SIMP(op2.read())<<shift
        
        if cpu.bit_is_set(31):
            size = 64
        else:
            size = 32

        cpu.calculateFlags('ADDS', size, arg0+arg1, arg0, arg1)
        if cmn==0:
            cpu.ADD(dest, op1, op2, shift)

    @instruction
    def CMN(cpu, dest, op1, shift=0):
        
        #CMN instruction

        cpu.ADDS(0, dest, op1, shift, 1)


    @instruction
    def SUB(cpu, dest, op1, op2, shift = 0):

        #SUB instruction

        if cpu.bit_is_set(31):
            size = 64
        else:
            size = 32
        op2.size = size

        dest.write(op1.read() - (op2.read()<<shift))

    def SUBS(cpu, dest, op1, op2, shift=0):

        #SUBS instruction

        arg0 = SIMP(op1.read())
        arg1 = SIMP(op2.read())<<shift
        
        if cpu.bit_is_set(31):
            size = 64
        else:
            size = 32

        cpu.calculateFlags('SUBS', size, arg0-arg1, arg0, arg1)
        cpu.SUB(dest, op1, op2, shift)

    @instruction
    def MUL(cpu, dest, op1, op2):

        #MUL Instruction

        dest.write(op1.read() * op2.read())

    @instruction
    def MSUB(cpu, dest, op1, op2, op3):

        #MSUB Instruction

        dest.write((op1.read() * op2.read())-op3.read())

    @instruction
    def MADD(cpu, dest, op1, op2, op3):

        #MSUB Instruction

        dest.write((op1.read() * op2.read())-op3.read())

    @instruction
    def UDIV(cpu, dest, op1, op2):

        #UDIV Instruction

        if op2.read() == 0:
            cpu.impossible = 1
            return

        dest.write(UDIV(op1.read(), op2.read()))

############################################################################
############################################################################
# General Movement Operations                                              #
############################################################################
# MOV, MOVZ, LDR, LDRH, LDRB, LDUR, LDURH, LDURB, LDP, STP, STR, STRH, STRB#
# STUR, STURH, STURB, MOVK, LDXR                                           #
############################################################################

    @instruction
    def MOV(cpu, dest, src):

        #MOV instuction

        #needed for shifts
        if cpu.bit_is_set(31):
            src.size = 64

        dest.write(src.read())

    def MOVZ(cpu, dest, src):
        
        #MOVZ instruction

        MOV(cpu, dest, src)

    @instruction
    def MOVK(cpu, dest, src):

        #MOVK Instruction

        mask = 0xffffffffffffffff ^ (0xffff << src.shift.value)

        tmp = dest.read() & mask

        dest.write(tmp | src.read())

    @instruction 
    def LDP(cpu, reg1, reg2, src, offset=0):

        #LDP instruction
        
        src.size = 64
        size = 0
        reg1.write(src.read())
        if cpu.bit_is_set(31):
            size = 8
        else:
            size = 4
        src.mem.disp += size
        reg2.write(src.read())

        #post increment
        if offset != 0:
            reg = cpu.get_reg(src)
            setattr(cpu, reg, getattr(cpu,reg) + offset.prefetch)

        #pre increment
        elif cpu.bit_is_set(24) and cpu.bit_is_set(23):
            reg = cpu.get_reg(src)
            setattr(cpu, reg, getattr(cpu,reg) + src.mem.disp - size)

    @instruction
    def LDR(cpu, dest, src, offset=0):

        #LDR instruction

        src.size = 64

        dest.write(src.read())

        #post increment
        if offset != 0:
            reg = cpu.get_reg(src)
            setattr(cpu, reg, getattr(cpu,reg) + offset.prefetch)

        #pre increment
        elif not cpu.bit_is_set(24) and cpu.bit_is_set(11):
            reg = cpu.get_reg(src)
            setattr(cpu, reg, getattr(cpu,reg) + src.mem.disp)

    @instruction
    def LDRH(cpu, dest, src, offset=0):

        #LDR instruction

        src.size = 16
        dest.size = 16

        dest.write(src.read())
        #post increment
        if offset != 0:
            reg = cpu.get_reg(src)
            setattr(cpu, reg, getattr(cpu,reg) + offset.prefetch)

        #pre increment
        elif not cpu.bit_is_set(24) and cpu.bit_is_set(11):
            reg = cpu.get_reg(src)
            setattr(cpu, reg, getattr(cpu,reg) + src.mem.disp)

    @instruction
    def LDRB(cpu, dest, src, offset=0):

        #LDR instruction

        src.size = 8
        dest.size = 8

        dest.write(src.read())
        #post increment
        if offset != 0:
            reg = cpu.get_reg(src)
            setattr(cpu, reg, getattr(cpu,reg) + offset.prefetch)

        #pre increment
        elif not cpu.bit_is_set(24) and cpu.bit_is_set(11):
            reg = cpu.get_reg(src)
            setattr(cpu, reg, getattr(cpu,reg) + src.mem.disp)

    def LDUR(cpu, dest, src):
        
        #LDUR instruction

        cpu.LDR(dest,src)

    def LDURH(cpu, dest, src):
        
        #LDURH instruction

        cpu.LDRH(dest,src)

    def LDURB(cpu, dest, src):
        
        #LDURB instruction

        cpu.LDRB(dest,src)
    
    @instruction
    def LDRSB(cpu, dest, src, offset=0):

        #LDRSB Instruction

        src.size = 8

        if cpu.bit_is_set(31):
            size = 64
        else:
            size = 32

        dest.write(src.read())
        #post increment
        if offset != 0:
            reg = cpu.get_reg(src)
            setattr(cpu, reg, SEXTEND(getattr(cpu,reg) + offset.prefetch, src.size, size))

        #pre increment
        elif not cpu.bit_is_set(24) and cpu.bit_is_set(11):
            reg = cpu.get_reg(src)
            setattr(cpu, reg, getattr(cpu,reg) + src.mem.disp)

    @instruction
    def LDRSH(cpu, dest, src, offset=0):

        #LDRSH Instruction

        src.size = 16

        if cpu.bit_is_set(31):
            size = 64
        else:
            size = 32

        dest.write(src.read())
        #post increment
        if offset != 0:
            reg = cpu.get_reg(src)
            setattr(cpu, reg, SEXTEND(getattr(cpu,reg) + offset.prefetch, src.size, size))

        #pre increment
        elif not cpu.bit_is_set(24) and cpu.bit_is_set(11):
            reg = cpu.get_reg(src)
            setattr(cpu, reg, getattr(cpu,reg) + src.mem.disp)

    @instruction
    def LDRSW(cpu, dest, src, offset=0):

        #LDRSW Instruction

        src.size = 32

        if cpu.bit_is_set(31):
            size = 64
        else:
            size = 32

        dest.write(src.read())

        #post increment
        if offset != 0:
            reg = cpu.get_reg(src)
            setattr(cpu, reg, SEXTEND(getattr(cpu,reg) + offset.prefetch, src.size, size))

        #pre increment
        elif not cpu.bit_is_set(24) and cpu.bit_is_set(11):
            reg = cpu.get_reg(src)
            setattr(cpu, reg, getattr(cpu,reg) + src.mem.disp)

    '''
    @instruction
    def LDXR(cpu, dest, src):

        #LDXR Instruction

        if cpu.bit_is_set(31):
            size = 64
        else:
            size = 32

        src.size = size

        dest.write(src.read())
    '''

    @instruction
    def STP(cpu, reg1, reg2, dest, offset = 0):
        
        #STP instruction

        if cpu.bit_is_set(31):
            size = 8
        else:
            size = 4
        dest.size = size*4

        dest.write(reg1.read())
        reg1.mem.disp += size
        dest.write(reg2.read())

        #post increment
        if offset != 0:
            reg = cpu.get_reg(reg1)
            setattr(cpu, reg, getattr(cpu,reg) + offset.prefetch)

        #pre increment
        elif cpu.bit_is_set(24) and cpu.bit_is_set(23):
            reg = cpu.get_reg(reg1)
            setattr(cpu, reg, getattr(cpu,reg) + reg1.mem.disp - size)

    def STR(*args):
        
        #STR instruction
        #So... is this the right way to do this? probably not, but it works
        cpu = args[0]
        tmp = args[1] #technically source
        args = list(args[1:])
        args[0] = args[1]
        args[1] = tmp

        if cpu.bit_is_set(30):
            args[0].size = 64
            args[1].size = 64

        cpu.LDR(*args)

    def STRH(*args):
        
        #STRH instruction
        #So... is this the right way to do this? probably not, but it works
        cpu = args[0]
        tmp = args[1]
        args = list(args[1:])
        args[0] = args[1]
        args[1] = tmp
        cpu.LDRH(*args)

    def STRB(*args):
        
        #STRH instruction
        #So... is this the right way to do this? probably not, but it works
        cpu = args[0]
        tmp = args[1]
        args = list(args[1:])
        args[0] = args[1]
        args[1] = tmp
        cpu.LDRB(*args)

    def STUR(cpu, dest, src):
        
        #STUR instruction

        cpu.STR(dest,src)

    def STRUH(cpu, dest, src):
        
        #STURH instruction

        cpu.STRH(dest,src)

    def STURB(cpu, dest, src):
        
        #STURB instruction

        cpu.STRB(dest,src)
        

############################################################################
# PROTECTION OPERATIONS                                                    #
############################################################################
# PACIBSP, AUTIBSP, BTI, HINT                                              #
############################################################################

    #TODO fix these 2 instructions in the futre, but at the moment this should hold well enough
    @instruction
    def PACIBSP(cpu):

        #PACIBSP instruction

        cpu.X30 = cpu.X30 ^ 0XDEAD000000000000

    @instruction
    def PACIASP(cpu):

        #PACIBSP instruction

        cpu.X30 = cpu.X30 ^ 0XDEAD000000000000


    @instruction
    def AUTIBSP(cpu):
        
        #AUT instruction

        cpu.X30 = cpu.X30 ^ 0xDEAD000000000000
        if SIMP(cpu.X30 & 0xffff000000000000):
            #simulates a failed autibsp instruction
            cpu.impossible = 1

    def AUTIASP(cpu):

        #AUT instruction

        cpu.AUTIBSP()

    @instruction
    def BTI(cpu):

        #BTI instruction
        #Gonna treat this as a nop

        pass

    def HINT(cpu, blah):

        #HINT Instruction
        #Capstone incorrectly decompiled this instruction

        if cpu.instruction.bytes == b'\x5f\x24\x03\xd5':
            cpu.BTI()
        else:
            cpu.impossible = 1



############################################################################
# CONTROL FLOW OPERATIONS                                                  #
############################################################################
# RET, BR, BL, BLR                                                         #
############################################################################

    @instruction
    def RET(cpu):

        #RET instruction

        if cpu.X30 == 0xbeefcafebabe:
            cpu.done = 1
            cpu.PC = cpu.X30
            return
        cpu.PC = cpu.X30-4

    @instruction
    def BLR(cpu, dest):

        #BLR Instruction

        cpu.done = 1
        cpu.target = dest.read()
        cpu.PC = 0XCAFEBABEDEADBEEF

    @instruction
    def BL(cpu, dest):

        #BL instruction

        cpu.X30 = cpu.PC+4
        cpu.PC = dest.read()


    #used as a helper to all the branches, since they all have the same layout
    def branchy(self, target, condition, symbol=None):

        if type(condition) is tuple:
            symbol = condition[1]
            condition = SIMP(condition[0])
        else:
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
            if type(condition) is bool and condition == True:
                self.PC = target.read()
            elif type(condition) is BoolRef and FALSE(condition):
                self.impossible = 1
            elif type(condition) is BoolRef and TRUE(condition):
                self.PC = target.read()
            elif self.instruction.mnemonic == 'BR':
                self.PC = target.read()
            else:
                if self.flag_constraints != () and symbol != '':
                    self.jump_constraints.append(f'{self.size_lookup[self.flag_constraints[3]]} {self.flag_constraints[1]} {symbol} {self.flag_constraints[2]}')
                elif type(condition) in [BitVecRef, BoolRef]:
                    self.jump_constraints.append(f'{condition} {symbol}')
                self.PC = target.read()

    @instruction
    def TBNZ(cpu, src, val, dest):

        #TBNZ instruction

        cpu.branchy(dest, src.read()&(1<<val.read()), '')

    @instruction
    def TBZ(cpu, src, val, dest):

        #TBZ instruction

        cpu.branchy(dest, (src.read()&(1<<val.read())) == 0, '')


    @instruction
    def CBZ(cpu, src, dest):

        #CBZ instruction

        cpu.branchy(dest, src.read() == 0, '')

    @instruction
    def CBNZ(cpu, src, dest):
        
        #CBNZ instruction

        cpu.branchy(dest, src.read() != 0, '')

    @instruction
    def B(cpu, dest):

        #B instruction

        #cpu.PC = dest.read()
        cpu.branchy(dest, cpu.condition_set())

############################################################################
# Bit Manipulation OPERATIONS                                              #
############################################################################
# SCTW, SCTH, SCTB, UBFIZ, SBFIZ, BIC, SXTW, SXTH, SXTB                    #
############################################################################

    @instruction
    def SCTW(cpu, dest, src):
        
        #SCTW Instruction

        dest.write(SEXTEND(src, 32, 64))

    #Logic for the next two is that it will just extract down to a word or stay at 64 bits, in the set reg function
    @instruction
    def SCTH(cpu, dest, src):
        
        #SCTW Instruction

        dest.write(SEXTEND(src, 16, 64))

    @instruction
    def SCTH(cpu, dest, src):
        
        #SCTW Instruction

        dest.write(SEXTEND(src, 8, 64))

    @instruction
    def LSL(cpu, dest, src, size):

        #LSL Instruction
        
        dest.write(src.read() << size.read())

    @instruction
    def LSR(cpu, dest, src, size):

        #LSR Instruction

        dest.write(src.read() >> size.read())

    @instruction
    def ASR(cpu, dest, src, op):

        #ASR Instration

        if cpu.bit_is_set(31):
            size = 64
        else:
            size = 32
        
        new_size = SIMP(op.read())
        
        #Z3 cannot extract based on a symbolic size
        if type(new_size) is not int:
            cpu.impossible = 1
            return

        val = EXTRACT(src.read() >> new_size, 0, size-new_size)
        

        val = SEXTEND(val, size-new_size, size)
        dest.write(val)

    @instruction
    def UBFIZ(cpu, dest, src, offset, size):

        #UBFIZ Instruction

        dest.write(EXTRACT(src.read(), 0, size.read())<<offset.read())

    @instruction
    def SBFIZ(cpu, dest, src, offset, op):

        #SBFIZ Instruction

        if cpu.bit_is_set(31):
            size = 64
        else:
            size = 32

        dest.write(SEXTEND(EXTRACT(src.read(), 0,op.read()),op.read(), size)  << offset.read())

    @instruction
    def UBFX(cpu, dest, src, offset, size):

        #UBFX Instruction
        
        dest.write(EXTRACT(src.read(),offset.read(), size.read()))

    @instruction
    def BFI(cpu, dest, src, lsb, width):

        #BFI Instruction

        if cpu.bit_is_set(31):
            size = 64
        else:
            size = 32

        lsb = lsb.read()
        width = width.read()
        mask = 0xffffffffffffffff 
        #lol this operation
        mask = mask ^ (EXTRACT(mask, 0, width) << lsb)
        val = SIMP(ZEXTEND(EXTRACT(src.read(), 0,width)<<lsb, size))
        val2 = SIMP(ZEXTEND(dest.read() & mask,size))
        dest.write(val2 | val)

    @instruction
    def BIC(cpu, dest, op1, op2):

        #BIC Instruction

        dest.write(op1.read() & op2.read())

    @instruction
    def SXTW(cpu, dest, src):

        #SXTW Instruction

        dest.write(SEXTEND(src.read(),32, 64))

    @instruction
    def SXTH(cpu, dest, src):

        #SXTH Instruction

        if cpu.bit_is_set(31):
            size = 64
        else:
            size = 32

        dest.write(SEXTEND(src.read(),16, size))

    @instruction
    def SXTB(cpu, dest, src):

        #SXTB Instruction

        if cpu.bit_is_set(31):
            size = 64
        else:
            size = 32

        dest.write(SEXTEND(src.read(),8, size))


############################################################################
# CONDITIONAL OPERATIONS                                                   #
############################################################################
# CSEL, CCMP, CSET, CSINC, CSINV                                           #
############################################################################

    @instruction
    def CSEL(cpu, dest, op1, op2):

        #CSEL Instruction

        if cpu.bit_is_set(31):
            size = 64
        else:
            size = 32

        #CONDITIONS
        cond = cpu.condition_set()[0]
        symbol = cpu.condition_set()[1]
        if cpu.flag_constraints != ():
            cpu.condition_condition.append(f'{cpu.size_lookup[cpu.flag_constraints[3]]} {cpu.flag_constraints[1]} {symbol} {cpu.flag_constraints[2]}')

        dest.write(ITE(size, cond, op1.read(), op2.read()))

    def CCMP(cpu, op1, op2, val):

        #CCMP instruction

        if cpu.bit_is_set(31):
            size = 64
        else:
            size = 32

        val.size = size
        flag = EXTRACT(cpu.getNZCV(),0,size)

        cpu.CMP(op1, op2)

        cond = cpu.condition_set()[0]
        symbol = cpu.condition_set()[1]
        if cpu.flag_constraints != ():
            cpu.condition_condition.append(f'{cpu.size_lookup[cpu.flag_constraints[3]]} {cpu.flag_constraints[1]} {symbol} {cpu.flag_constraints[2]}')
        cpu.setNZCV(ITE(size, cond, flag, val.read()))

    @instruction
    def CSET(cpu, dest):

        #CSET Instruction

        if cpu.bit_is_set(31):
            size = 64
        else:
            size = 32

        cond = cpu.condition_set()[0]
        symbol = cpu.condition_set()[1]
        if cpu.flag_constraints != ():
            cpu.condition_condition.append(f'{cpu.size_lookup[cpu.flag_constraints[3]]} {cpu.flag_constraints[1]} {symbol} {cpu.flag_constraints[2]}')

        dest.write(ITE(size, cond, 1, 0))

    @instruction
    def CSINC(cpu, dest, true, false):

        #CSINC Instruction

        if cpu.bit_is_set(31):
            size = 64
        else:
            size = 32

        cond = cpu.condition_set()[0]
        symbol = cpu.condition_set()[1]
        if cpu.flag_constraints != ():
            cpu.condition_condition.append(f'{cpu.size_lookup[cpu.flag_constraints[3]]} {cpu.flag_constraints[1]} {symbol} {cpu.flag_constraints[2]}')

        dest.write(ITE(size, cond, true.read(), false.read()+1))

    @instruction
    def CSINV(cpu, dest, true, false):

        #CSINV Instruction

        if cpu.bit_is_set(31):
            size = 64
        else:
            size = 32

        cond = cpu.condition_set()[0]
        symbol = cpu.condition_set()[1]
        if cpu.flag_constraints != ():
            cpu.condition_condition.append(f'{cpu.size_lookup[cpu.flag_constraints[3]]} {cpu.flag_constraints[1]} {symbol} {cpu.flag_constraints[2]}')

        dest.write(ITE(size, cond, true.read(), false.read()^((1<<size)-1)))

############################################################################
# MISC OPERATIONS                                                          #
############################################################################
# CMP, NOP, ADDRP, MRS, SVC, REV,                                           #
############################################################################
    
    @instruction
    def CMP(cpu, op1, op2):

        #CMP instruction

        if cpu.bit_is_set(31):
            size = 64
        else:
            size = 32
        
        op2.size = size
    
        arg0 = SIMP(op1.read())
        arg1 = SIMP(op2.read())

        cpu.calculateFlags('CMP', size, arg0-arg1, arg0, arg1)

    @instruction
    def NOP(cpu):

        #NOP

        pass

    @instruction 
    def ADRP(cpu, dest, src):

        #ADRP instruction

        val = src.read()

        dest.write(val&0xfffffffffffff000)

    @instruction
    def MRS(cpu, dest, src):

        #MRS instruction

        dest.write(src.read())

    @instruction
    def SVC(cpu, val):

        #SVC instruction

        sys = SIMP(cpu.X8)
        cpu.syscall.append(sys)
        cpu.X0 = -1

    @instruction
    def REV(cpu, dest, src):

        #REV instruction

        if cpu.bit_is_set(31):
            size = 64
        else:
            size = 32

        val = src.read()
        val2 = 0

        for x in range(0, size, 8):
            val2 = val2 << 8
            val2 += val&0xff
            val = val >> 8

        dest.write(val2)


############################################################################
# FLOATING-POINT OPERATIONS                                                          #
############################################################################
# FMOV                                                #
############################################################################

    @instruction
    def FMOV(cpu, dest, src):

        #FMOV instruction
        #cpu.impossible = 1 
        dest.write(src.read())
