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

from consts import *
import z3
from smtlib import SIMP
import re

def extract(s):
    #TODO try to find a xmm - zmm extract example
    l = re.findall(r"Extract\([0-9]+, 0, R..\)",str(s))

    #I could have set this to a set, but that changes the order and just makes the output look weird
    l2 = []

    for x in l:
        if x in l2:
            continue
        l2.append(x)
        val = x.split('(')[1].split(',')
        reg = val[2][1:].split(')')[0]
        val = int(val[0]) + 1
        if val not in [8,16,32]:
            continue
        s = s.replace(x,extract_lookup[reg][val])

    return s

def extract2(s):
   
    index = 0
    counter = 0
    while True:
        if counter == 100:
            print('yep')
            exit(0)
            break #infinite loop of redirections somehow...
        l = re.search(r"Extract\([\s]*[0-9]+,[\s]*[0-9]+,[\s]*",str(s[index:]))
        if l == None:
            break
        span = list(l.span())
        span[0] += index
        span[1] += index
        string = s[span[0]:span[1]]
        string = string.split('(')[1].split(',')
        end = int(string[0])
        start = int(string[1])
        val = ((2<<(end-start))-1)<<start
        s = list(s)
        counter = 0
        found = 0
        #preserve any nesting that occurs
        for x in range(span[1], len(s)):
            if '(' == s[x]:
                counter += 1
            if ')' == s[x]:
                if counter == 0:
                    if end == start and end > 8:
                        s[x] = f') & 1<<{end}'
                    else:
                        s[x] = f') & {hex(val)}'
                    found = 1
                    break
                else:
                    counter -= 1

        l = 0
        if found == 1:
            #remove the extract string and its bits
            s = s[0:span[0]] + ['('] + s[span[1]:]
            l = span[1] - span[0]

        index = span[1]-l

        s = ''.join(s)
        yesyes=1
        counter+=1

    return s

#Following functions are used for pretty print ability
def big_int(s):
    l = []
    l += re.findall(r"[0-9][0-9][0-9]+",str(s))
    l = sorted(l,key=lambda c: len(c))[::-1]
    for numeral in l:
        s = s.replace(numeral,str(hex(int(numeral))))
    return s

def reg(s, constraints):
    l = []
    #Remove any nested constraints, happens when memory is dereferenced several times
    while 1:
        attempted = 0
        l2 = []
        l = re.findall(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",str(s))
        while len(l):
            n = l.pop()
            if n in l2:
                continue
            attempted = 1
            l2.append(n)
            s = str(s).replace(n, f'[{str(constraints[n])}]')
        if attempted == 0:
            break
    return s

def foppy(cpu):

    diff_results = {}

    pre_a = cpu.dumpregs()
    #set the return address
    if cpu.machine == 'amd64':
        cpu.push(0xdeadbeefcafebabe, 64)
        
    count = 0
    test_case_no = 0
    #print(hex(cpu.PC))

    hit = {}
    #execute until exception or finish
    while cpu.done == 0 and cpu.bad_inst != 1 and cpu.impossible != 1:
        #limits looping at specific addresses
        if cpu.PC in hit:
            hit[cpu.PC]+=1
        else:
            hit[cpu.PC] = 0

        if hit[cpu.PC] == cpu.loop_max:
            cpu.impossible=1
            break

        cpu.execute()

    if cpu.bad_inst == 1 or cpu.impossible == 1:
        #print("bad inst, impossible")
        return {}
    a = cpu.dumpregs()
    b = cpu.constraints
    for reg_name in a:
        if reg_name in ['RIP', 'PC', 'ZF','PF','CF','OF','NF','AF','SF', 'IF']:
            continue

        a[reg_name] = SIMP(a[reg_name])

        if str(a[reg_name]) != str(pre_a[reg_name]):
            try:
                if reg_name in ['RSP','X31'] and (type(cpu.PC) is not z3.z3.BitVecRef and cpu.PC != 0xCAFEBABEDEADBEEF): #can't change the stack pointer
                    return {}
            except:
                print("Bad name?")
                print(cpu.PC)
                exit(0)
            if type(a[reg_name]) in (z3.z3.BitVecRef, z3.z3.BoolRef):

                #not sure if bool is possible but worth the check
                s = str(a[reg_name])
                #replace contraints

                s = reg(s, b)

                #convert big numbers to hex
                s = big_int(s)

                #convert extract
                s = extract(s)
                s = extract2(s)

                diff_results[reg_name] = s.replace('\n', ' ')
            else:
                diff_results[reg_name] = str(a[reg_name]) #this should only be an int I think

        else:
            pass


    if diff_results:
        for x in cpu.constraints:
            try:
                cpu.constraints[x] = z3.z3.simplify(cpu.constraints[x])
            #there is a chance that this value is not a z3 expression somehow
            except:
                pass
    return (diff_results, (cpu.constraints, cpu.read_constraints, cpu.write_constraints, cpu.seg_constraints, cpu.jump_constraints, cpu.condition_condition, cpu.syscall))

def nesting(constraints, s):
    size = 0
    lookup = []
    const_counter = -1
    value = -1
    if len(s) > 1 and type(s) is not str:
        size = s[1]
        const_counter = s[2]
        if len(s) > 3:
            value = s[3]
        s=s[0]

    s = reg(s, constraints)

    if size:
        size = sizes_lookup[size] + " "
    else:
        size = ""
    if const_counter != -1:
        const_counter = str(const_counter) + ": "
    else:
        const_counter = ""
    if value == -1:
        value = ""
    else:
        value = " = " + reg(str(value), constraints)
    s = extract(s)
    s = extract2(s)
    value = extract(value)
    value = extract2(value)
    t = f"      {const_counter}{size}{s}{value}"
    t = re.sub('\s+', ' ', t.replace('\n', ' '))
    t = big_int(t)
    return f"      {t}"

#pretty print function
def pretty_print(lib, addr, ret, cpu):
    results = ret[0]
    constraints, read_constraints, write_constraints, seg_constraints, jump_constraints, conditions, syscall = ret[1]
    #only print if we have results in the first place
    if len(results) and not (cpu.nc and (read_constraints[1:] or write_constraints[1:] or seg_constraints[1:] or jump_constraints[1:] or syscall[1:])):
        if (len(results) == 1 and 'RAX' in results) and (not (cpu.nc and (write_constraints[1:] or syscall[1:])) and not (write_constraints[1:] or syscall[1:])):
        #    #Remove useless gadgets that only modify RAX and nothing else 
            return 0
        if ar: #avoid register
            if any(REG.upper() in results for REG in ar):
                return 0
        if tr: #target register
            if rt: # require target register
                if not all(REG.upper() in results for REG in tr):
                    return 0
            else:
                #if none of our regs exist leave early
                if not any(REG.upper() in results for REG in tr):
                    return 0

        if rv:
            #if a specific register value
            test = 0
            for reg_val in rv:
                reg,val = reg_val.split(':')
                #exit early if our reg doesn't exist
                reg = reg.upper()
                if reg not in results:
                    continue
                #check if val is a digit
                if val.isdigit() or (val[0] == '-' and val[1:].isdigit()):
                    val = int(val)
                    #convert to 64 unsigned, like how python has it stored
                    if val < 0:
                        if m32:
                            val += 2<<31
                        else:
                            val += 2<<63
                    
                    if results[reg] == str(val):
                        #good to go
                        test = 1
                        break
                else:
                    if results[reg] == val:
                        #good to go
                        test = 1
                        break

            if test == 0:
                return 0
        #TODO   
        #print(f'{cpu.location} {addr}:')
        print(f'{lib} {hex(addr)}:')
        print("   Results:")

        for REG in results:
            res = results[REG]
            if res.isdigit():
                val = hex(int(res))
            else:
                val = res
            val = re.sub('\s+', ' ', val)
            #val = big_int(val)
            print(f"      {REG}: {val}") 
        #only print if constraints exist
        for x in [read_constraints, write_constraints, seg_constraints, jump_constraints, conditions]:
            if len(x) > 1:
                c = []
                print(f"   {x[0]}:")
                for v in x[1:]:
                    s = nesting(constraints,v)
                    if s in c:
                        continue
                    c.append(s)
                    print(s)
        if len(syscall) > 1:
            if cpu.machine == 'aarch64':
                syscalls = asyscalls
            else:
                syscalls = isyscalls
            print(f"   {syscall[0]}")
            for x in syscall[1:]:
                if x not in syscalls:
                    print(f"      {x}")
                else:
                    print(f"      {syscalls[x]}")

        #register call
        if cpu.PC == 0xCAFEBABEDEADBEEF:
            #only really cae about symbolic ones
            if type(cpu.target) is z3.z3.BitVecRef:
                s = str(cpu.target)
                print(f"    Symbolic target:")
                print(f"        {nesting(constraints, s)}")

        print()
        return 1
    else:
        return 0

