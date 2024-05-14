import gc
from copy import deepcopy
from consts import *
from funcs import *
from capstone import Cs
from capstone import *
from elftools.elf.elffile import ELFFile
from io import BytesIO

class util():
    def __init__(self, core):
        self.num = 0
        self.fa = False
        self.func_counter = 0
        self.counter = 0
        self.counterr = 0
        self.elf = core
        self.avoids = False
        self.cpu = 0
        self.core = core

    def convert_jumps(self,a):
        #convert the jump from who knows how much to 1 byte
        
        m = jil1[a.mnemonic.upper()]
        if a.size() > 2:
            s = jil2[m]
            a.bytes[1] = s
            s = 2
        else:
            s = jil3[m]
            a.bytes[0] = s
            s = 1
        
        for x in range(s,a.size()):
            a.bytes[x] = 0
        #s = a.bytes

        a.mnemonic = m


    #Function will loop through the instructions and try to generate every variation of a loop
    #This will then pass the set of instructions into foppy to simulate it, and generate a list of possibilities
    #If a result is found we then pass the results to pretty_print to make things look nice and printable
    #Since we are generating the list of instructions first we miss the opportunity to go through memory/register calls and jumps
    #This could be circumvented in the future, by simulating every instruction. Problem is we would then be simulating
    #1000s of useless iterations and this can be costly. 
    #but we would be able to avoid the instructions/revisions that we would never hit
    #For now this works well enough to get by
    def loop(self,cur,inst,jumps, stack):
        sym_call = 0
        while len(cur) < self.num and self.func_counter < self.fa:

            if inst not in self.elf.instructions_dict: #for some reason we are at an instruction that does not exist
                inst-=1
                return
                #if inst not in elf.instructions_dict: #still not here, we are off somehow
                #    return
                #elif elf.instructions_dict[inst].mnemonic[:4] != "lock": 
                    #interesting case to handle within arena_get2.part.0
                    #possible jump into the middle of an instruction
                    #appears to be testing to see if to use the lock version or not
                    #   97060:       74 01                   je     97063 <arena_get2.part.0+0x1e3>
                    #   97062:       f0 48 0f b1 0d dd 92    lock cmpxchg %rcx,0x1592dd(%rip)        # 1f0348 <narenas>
                    #   97069:       15 00 
                #    return
            
            inst = self.elf.instructions_dict[inst]

            cur.append(inst)

            if inst.mnemonic == 'ret' or (inst.mnemonic == 'call' and inst.op_str[0] != '0'):
                #check for a ret and we are at the end of the call chain, time to call foppy
                #check for a ret, while at a depth, ie already in a call, if so we will pop and return
                if len(stack) == 0 or inst.mnemonic == 'call':
                    #print(hex(cur[0].address))
                    #results = foppy.foppy(cur, tj, nr, nw, ns, kv, c, lm, m)
                    self.cpu.reset(cur, kv)
                    #p = pickle.dumps(cpu)
                    #with open(f'files/[cur[0].address','wb') as w:
                    #    w.write(p)
                    results = foppy(self.cpu)
                    self.func_counter += 1
                    self.counterr+=1
                    #gabage collect every so often
                    if self.counterr%200 == 0:
                        gc.collect()
                    #there are no results so continue
                    if results == {}:
                        return
                    library, cur_chunk = self.current_chunk(cur[0].address)
                    offset = cur[0].address - cur_chunk
                    self.counter += pretty_print(library,offset,results, self.cpu)
                    return
                inst = stack.pop()
                continue
            elif inst.mnemonic == 'ss_inst': #simulation can't handle shadow stack emulation, could just treat it as a nop but for now let's try to avoid it to not corrupt the stack
                return
            elif self.avoids and inst.mnemonic == 'syscall': #ignore syscall if parameter set
                return
            elif inst.mnemonic[0] == 'j' and inst.mnemonic != 'jmp' or inst.mnemonic[:7] == 'notrack':
                if inst.op_str[0] != '0':
                    #this is a register or memory
                    return
                if inst.mnemonic[:2] == 'jr':
                    #this is a jump register if rcx instruction, currently our jump modifications cannot handle this
                    return
                #currently do not handle indirect jumps
                if inst.mnemonic[:7] == 'notrack':
                    return
                if int(inst.op_str,16) not in jumps: #check to make sure we haven't hit it yet
                    jumps.append(inst.address) #add to the list to check if we hit again
                    #if we don't save the real original then we accidently overwrite the instruction that is in the instruction list, meaning every next function that hits this instruction is now broken
                    new = deepcopy(cur[-1])
                    orig = cur[-1]
                    cur[-1] = new

                    #converts the jump
                    self.convert_jumps(cur[-1])
                    #we recurse into the function with the modified jump
                    a = self.loop(deepcopy(cur),inst.address+inst.size(),jumps[:],stack[:]) #handle for not taking the jump

                    #reset for taking the original jump
                    cur[-1] = orig
                    inst = int(inst.op_str,16)
                    continue
                    #handle not taking the jump
                else: #already went down this path
                    return 
            elif inst.mnemonic in ['jmp', 'call', 'bnd jmp']: #handle a regular jump or call
                if inst.op_str[0] != '0':
                    #this is a register or memory jmp/call
                    #
                    if inst.mnemonic == 'call':
                        sym_call = 1
                    #HANDLE register calls here, symbolic calls would allow for more possible gadgets
                    #Variable for the looping here should work fine
                    #CPU variable for if symbolic is found, to fend off checks later on
                    #set pc to register value, only if it is symbolic, if deterministic end there as the route is dead
                    #
                    return
                if inst.mnemonic == "call": #if call, append the returning instruction to the 'stack' so we can return to after next return
                    stack.append(inst.address+inst.size())
                
                #we are now jumping/calling the next instruction referenced
                inst = int(inst.op_str,16)
                continue

            #this is a regular instruction so we don't need to do anything
            inst = inst.address+inst.size()

    def current_chunk(self, address):
        for x in reversed(self.libraries):
            if self.libraries[x] < address:
                return (x, self.libraries[x])

    #function used to find a dispatcher gadget
    def find_dispatcher(self):
        first = 0
        elf = self.core
        for x in range(len(elf.instructions)):
            y = elf.instructions[x]
            #find all instructions that are calls to registers or memory references from registers
            if y.mnemonic == 'call' and ((y.op_str[0] == 'r' or '[r' in y.op_str) and '[rip' not in y.op_str):
                found = 0
                #determine if an add or sub is before the call, we are hoping for an incrementing loop esc structure
                for z in range(x-10, x):
                    if z < 0:
                        break
                    m = elf.instructions[z]
                    if m.mnemonic == 'add' or m.mnemonic == 'sub':
                        found = 1
                        break
                found = 1

                #check for an add or sub after as well as look for a cmp after
                for z in range(x, x+10):
                    if z >= len(elf.instructions) or found == 2:
                        break

                    m = elf.instructions[z].mnemonic
                    if not found and (m == 'add' or m == 'sub'):
                        found = 1
                    if m == 'cmp':
                        for w in range(z,z+10):
                            if w > len(elf.instructions):
                                break

                            m = elf.instructions[w]
                            if m.mnemonic[0] == 'j':
                                o = m.op_str
                                if o[:2] == '0x':
                                    if int(o,16) <= y.address and int(o,16) >= y.address-20:
                                        if found:
                                            address = y.address 
                                            library, cur_chunk = self.current_chunk(address)
                                            offset = address - cur_chunk
                                            y.address = offset
                                            print(f"{library}: {hex(offset)} \"{y.mnemonic} {y.op_str}\"")
                                            break
                        #we only want the first instance of the compare if it doesn't work we are done
                        break

#class to relate to every instruction, holds information about each instruction
class Instruction:
    def __init__(self, instruction, inserted):
        self.mnemonic = instruction.mnemonic
        self.op_str = instruction.op_str
        self.address = instruction.address
        self.bytes = instruction.bytes
        self.size = lambda : len(self.bytes)

    def __str__(self):
        return str([self.mnemonic, self.op_str, hex(self.address), self.bytes.hex()])

#class Elf:
class ELFY:
    def __init__(self, core):

        #self.file = open(filename,'rb')
        self.elffile = ELFFile(BytesIO(core))
        self.instructions = []
        self.instructions_dict = {}
        md = Cs(CS_ARCH_X86, CS_MODE_64)

        #iterate through the sections to get the executable areas
        for section in self.elffile.iter_sections():
            header = section.header
            if header.sh_flags & 4 == 4:
                data = section.data()
                addr = header.sh_addr
                size = 0
                while size < len(data):
                    for instruction in md.disasm(data[size:], addr+size):
                        instruction = Instruction(instruction,0)
                        self.instructions.append(instruction)
                        self.instructions_dict[instruction.address] = instruction
                        #capstone doesn't recognize bti yet

                        size += instruction.size()
                    size += 1
        #self.file.close()
