import gc
from copy import deepcopy
from consts import *
from funcs import *
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from elftools.elf.elffile import ELFFile
from io import BytesIO

class util():
    def __init__(self, core):
        self.num = 0
        self.fa = False
        self.func_counter = 0
        self.counter = 0
        self.counterr = 0
        self.elf = 0
        self.avoids = False
        self.cpu = 0
        self.core = core
        self.elf = core

    def convert_jumps(self, a):
        
        m = jal1[a.mnemonic.upper()]
        if m == "CBNZ":
            byte = a.bytes[:]
            byte[3] = (byte[3]&(1<<7)) + 0b0110101
            byte[2] = 0
            byte[1] = 0
            byte[0] = (byte[0] & 0x1F) + (1<<5)
        elif m == "CBZ":
            byte = a.bytes[:]
            byte[3] = (byte[3]&(1<<7)) + 0b0110100
            byte[2] = 0
            byte[1] = 0
            byte[0] = (byte[0] & 0x1F) + (1<<5)
        elif m == "TBNZ":
            byte = a.bytes[:]
            byte[3] = (byte[3]&0xfe) + 1
            byte[2] = byte[2]&0xf8
            byte[1] = 0
            byte[0] = (byte[0] & 0x1F) + (1<<5)
        elif m == "TBZ":
            byte = a.bytes[:]
            byte[3] = byte[3]&0xfe
            byte[2] = byte[2]&0xf8
            byte[1] = 0
            byte[0] = (byte[0] & 0x1F) + (1<<5)
        else:
            byte = a.bytes[:]
            byte[0] = 0x20 + jal2[m]
            byte[1] = 0
            byte[2] = 0

        a.bytes = byte
           
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
        while len(cur) < self.num and self.func_counter < self.fa:
            if inst not in self.elf.instructions_dict: #for some reason we are at an instruction that does not exist
                #for x in self.elf.instructions_dict:
                #    print(hex(x))
                #print(self.elf.instructions_dict)
                #print(hex(inst))
                #for x in cur:
                #    print(x)
                raise("instruction/address does not exist")
                return
            
            inst = self.elf.instructions_dict[inst]

            cur.append(inst)

            #check for a ret and we are at the end of the call chain, time to call foppy
            if (inst.mnemonic == 'ret' and len(stack) == 0) or inst.mnemonic in ['blr']:

                #print(hex(cur[0].address))
                self.cpu.reset(cur, kv)
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
            #check for a ret, while at a depth, ie already in a call, if so we will pop and return
            elif inst.mnemonic == 'ret':
                inst = stack.pop()
                continue
            elif inst.mnemonic not in ['b','bti','bic', 'bfxil', 'bit', 'bif', 'bfi', 'bics', 'brk'] and (inst.mnemonic[0] == 'b' or inst.mnemonic in ['cbz', 'cbnz', 'tbnz', 'tbz']):
                #TODO
                if inst.mnemonic in ['br']:
                    return
        
                if inst.mnemonic == "bl": #if call, append the returning instruction to the 'stack' so we can return to after next return
                    stack.append(inst.address+inst.size())
                    inst = int(inst.op_str[1:],16)
                    continue
                #if inst.op_str[0] != '0':

                val = int(inst.op_str.split('#')[-1],16)

                if val not in jumps: #check to make sure we haven't hit it yet
                    #Not a perfect plan but idea is to switch the jump mnemonic and set the condition to jump over a ret no matter the result, or take the ret if it fails
                    #So jne turns into je and jne
                    jumps.append(inst.address) #add to the list to check if we hit again
                    #if we don't save the real original then we accidently overwrite the instruciton that is in the instruction list, meaning every next function that hits this instruction is now broken
                    new = deepcopy(cur[-1])
                    orig = cur[-1]
                    cur[-1] = new

                    #converts the function
                    self.convert_jumps(cur[-1])
                    #we recurse into the function with the modified jump
                    a = self.loop(deepcopy(cur),inst.address+inst.size(),jumps[:],stack[:]) #handle for not taking the jump

                    #reset for taking the original jump
                    cur[-1] = orig
                    inst = val
                    continue
                    #handle not taking the jump
                else: #already went down this path
                    return 
            elif inst.mnemonic == 'b': #handle a regular jump or call
                if inst.op_str[0] != '#':
                    raise("what are you")
                    #this is a register or memory jmp/call
                    return
                
                #we are now jumping/calling the next instruction referenced
                inst = int(inst.op_str[1:],16)
                continue

            #this is a regular instruction so we don't need to do anything
            inst = inst.address+inst.size()

    def current_chunk(self,address):
        for x in reversed(self.libraries):
            if self.libraries[x] < address:
                return (x,self.libraries[x])

    #function used to find a dispatcher gadget
    def find_dispatcher(self):
        first = 0
        elf = self.core
        for x in range(len(elf.instructions)):
            y = elf.instructions[x]
            if y.mnemonic == 'blr' or (y.mnemonic == 'bl' and '[' in y.op_str):
                #check to see if there is a compare
                reg = y.op_str
                found = 0
                for z in range(x, x+20):
                    if z > len(elf.instructions):
                        break
                    w = elf.instructions[z]
                    m = w.mnemonic
                    if m == 'cmp':
                        for a in range(z+1, x+20):
                            #check if a branch is next
                            w = elf.instructions[a]
                            m = w.mnemonic
                            if m[:2] == 'b.' or m in ['TBZ', 'TBNZ', 'CBZ', 'CBNZ']:
                                add = int(w.op_str.split('#')[1],16)
                                #make sure the branch goes to before the branch and link
                                if add <= y.address and add+20 >= y.address:
                                    #right now just check to make sure the reg is set within this range
                                    for v in range(add, w.address, 4):
                                        u = elf.instructions_dict[v]
                                        if u == y:
                                            continue
                                        if reg in u.op_str:
                                            address = y.address
                                            library, cur_chunk = self.current_chunk(address)
                                            offset = address - cur_chunk
                                            y.address = offset
                                            print(f"{library}: {hex(offset)} \"{y.mnemonic} {y.op_str}\"")
                                            found = 1
                                            break
                            if found:
                                break
                    if found:
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

        self.elffile = ELFFile(BytesIO(core))
        self.instructions = []
        self.instructions_dict = {}
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        bad_inst = list(md.disasm(b'\x00\x28\x60\x1e', 0))[0]

        for section in self.elffile.iter_segments():
            header = section.header
            #arm did not dump with section information and only segment
            #I don't think there are any differences but will keep the two different just in case
            if header.p_flags & 4 == 4:
                data = section.data()
                addr = header.p_vaddr
                size = 0
                #This can result in false positivies, during testing it was found that the first mapped areas
                #were always identified as executable in core dumps.
                #This shouldn't be a big deal given that only instructions that begin with the bti instruction
                #should be analyzed
                #This could possibly give false positives for dispatcher gadgets though
                while size < len(data):
                    for instruction in md.disasm(data[size:], addr+size):
                        instruction = Instruction(instruction,0)
                        self.instructions.append(instruction)
                        self.instructions_dict[instruction.address] = instruction
                        #capstone doesn't recognize bti yet
                        if instruction.bytes == b"\x5f\x24\x03\xd5":
                            instruction.mnemonic = 'bti'
                        size += instruction.size()
                    #so slight bug here, if capstone doesn't recognize an instruction. 
                    #This now becomes an empty spot in memory
                    #and will crash the application
                    #to remody this I am going to insert an instruction that the program
                    #does not handle anyways so the program does not crash at least
                    if size < len(data):
                        instruction = Instruction(bad_inst,0)
                        instruction.address = addr+size
                        self.instructions.append(instruction)
                        self.instructions_dict[instruction.address] = instruction
                        size += 4
