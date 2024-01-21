#https://wiki.osdev.org/ELF_Tutorial#Relocation_Sections
#32 bit but good explanations of sections and structures/uses
#from elftools.elf.elffile import ELFFile
#from capstone import *
#import capstone
#from keystone import *
#import struct
#from ropper import RopperService
#import operator
#import re
import sys
#import claripy
import argparse
#import z3
#from os import path, SEEK_END, unlink
#import gc
import pwn
#import lief
#import pickle

#load functions used by the program
#sys.path.insert(0,'./pysymemu')
#import foppy
#from cpu import Cpu
#from smtlib import SIMP
from memory import SMemory

from consts import *

#stream to stdout and file depending on parameters
class Stream:
    def __init__(self, stream, size, file = False):
        self.stream = stream
        self.file = file
        self.size = size
        if file != False:
            self.send = open(file,'w')
        self.encoding = stream.encoding
        self.start = 0

    def write(self, data):
        if self.size != -1 and len(data) > self.size:
            self.stream.write(data[:self.size] + '...')
        else:
            self.stream.write(data)
        if self.file:
            self.send.write(data)

    def flush(self):
        self.stream.flush()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='A test description')
    #parser.add_argument("-lc", "--libc", help="Target file to find gadgets in", required=True)
    #parser.add_argument("-ld", "--ld", help="Target file to find gadgets in", required=True)
    parser.add_argument("-c", "--core", help="Corefile to load data from", required=True)
    parser.add_argument("-o", "--outfile", help="Target to write gadgets to", default=False)
    parser.add_argument("-q", "--quiet", help="Does not display anything to stdout, -o (--outfile) required", action="store_true", default=False)
    parser.add_argument("-wc", "--wordcount", help="Max number of characters to display in stdout. Typically shortens constraint and result output, set to -1 for all output.", default=100, type=int)
    parser.add_argument("-gd", "--gadgetdepth", help="Max number of instructions to search through functions for, default=15", default=15, type=int)
    parser.add_argument("-nc", "--noconstraints", help="Only display gadgets that have no listed constraints", default=False, action="store_true")
    parser.add_argument("-ar", "--avoidreg", help="Only display gadgets that do not touch the supplied registers, can be a comma sepperated list. Ex: Rax,RDi,RSI", default=False)
    parser.add_argument("-tr", "--targetreg", help="Only display gadgets that contain one of the listed regs, can be a comma seperated list of registers. Ex: RAX,rbx,Rdx", default=False)
    parser.add_argument("-rt", "--requiretarget", help="Require that the listed gadgets have all of the listed regs from targetreg, targetreg must be present to use", default=False, action="store_true")
    parser.add_argument("-rv", "--regvalue", help="Only display gadgets containing one of the listed regs with the listed value, Reg and Value are colon seperated and must be in decimal, can be a list of reg/values comma seperated. Ex: RAX:0,rdi:1,Rsi:rBx", default=False)
    parser.add_argument("-kv", "--knownvalue", help="Set values to registers to check for useful gadgets, can be a list of registers comma seperated. Reg and Value are colon seperated and must be decimal", default=False)
    parser.add_argument("-tj", "--truejumps", help="Only take jumps that are guarenteed to be true, ie no jump constraints", default=False, action="store_true")
    parser.add_argument("-nw", "--nowrite", help="Do not allow any gadgets that have write constraints", default=False, action="store_true")
    parser.add_argument("-nr", "--noread", help="Do not allow any gadgets that have read constraints", default=False, action="store_true")
    parser.add_argument("-ns", "--noseg", help="Do not allow any gadgets that reference a segment", default=False, action="store_true")
    parser.add_argument("-m32", "--m32", help="Treat all regvalue comparisons as 32 bit", default=False, action="store_true")
    parser.add_argument("-fd", "--finddispatcher", help="Ignores everything else and tries to find all dispatchers in the file", default=False, action="store_true")
    parser.add_argument("-cy", "--cycles", help="Max number of instruction to step through when executing, default gadgetdepth*2, used to avoid infinite loops in the symbolic executer", default=False) 
    parser.add_argument("-lm", "--loopmax", help="Max number of times an address can be hit, used to avoid infinite loops, default is 20", default=20, type=int)
    parser.add_argument("-as", "--avoidsyscall", help="Set to avoid syscall instructions", default=False, action="store_true")
    parser.add_argument("-fa", "--functionattempts", help="Set the number of times to check a function, useful for large gadget depths where there are thousands of possible branching possiblities, default=15", default=15)
    args = parser.parse_args()
    
    assert args.quiet == False or (args.quiet and args.outfile != False),"Quiet cannot be ran without an outfile"

    #l = pwn.Corefile('./arm_core')
    #f = open("./arm_core", 'rb')
    #l = ELFFile(f)
    #for x in l.iter_sections():
    #    print(x.header)
        #if x.header['p_flags'] == 5:
        #    print(x.data())
    #l = lief.parse("./arm_core")
    #print(l)
    #print(dir(l))
    #for x in l.segments:
    #    print(x.from_raw()[:100],x)
    #    #print(dir(x))

    #load the instructions
    #p = pwn.process([args.ld,'./a.out'],env={'LD_PRELOAD':args.libc}) 
    #pwn.gdb.attach(p)
    #p.interactive()
    #l = p.corefile
    #p.close()
    #l = pwn.Corefile('./arm_core')
    #l = pwn.Corefile('./core')
    l = pwn.Corefile(args.core)

    arch = l.arch
    print(arch)
    assert(arch in ['amd64','aarch64'])

    if arch == 'amd64':
        from x64.cpu import Cpu
        from x64.x64_util import util, ELFY
        fs_base = l.registers["fs_base"]
    elif arch == 'aarch64':
        from arm.cpu import Cpu
        from arm.arm_util import util, ELFY

    #libc = ELFY(args.libc)
    #ld   = ELFY(args.ld)

    mappings = []
    libraries = {}
    libc_base = 0
    ld_base   = 0
    libc_found = 0
    libc_first = 0
    libc_second = 0
    exec_pages_found = 0
    for x in l.mappings:
        #print(x, x.flags)
        if x.name in ['[stack]', '[vdso]']:
            continue
        print(x, x.name)

        #keep track of the base mappings for libraries and binaries.
        if x.name:
            #grab the library or binary name only
            #do not care about the path for now
            tmp_name = x.name.split('/')[-1]
            if tmp_name not in libraries:
                tmp_dict = {}
                libraries[tmp_name] = x.address
                
        #make exececutable pages writeable for modifications that occur within the tool
        if x.flags&1:
            if len(x.data) > 0:
                exec_pages_found = 1
            x.flags += 2

        if x.size == 0:
            continue

        t = [x.address,x.size,x.flags,x.data]
        mappings.append(t)

    if exec_pages_found == 0:
        print("No executable pages/data found\nCheck that the core file contains the executable pages\nIf needed change the core_file permissions, info: `man core`") 
        exit(0)

    core = ELFY(l.data)
    l.close()

    util = util(core)
    util.mappings = mappings
    util.libraries = libraries

    #set the logging
    if args.quiet:
        sys.stdout.close()
        sys.stdout = open(args.outfile,'w')
    else:
        sys.stdout = Stream(sys.stdout, args.wordcount, args.outfile)

    #set the other arguments
    fd = args.finddispatcher
    if fd:
        util.find_dispatcher()
        exit(0)
    util.num = args.gadgetdepth
    util.fa = args.functionattempts
    if not args.cycles:
        c = args.gadgetdepth*2
    util.avoids = args.avoidsyscall
    nc = args.noconstraints
    tj = args.truejumps
    nr = args.noread
    nw = args.nowrite
    ns = args.noseg
    if nc:
        tj = 1
        nr = 1
        nw = 1
        ns = 1
    m32 = args.m32
    lm  = args.loopmax
    if args.avoidreg:
        ar = args.avoidreg.split(',')
    if args.targetreg:
        tr = args.targetreg.split(',')
        rt = args.requiretarget
    elif args.requiretarget:
        assert args.requiretarget and args.targetreg,"Require Target cannot be used without a Target Register"
    if args.regvalue:
        rv = args.regvalue.split(',')
    if args.knownvalue:
        kv = {}
        v = args.knownvalue.split(',')
        for x in v:
            x = x.split(':')
            try:
                v = int(x[1],16)
            except:
                v = int(x[1])
            if v < 0:
                if m32:
                    v += 2<<31
                else:
                    v += 2<<64
            kv[x[0].upper()] = v


    #Initialize the cpu
    mem = SMemory(64, 12)
    if arch == 'amd64':
        util.cpu = Cpu(mem, fs_base, arch, tj, nr, nw, ns, c, lm, nc)
        util.cpu.registers = iregisters
    else:
        util.cpu = Cpu(mem, arch, tj, nr, nw, ns, c, lm, nc)
        util.cpu.registers = aregisters

    util.cpu.initialize(mappings)

    def current_chunk(address):
        for x in libraries:
            if libraries[x] < address:
                return libraries[x]

    matching_inst = {"amd64":"endbr64","aarch64":"bti"}[arch]

    #loop through all instructions and jump into our loop if we need to
    for x in util.core.instructions:
        if x.mnemonic == matching_inst:
            #util.cpu.entry = current_chunk(x.address)
            util.func_counter = 0
            util.loop([],x.address,[], [])

    print(f"Total Gadgets: {util.counter}")
