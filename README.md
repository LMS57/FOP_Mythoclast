## FOP_Mythoclast

FOP_Mythoclast is a tool designed to identify Function-Oriented Programming (FOP) gadgets within ARM and x86-64 binaries. It is based on the research presented in the dissertation "Bypassing Modern CPU Protections With Function-Oriented Programming" (https://scholar.dsu.edu/theses/433/).

### Dependencies:

The tool utilizes the following required libraries, which can be installed via pip3:

    z3_solver
    capstone
    pwntools
    pyelftools

### Built Upon:

FOP_Mythoclast is built upon the pysymemu framework, which provides symbolic execution capabilities.

### Installation:

To install the required dependencies, use pip3:

``` bash

pip3 install z3-solver capstone pwntools pyelftools

```

### Usage:

``` bash

usage: fm.py [-h] -c CORE [-o OUTFILE] [-q] [-wc WORDCOUNT] [-gd GADGETDEPTH] [-nc] [-ar AVOIDREG] [-tr TARGETREG]
             [-rt] [-rv REGVALUE] [-kv KNOWNVALUE] [-tj] [-nw] [-nr] [-ns] [-m32] [-fd] [-cy CYCLES] [-lm LOOPMAX]
             [-as] [-fa FUNCTIONATTEMPTS]
```

### Options:

    -h, --help: Display help message and exit.
    -c CORE, --core CORE: Core file to load data from.
    -o OUTFILE, --outfile OUTFILE: Target to write gadgets to.
    -q, --quiet: Does not display anything to stdout (requires -o).
    -wc WORDCOUNT, --wordcount WORDCOUNT: Max number of characters to display in stdout.
    -gd GADGETDEPTH, --gadgetdepth GADGETDEPTH: Max number of instructions to search through functions for (default=15).
    -nc, --noconstraints: Only display gadgets that have no listed constraints.
    -ar AVOIDREG, --avoidreg AVOIDREG: Only display gadgets that do not touch the supplied registers.
    -tr TARGETREG, --targetreg TARGETREG: Only display gadgets that contain one of the listed registers.
    -rt, --requiretarget: Require that the listed gadgets have all of the listed registers from targetreg.
    -rv REGVALUE, --regvalue REGVALUE: Only display gadgets containing one of the listed registers with the listed value.
    -kv KNOWNVALUE, --knownvalue KNOWNVALUE: Set values to registers to check for useful gadgets.
    -tj, --truejumps: Only take jumps that are guaranteed to be true.
    -nw, --nowrite: Do not allow any gadgets that have write constraints.
    -nr, --noread: Do not allow any gadgets that have read constraints.
    -ns, --noseg: Do not allow any gadgets that reference a segment.
    -m32, --m32: Treat all register value comparisons as 32-bit.
    -fd, --finddispatcher: Ignore other options and attempt to find all dispatchers in the file.
    -cy CYCLES, --cycles CYCLES: Max number of instructions to step through when executing.
    -lm LOOPMAX, --loopmax LOOPMAX: Max number of times an address can be hit.
    -as, --avoidsyscall: Set to avoid syscall instructions.
    -fa FUNCTIONATTEMPTS, --functionattempts FUNCTIONATTEMPTS: Set the number of times to check a function.

### Known Issues/Limitations:

The tool is currently single-threaded and may not perform optimally for large binaries or deep searches.
Memory management may not be optimized, leading to potential performance issues with large inputs.

### Platform Compatibility:
The tool is designed to run in any Python 3 supported environment but is optimized for Linux-based core files currently.

### Requirements:

The core file requires the data of the executable area to be included. Generate coredumps by running:

``` bash

echo 0x37 > /proc/self/coredump_filter

```

Capstone engine version 4.0 or higher is required to include necessary instructions. However, note that there may be Capstone bugs impacting functionality.

### Additional Information:
For more details and research background, refer to the dissertation linked above. The tool is designed to assist in the identification of FOP gadgets for research and security purposes.
