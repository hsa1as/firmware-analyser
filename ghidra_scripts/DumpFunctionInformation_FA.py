# Dump function information for fuzzy hashing with firmware-analyser
#@author "R Sai Ashwin"
#@category _NEW_
#@keybinding
#@menupath
#@toolbar

##################
# Code for
# Ghidrathon
##################

import sqlite3
import os
import ssdeep
import time
from ghidra.program.model.listing import Instruction
from ghidra.program.model.address import Address
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.lang import OperandType

# Set FIRMAL_DIR in env for output file location
if 'FIRMAL_DIR' not in os.environ:
	print("ERROR: env FIRMAL_DIR not set. Set FIRMAL_DIR for output directory")
	exit(-1)

op_path = os.environ['FIRMAL_DIR']
if op_path[-1] != "/":
	op_path += "/"

timestr = time.strftime("%Y%m%d:%H%M%S")

hashdb = sqlite3.connect(op_path + "hash.db")
cur = hashdb.cursor()
res = cur.execute("SELECT name FROM sqlite_master WHERE name='hashdump'")
if(res.fetchone() is None):
    cur.execute("CREATE TABLE hashdump(size, progname, progpath, funcname, vaddr, fileoff, hash)")

cp = currentProgram()
ctx = {}
ctx["ARCH"] = cp.getLanguage().toString().split("/")[0]
ctx["BITS"] = cp.getLanguage().toString().split("/")[2]
ctx["DBPATH"] = op_path+"hash.db"
ctx["TIME"] = timestr
ctx["FILEPATH"] = cp.getExecutablePath()

# Let script be run on headless mode with -noanalyse flag
# Set minimum number of analysis options
opts = getCurrentAnalysisOptionsAndValues(cp)
for x in opts:
    if(opts[x] == 'true'):
        opts[x] = 'false'
opts['Disassemble Entry Points.Respect Execute Flag'] = 'true'
setAnalysisOptions(cp, opts)
analyze(cp)

# Get required objects from ghidra's java hell
funcs = cp.getFunctionManager().getFunctions(True)
addr = cp.getAddressFactory()
mem = cp.getMemory()

def mask_ARM(insn):
    res = []
    mask = 0
    numOp = insn.getNumOperands()
    for i in range(numOp):
        mask = mask | int(insn.getPrototype().getOperandValueMask(i).toString(), 16)
    BITS = int(ctx["BITS"])
    mask = ( 1 << BITS ) - 1 - mask
    insn_int = insn.getUnsignedInt(0)
    insn_int = insn_int & mask
    while(insn_int > 0):
        res.append(insn_int & 0xFF)
        insn_int = insn_int >> 8

    return res

def mask_ARM_THUMB(insn):
    res = []
    mask = 0
    numOp = insn.getNumOperands()
    for i in range(numOp):
        mask = mask | int(insn.getPrototype().getOperandValueMask(i).toString(), 16)
    BITS = int(ctx["BITS"])
    mask = ( 1 << BITS ) - 1 - mask
    insn_int = insn.getUnsignedShort(0)
    insn_int = insn_int & mask

    while(insn_int > 0):
        res.append(insn_int & 0xFF)
        insn_int = insn_int >> 8

    return res

def process_instruction(instruction):
    code_bytes = bytes(map(lambda b: b &0xff, instruction.getBytes()))
    # Architecture specific code follows.
    # Register and memory masking is implemented for ARM only
    match ctx["ARCH"]:
        case "ARM":
            # Deconstructing arm is easier than other archs i hope

            # 4 byte instruction:
            if(len(code_bytes) == 4):
                code_bytes = mask_ARM(instruction)

            # 2 Byte instruction (thumb)
            if(len(code_bytes) == 2):
                code_bytes = mask_ARM_THUMB(instruction)
        case _:
            print("Unknown Architecture for process_instruction. Falling back to no masking")

    return code_bytes
def process_function(func, cur):
    # Perform adress masking
    # Get first instruction and iterate
    code_bytes = []
    instruction = getFirstInstruction(func)
    while instruction is not None:
        if(instruction.getMaxAddress() > func.getBody().getMaxAddress()):
            break
        code_bytes.extend(process_instruction(instruction))
        instruction = instruction.getNext()

    result = {}
    result["name"] = func.getName()
    entrypoint = func.getEntryPoint()
    result["vaddr"] = "0x" + entrypoint.toString()
    result["fileoffset"] = str(mem.getAddressSourceInfo(entrypoint).getFileOffset())
# For size to work, ghidra analysis should be run
# In case ghidra did not run analysis, the returned size is always 1
    result["size"] = str(func.getBody().getNumAddresses())
# Get function bytes out of a stupid java object
    result["hash"] = ssdeep.hash(bytes(code_bytes))
    row = (result['size'], cp.getName(), cp.getExecutablePath(), result['name'], result['vaddr'], result['fileoffset'], result['hash'])
    return row

data = []
for func in funcs:
    if(func.isThunk()):
        continue
    data.append(process_function(func, cur))
    if(len(data) > 1000):
        cur.executemany("INSERT INTO hashdump VALUES(?, ?, ?, ?, ?, ?, ?)", data)
        data.clear()


cur.executemany("INSERT INTO hashdump VALUES(?, ?, ?, ?, ?, ?, ?)", data)
data.clear()
hashdb.commit()
hashdb.close()

