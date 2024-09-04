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

cp = currentProgram()
ctx = {}
ctx["ARCH"] = cp.getLanguage().toString().split("/")[0]
ctx["BITS"] = cp.getLanguage().toString().split("/")[2]
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
    mask = int(insn.getPrototype().getInstructionMask().toString(), 16)
    insn_bytes = bytes(map(lambda b: b&0xff, insn.getBytes()))
    insn_int = int.from_bytes(insn_bytes, "big")
    insn_int = insn_int & mask
    while(insn_int > 0):
        res.append(insn_int & 0xFF)
        insn_int = insn_int >> 8
    masked_bytes = [0 for i in range(4-len(res))]
    masked_bytes.extend(res)
    return masked_bytes

def mask_ARM_THUMB(insn):
    res = []
    mask = 0
    mask = int(insn.getPrototype().getInstructionMask().toString(), 16)
    insn_bytes = bytes(map(lambda b: b&0xff, insn.getBytes()))
    insn_int = int.from_bytes(insn_bytes, "big")
    insn_int = insn_int & mask
    while(insn_int > 0):
        res.append(insn_int & 0xFF)
        insn_int = insn_int >> 8
    masked_bytes = [0 for i in range(2-len(res))]
    masked_bytes.extend(res)
    return masked_bytes

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
def process_function(func):
    # Perform adress masking
    # Get first instruction and iterate
    code_bytes = []
    instruction = getFirstInstruction(func)
    while instruction is not None:
        if(instruction.getMaxAddress() > func.getBody().getMaxAddress()):
            break
        code_bytes.extend(process_instruction(instruction))
        instruction = instruction.getNext()

    hash = ssdeep.hash(bytes(code_bytes))
    return (hash, code_bytes)


funcaddr = askAddress("Function address","Enter Function address")
fm = cp.getFunctionManager()
func = fm.getFunctionAt(funcaddr)
hash,code = process_function(func)
print(hash)
print(" ".join(["0x{:02x}".format(x) for x in code]))
