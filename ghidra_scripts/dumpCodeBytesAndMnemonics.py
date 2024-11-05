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
import json
from ghidra.program.model.listing import Instruction
from ghidra.program.model.address import Address
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.lang import OperandType

cp = currentProgram()
# Get required objects from ghidra's java hell
funcs = cp.getFunctionManager().getFunctions(True)
addr = cp.getAddressFactory()
mem = cp.getMemory()
def process_instruction(instruction):
    code_bytes = bytes(map(lambda b: b &0xff, instruction.getBytes()))
    return code_bytes
def process_function(func):
    # Perform adress masking
    # Get first instruction and iterate
    code_bytes = []
    instruction = getFirstInstruction(func)
    assembly = ""
    while instruction is not None:
        if(instruction.getMaxAddress() > func.getBody().getMaxAddress()):
            break
        code_bytes.extend(process_instruction(instruction))
        assembly += "\n" + instruction.toString()
        instruction = instruction.getNext()
    result = {"program": cp.getName(), "func_name": func.getName(), "addr": func.getBody().getMinAddress().toString(), "mnemonic": assembly, "code_bytes": "".join(["{:02x}".format(x) for x in code_bytes])}
    return result
f = open("/home/hsaias/LLMExp/output.json","r+")
data = f.read()
f.close()
f = open("/home/hsaias/LLMExp/output.json", "w")
funcaddr = askAddress("Function address","Enter Function address")
fm = cp.getFunctionManager()
func = fm.getFunctionAt(funcaddr)
results = process_function(func)
if(data == ''):
    # Empty file
    f.write(json.dumps([results]))
else:
    data = json.loads(data)
    data.append(results)
    f.write(json.dumps(data))

f.close()

