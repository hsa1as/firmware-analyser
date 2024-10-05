# Dump function information for fuzzy hashing with firmware-analyser
#@author "R Sai Ashwin"
#@category Custom Scripts
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
import pyhidra
import sys
import tlsh
# Get Jpype to ghidra
pyhidra.start()
import ghidra
from ghidra.app.util.headless import HeadlessAnalyzer
from ghidra.base.project import GhidraProject
from java.lang import String

# Set FIRMAL_DIR in env for output file location
if 'FIRMAL_DIR' not in os.environ:
	print("ERROR: env FIRMAL_DIR not set. Set FIRMAL_DIR for output directory")
	exit(-1)

# Database save path from environ
op_path = os.environ['FIRMAL_DIR']
if op_path[-1] != "/":
	op_path += "/"

# Get conn to db and create table if it doesn't already exist
hashdb = sqlite3.connect(op_path + "tslh_hash.db")
cur = hashdb.cursor()
res = cur.execute("SELECT name FROM sqlite_master WHERE name='hashdump'")
if(res.fetchone() is None):
    cur.execute("CREATE TABLE hashdump(size, progname, progpath, funcname, vaddr, fileoff, hash)")
files = sys.argv[1:]
for filename in files:
# Open program
    with pyhidra.open_program(filename,project_location=None,project_name=None,
                              analyze=False,
                              language=None) as flat_api: # ARM:LE:32:Cortex
        cp = flat_api.getCurrentProgram()
        ctx = {}
        ctx["ARCH"] = None #cp.getLanguage().toString().split("/")[0]
        ctx["BITS"] = cp.getLanguage().toString().split("/")[2]
        ctx["DBPATH"] = op_path+"hash.db"
        ctx["FILEPATH"] = cp.getExecutablePath()
# Let script be run on headless mode with -noanalyse flag
# Set minimum number of analysis options
        #from ghidra.app.script.GhidraScript import getCurrentAnalysisOptionsAndValues
        #opts = getCurrentAnalysisOptionsAndValues(cp)
        #for x in opts:
        #    if(opts[x] == 'true'):
        #        opts[x] = 'false'
        #opts['Disassemble Entry Points.Respect Execute Flag'] = 'true'
        #setAnalysisOptions(cp, opts)
        flat_api.analyze(cp)

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
                case "ARM" | None:
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
            instruction = flat_api.getFirstInstruction(func)
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
            result["hash"] = tlsh.hash(bytes(code_bytes))
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

