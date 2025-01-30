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
import argparse


'''
# Set FIRMAL_DIR in env for output file location
if 'FIRMAL_DIR' not in os.environ:
	print("ERROR: env FIRMAL_DIR not set. Set FIRMAL_DIR for output directory")
	exit(-1)

# Database save path from environ
op_path = os.environ['FIRMAL_DIR']
if op_path[-1] != "/":
	op_path += "/"
'''

# Setup argument parsing
parser = argparse.ArgumentParser(prog='FiVB',
                                 description='Extract and compare functions in a given file using ghidra',
                                 epilog="Optionally include *.vuln file for each file added to a database, for information on vulnerable functions.\n\
                                        The *.vuln file should contain a list of addresses, one per line, of vulnerable functions in the file, followed by \
                                        a whitespace and an optional description")
parser.add_argument('-d', '--db', help='Path to sqlite3 db file', required=False)
parser.add_argument('-f', '--filenames', help='Files to be analysed', required=True, action='extend', nargs="+")
parser.add_argument('-a', '--arch', help='Architecture of the file to be analysed, represented as a ghidra language string, defaults to ARM:LE:32:Cortex', default="ARM:LE:32:Cortex")
parser.add_argument('-b', '--build', help='Set if blocks need to be added to the database', action='store_false')
parser.add_argument('-fn', '--func_name', help='Name of the function to be analysed', required=False)
parser.add_argument('-t', '--threshold', help='Threshold for fuzzy hashing. Defaults to a difference of 10', required=False)

# Parse arguments
args = vars(parser.parse_args())
db_path = args['db']
lang = args['arch']
matching = args['build']
files = args["filenames"]
func_name = args["func_name"]
threshold = args["threshold"]

print("Decompiling with language = " + lang)

# Parser checks
if(func_name is not None and len(files) > 1):
    parser.error("func_name can only be specified for a single file")
if(func_name is not None and not matching):
    parser.error("func_name can only be specified when matching is being performed")
if(threshold is not None and not matching):
    parser.error("threshold can only be specified when matching is being performed")

if(matching):
    threshold = 10


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Get conn to db and create table if it doesn't already exist
hashdb = sqlite3.connect(db_path)
cur = hashdb.cursor()
res = cur.execute("SELECT name FROM sqlite_master WHERE name='hashdump'")
if(res.fetchone() is None):
    cur.execute("CREATE TABLE hashdump(size, progname, progpath, funcname, vaddr, fileoff, hash, vulnerable, vuln_desc)")

# Get Jpype to ghidra
pyhidra.start()
import ghidra
from ghidra.app.util.headless import HeadlessAnalyzer
from ghidra.base.project import GhidraProject
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor
from java.lang import String


for filename in files:
    vulns = {}
    # Check if we have a list of vulnerable functions for this file
    if((not matching) and os.path.isfile(filename + ".vuln")):
        # We expect file with an address on each line, followed by a whitespace and an optional description
        with open(filename + ".vuln", "r") as f:
            for line in f:
                parts = line.split(" ", 1)
                vulns[int(parts[0], 16)] = parts[1]

    # Open program
    with pyhidra.open_program(filename,project_location=None,project_name=None,
                              analyze=False,
                              language=lang) as flat_api: # ARM:LE:32:Cortex
        cp = flat_api.getCurrentProgram()
        blockModel = BasicBlockModel(cp)
        monitor = ConsoleTaskMonitor()

        ctx = {}
        ctx["ARCH"] = cp.getLanguage().toString().split("/")[0]
        ctx["BITS"] = cp.getLanguage().toString().split("/")[2]
        ctx["DBPATH"] = db_path
        ctx["FILEPATH"] = cp.getExecutablePath()

        # Set minimum number of analysis options
        #from ghidra.app.script.GhidraScript import getCurrentAnalysisOptionsAndValues
        #opts = getCurrentAnalysisOptionsAndValues(cp)
        #for x in opts:
        #    if(opts[x] == 'true'):
        #        opts[x] = 'false'
        #opts['Disassemble Entry Points.Respect Execute Flag'] = 'true'
        #setAnalysisOptions(cp, opts)
        flat_api.analyze(cp)

        # Get required objects from ghidra
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
            code_bytes_instr = bytes(map(lambda b: b &0xff, instruction.getBytes()))
            # Architecture specific code follows.
            # Register and memory masking is implemented for ARM only
            if(ctx["ARCH"] == "ARM" or ctx["ARCH"] == None):

                # 4 byte instruction:
                if(len(code_bytes_instr) == 4):
                    code_bytes = mask_ARM(instruction)

                # 2 Byte instruction (thumb)
                if(len(code_bytes_instr) == 2):
                    code_bytes = mask_ARM_THUMB(instruction)
            else:
                print("Unknown Architecture for process_instruction. Falling back to no masking")

            return code_bytes
        def process_function(func, cur):
            # Perform adress masking
            # Get first instruction and iterate
            code_bytes = []
            instruction = flat_api.getFirstInstruction(func)

            while instruction is not None:
                if(int(instruction.getMaxAddress().toString(), 16) > int(func.getBody().getMaxAddress().toString(), 16)):
                    break
                code_bytes.extend(process_instruction(instruction))
                instruction = instruction.getNext()

            # Construct graph from BBs
            # Dictionary key is the address of the block, and the value is a tuple
            # (Destinations: List[int], FlowType: String, hash: String)
            bbs = {}
            curBlocks = blockModel.getCodeBlocksContaining(func.getBody(), monitor)
            while curBlocks.hasNext():
                bb = curBlocks.next()
                code_bytes_bb = []
                instruction = flat_api.getInstructionAt(bb.getFirstStartAddress())
                while(instruction.getMaxAddress() <= bb.getMaxAddress()):
                    code_bytes_bb.extend(process_instruction(instruction))
                    if(instruction.getMaxAddress() == bb.getMaxAddress()):
                        break
                    instruction = instruction.getNext()
                dests = bb.getDestinations(monitor)
                bbs[int(bb.getFirstStartAddress().toString(), 16)] = (
                    [int(x, 16) for x in [dests.next().getDestinationBlock().getFirstStartAddress().toString() for i in range(bb.getNumDestinations(monitor))]],
                    bb.getFlowType().toString(),
                    ssdeep.hash(bytes(code_bytes_bb))
                )


            result = {}
            result["name"] = func.getName()
            result["hash"] = tlsh.hash(bytes(code_bytes))
            entrypoint = func.getEntryPoint()
            result["vaddr"] = "0x" + entrypoint.toString()
            result["fileoffset"] = str(mem.getAddressSourceInfo(entrypoint).getFileOffset())
            # For size to work, ghidra analysis should be run
            # In case ghidra did not run analysis, the returned size is always 1
            result["size"] = str(func.getBody().getNumAddresses())
            # Get function bytes out of java object
            result["vulnerable"] = True if int(entrypoint.toString(), 16) in vulns else False
            result["vuln_desc"] = vulns.get(int(entrypoint.toString(), 16), "")
            row = (result['size'], cp.getName(), cp.getExecutablePath(), result['name'], result['vaddr'],
                   result['fileoffset'], result['hash'], result["vulnerable"], result["vuln_desc"])
            return row

        funcs = cp.getFunctionManager().getFunctions(True)
        if(matching):
            func = None
            while(funcs.hasNext()):
                func = funcs.next()
                if(func.isThunk()):
                    continue
                if(func.getName() == func_name):
                    break
            if(func is None):
                print("Function not found")
                exit(-1)
            row = process_function(func, cur)
            res = cur.execute("SELECT * FROM hashdump")
            db_func = res.fetchone()
            while db_func:
                if(db_func[6] == 'TNULL'):
                    db_func = res.fetchone()
                    continue
                match = None
                try:
                    match = tlsh.diffxlen(row[6], db_func[6])
                except:
                    db_func = res.fetchone()
                    continue
                if(db_func[6] == row[6] or (match is not None and match <= threshold)):
                    print("{bcolors.HEADER}Match found for function: " + func_name + " in " + row[2] + " with " + db_func[3] + " in " + db_func[2] + "{bcolors.ENDC}")
                    print("Matches with a match distance of " + str(match))
                    if(db_func[-2]):
                        print("{bcolors.WARNING}Function " + func_name + " may be vulnearble{bcolors.ENDC}")
                        print("{bcolors.WARNING}Vulnerability description: " + db_func[-1] + "{bcolors.ENDC}")
                db_func = res.fetchone()




        if(not matching):
            data = []
            for func in funcs:
                if(func.isThunk()):
                    continue
                # We are building the database, so update data, and insert if required
                data.append(process_function(func, cur))
                if(len(data) > 1000):
                    cur.executemany("INSERT INTO hashdump VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)", data)
                    data.clear()

            # Flush remaining entries in data
            cur.executemany("INSERT INTO hashdump VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)", data)
            data.clear()
            hashdb.commit()

hashdb.close()

