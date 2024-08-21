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

import os

# Set FIRMAL_DIR in env for output file location
if 'FIRMAL_DIR' not in os.environ:
	print("ERROR: env FIRMAL_DIR not set. Set FIRMAL_DIR for output directory")
	exit(-1)

import time
timestr = time.strftime("%Y%m%d:%H%M%S")

op_path = os.environ['FIRMAL_DIR']
if op_path[-1] != "/":
	op_path += "/"

cp = currentProgram()


# Filename convention : prog_name-arch:endianness:64/32bit:compiler-spec-time.csv
# Ex: analysis on libc shows: libc.so.6-x86:LE:64:default-20240821:141528.csv
filename = cp.getName() + "-" + cp.getLanguageID().toString() + "-" + timestr + ".csv"

try:
	f = open(filename, "w+")
except:
	print("ERROR: could not open file: " + filename)
	exit(-1)
'''
# Ghidra requires analysis to be done in order to populate numAddresses
# in function body objects.
# If analysis is not run, all function sizes are reported as 1
if 'ANALYZEALL' in os.environ:
	analyzeAll(cp)
'''
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

f.write(cp.getName() + "," + cp.getExecutablePath() + ", " + cp.getLanguageID().toString() + ", 0\n")
f.write("NAME,VADDR,FILEOFFSET,SIZE\n")

# Gather and write results
for func in funcs:
	if(func.isThunk()):
		continue
	result = {}
	result["name"] = func.getName()
	entrypoint = func.getEntryPoint()
	result["vaddr"] = "0x" + entrypoint.toString()
	result["fileoffset"] = str(mem.getAddressSourceInfo(entrypoint).getFileOffset())
	# For size to work, ghidra analysis should be run
	# In case ghidra did not run analysis, the returned size is always 1
	result["size"] = str(func.getBody().getNumAddresses())
	f.write(result["name"] + "," + result["vaddr"] + "," + result["fileoffset"] + "," + result["size"] + "\n")

f.close()

###############################
#	Does not work	      #
###############################
'''
# Write code to dump all function names,
# vaddr ( ghidra ) and file offsets
# for further analysis

# Get all functions
funcs = currentProgram.functionManager.getFunctions(True)

# Get required handles to convert vaddr to file offsets
# Particularly useful in case currentProgram is NOT bare-metal
# firmware, and is instead part of an ELF

# Get addressFactory instance to convert addresses to ghidra's internal Address type
# as required by getAddressSourceInfo
addr = currentProgram.addressFactory


# get handle to program memory
mem = currentProgram.getMemory()

# To convert address 0xcafecafe to file offset, we simply do
# file_offset = mem.getAddressSourceInfo(addr.getAddress("0xcafecafe")).fileOffset
'''
