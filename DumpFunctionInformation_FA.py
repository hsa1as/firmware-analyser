# Dump function information for fuzzy hashing with firmware-analyser
#@author "R Sai Ashwin"
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


#TODO Add User Code Here


##################
# Code for	 # 
# Ghidrathon	 #
##################

# Filename to write results to
filename = askFile("Function Data File", "Okay").toString() 
f = open(filename, "w+")

cp = currentProgram()


# Ghidra requires analysis to be done in order to populate numAddresses
# in function body objects. 
# If analysis is not run, all function sizes are reported as 1
# Uncomment for headless mode, to run analysis before our script runs
# analyzeAll(cp)

# Get required objects from ghidra's java hell
funcs = cp.getFunctionManager().getFunctions(True)
addr = cp.getAddressFactory()
mem = cp.getMemory()

f.write(cp.getName() + "," + cp.getExecutablePath() +"\n")
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