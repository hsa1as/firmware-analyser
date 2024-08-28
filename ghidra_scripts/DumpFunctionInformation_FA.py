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

# Set FIRMAL_DIR in env for output file location
if 'FIRMAL_DIR' not in os.environ:
	print("ERROR: env FIRMAL_DIR not set. Set FIRMAL_DIR for output directory")
	exit(-1)

# Database save path from environ
op_path = os.environ['FIRMAL_DIR']
if op_path[-1] != "/":
	op_path += "/"

# Get conn to db and create table if it doesn't already exist
hashdb = sqlite3.connect(op_path + "hash.db")
cur = hashdb.cursor()
res = cur.execute("SELECT name FROM sqlite_master WHERE name='hashdump'")
if(res.fetchone() is None):
    cur.execute("CREATE TABLE hashdump(size, progname, progpath, funcname, vaddr, fileoff, hash)")

cp = currentProgram()

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

# Gather and write results
data = []
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
# Get function bytes out of a stupid java object
    func_code = bytes(map(lambda b: b & 0xff, getBytes(entrypoint, int(result["size"]))))
    result["hash"] = ssdeep.hash(func_code)
    row = (result['size'], cp.getName(), cp.getExecutablePath(), result['name'], result['vaddr'], result['fileoffset'], result['hash'])
    data.append(row)
    if(len(data) > 1000):
        cur.executemany("INSERT INTO hashdump VALUES(?, ?, ?, ?, ?, ?, ?)", data)
        data.clear()

cur.executemany("INSERT INTO hashdump VALUES(?, ?, ?, ?, ?, ?, ?)", data)
data.clear()
hashdb.commit()
hashdb.close()