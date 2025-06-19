#@author 
#@category Analysis
#@keybinding 
#@menupath 
#@toolbar 

import re
from ghidra.program.model.listing import Function
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.script import GhidraScript
from java.io import File
from javax.swing import JFileChooser

class AutoFunctionParsesGhidra(GhidraScript):
    def run(self):
        # Prompt for XenonRecomp log file
        xenonrecomp_log = self.askFile("Select XenonRecomp log file", "Open")
        # Prompt for output TOML file
        output_file = self.askFile("Select output TOML file", "Save")

        # Parse XenonRecomp log
        switch_idx = 22
        switch_addrs = set()
        with open(xenonrecomp_log.getAbsolutePath(), 'r') as file:
            for line in file:
                if re.search('ERROR: Switch case at ', line):
                    switch_addrs.add(line[switch_idx:switch_idx+8])

        # Get all functions in the current program
        function_manager = currentProgram.getFunctionManager()
        functions = list(function_manager.getFunctions(True))
        functs = []  # List of (start, end)
        for func in functions:
            start = int(str(func.getEntryPoint()), 16)
            end = int(str(func.getBody().getMaxAddress()), 16)
            functs.append((start, end))
        functs.sort()

        # For each switch address, find the function it belongs to
        output_functs = []
        for switch_addr in switch_addrs:
            switch_addr_int = int(switch_addr, 16)
            found = False
            for start, end in functs:
                if start <= switch_addr_int <= end:
                    output_functs.append((start, end - start))
                    found = True
                    break
            if not found:
                print("WARNING: Function relating to {} not found! Skipping.".format(switch_addr))

        # Remove duplicates
        output_functs = list(set(output_functs))

        # Check for functions with same start but different sizes
        starts = {}
        for start, size in output_functs:
            if start in starts and starts[start] != size:
                print("WARNING: 0x{:X} has multiple entries of different lengths, manually find correct one.".format(start))
            starts[start] = size

        print("{} functions found!".format(len(output_functs)))

        # Output to TOML
        output_str = "functions = ["
        for start, size in output_functs:
            curr_funct_start = '0x{:X}'.format(start)
            curr_funct_size = '0x{:X}'.format(size)
            curr_funct = "\n    { address = "+curr_funct_start+", size = "+curr_funct_size+" },"
            output_str += curr_funct
        if output_functs:
            output_str = output_str[:-1]  # Remove last comma
        output_str += "\n]"

        with open(output_file.getAbsolutePath(), "w") as f:
            f.write(output_str)

# If running as a Ghidra script, instantiate and run
if __name__ == "__main__" or __name__ == "__builtin__":
    script = AutoFunctionParsesGhidra()
    script.run() 
