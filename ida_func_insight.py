'''
# API to export:
1, generate_cfg(func_ea)
'''
import re
import struct
import datetime
import time
import sys
import socket
import base64
import json 

import idaapi
import ida_funcs
import idautils
import ida_idp
import ida_ua 

from idc import ARGV

ida_auto.auto_wait()

debug_mode=False
info = None
cpu_arch=None

def get_mnem_safe(ea, ignore_exception=False):
    try:
        mnemonic = ida_ua.print_insn_mnem(ea).lower()
    except Exception as e:
        print(f"Failed in obtaining mnemonics @ {ea:#x}: {str(e)}!")
        if not ignore_exception: raise  # re-throw it
        mnemonic=""
    return mnemonic

# for use in is_conditional_jump()
conditional_jumps={}

# x86/x64
conditional_jumps['metapc'] = [ \
    "jz", "jnz", "je", "jne", "ja", "jae", "jb", "jbe", \
    "jg", "jge", "jl", "jle", "jp", "jnp", "jo", "jno", "js", "jns" \
]

# MIPS cpu
conditional_jumps['mipsb']= ["beq", "beqz", "bne", "bnez", "bnz", "bgez", "bgtz", "blez", "bltz"]
conditional_jumps['mipsl']=conditional_jumps['mipsb']

# ARM cpu
conditional_jumps['arm']= [ "bne", "beq", "bgt", "blt", "bge", "ble", "bvs", "bvc", "bhi", "bls"]
conditional_jumps['arml']=conditional_jumps['arm']
conditional_jumps['armb']=conditional_jumps['arm']

def is_conditional_jump(ea):
    global cpu_arch, conditional_jumps

    """Check if the instruction at the given address is a conditional jump/branch."""
    mnemonic = get_mnem_safe(ea)
    
    # Check against known conditional jump mnemonics for different architectures
    return (mnemonic in conditional_jumps[cpu_arch])

unconditional_jumps= {}
unconditional_jumps['metapc']= {"jmp", "ljmp"}
unconditional_jumps['arm'] = {"b", "bx", "bl", "blx"}
unconditional_jumps['armb'] = unconditional_jumps['arm']
unconditional_jumps['arml']=unconditional_jumps['arm']
unconditional_jumps['mipsb']  = {"b", "j", "jr", "jal"}
unconditional_jumps['mipsl']=unconditional_jumps['mipsb']

def is_unconditional_jump(ea):
    global cpu_arch, unconditional_jumps
    
    """Check if the instruction at the given address is an unconditional jump."""
    mnemonic = get_mnem_safe(ea)

    # Check if the mnemonic belongs to any known unconditional jump group
    return mnemonic in unconditional_jumps[cpu_arch] 

func_returns={}
func_returns["metapc"]=["ret", "retn", "hlt"]
func_returns["arm"]=["ldmfd"]
func_returns["mipsb"] = ["jr"]
func_returns["mipsl"] = func_returns["mipsb"]
func_returns["sparcb"]=["ret", "retn"]  # SPARC
func_returns["68040"]=["rts"]

def is_return(ea):
    global cpu_arch, func_returns
    
    """Check if the instruction at the given address is an unconditional jump."""
    mnemonic = get_mnem_safe(ea)

    # Check if the mnemonic belongs to any known unconditional jump group
    return mnemonic in func_returns[cpu_arch] 

class BasicBlock:
    """Representation of a basic block."""
    def __init__(self, start_ea, end_ea):
        self.start_ea = start_ea
        self.end_ea = end_ea
        self.succs = []  # Successor blocks (CFG edges)
        
    def add_successor(self, successor):
        self.succs.append(successor)

    def __repr__(self):
        ss=f"BB[{self.start_ea:#x} - {self.end_ea:#x}] -> [%s]" % ", ".join([f"{x:#x}" for x in self.succs])
        return ss
        
def connect_basic_blocks(blocks, fn, fn_end):
    global cpu_arch, debug_mode

    """Establish CFG edges (successors) between basic blocks."""
    blocks2=[]
    for block in blocks:
        if debug_mode: print(f"check successor for BB @{block.start_ea:#x}")
        # Check for the last instruction in the block
        last_ea = idc.prev_head(block.end_ea) #block.end_ea - 1  # The end address is exclusive, so use `-1`
        # for mips CPUs, the prev last instruction is the really last one
        if 'mips' in cpu_arch:
            last_ea=idc.prev_head(last_ea)

        # Add successors based on the last instruction (e.g., jump or call)
        xrefs=idautils.CodeRefsFrom(last_ea, 0)
        for ref_ea in xrefs:
            # skip refs outside of current function
            if ref_ea < fn or ref_ea >= fn_end: continue

            # Find the target basic block for each reference
            #print("xref: %x -> %x" , ( last_ea, ref _ea))
            block.add_successor(ref_ea)
        
        # Since A block naturally ends (natural end) at its next following block's beginning, 
        # it's necessary to check whether the following block is outside of current function
        if block.end_ea < fn or block.end_ea >= fn_end: 
            if debug_mode: print(f"Skip outside natural successor @ {last_ea:#x} -> {block.end_ea:#x}, fn:{fn:#x}~{fn_end:#x}")
            continue

        # for conditional jump, there are two successors
        if not is_unconditional_jump(last_ea) and not is_return(last_ea):
            if debug_mode: 
                if is_conditional_jump(last_ea):
                    print(f"conditional jump at {last_ea:#x}.")
                else:
                    print(f"natural successor found at {last_ea:#x}.")
            block.add_successor(block.end_ea)
        
        #print(block)
        blocks2.append({"start":block.start_ea, "end":block.end_ea, 'successors':block.succs})

    return blocks2

'''
# analyze a specific function to get:
#  1, CFG: control-flow-graph
2, instructions
3, callers
'''
def ana_func(ea):
    global info, cpu_arch, debug_mode

    ret={'name':None, "start":None, "end": None, "instrs": None, 'cfg': None, 'callers':[]}
    
    # Generate basic blocks
    """Extract basic blocks from the function starting at 'ea'."""
    func = ida_funcs.get_func(ea)
    if not func:
        print(f"Error: No function found at {ea:#x}.")
        return ret
    
    fn,fn_end=func.start_ea,func.end_ea
    ret["name"]=idc.get_func_name(fn)
    ret['start'],ret['end']=fn,fn_end

    # get callers
    callers=set([])
    for x in CodeRefsTo(fn, 0):
        #print type(x)
        xx=idc.get_name_ea_simple(idc.get_func_name(x))
        callers.add(xx) 
    # convert to list for JSON handling
    ret['callers']=list(callers)
    
    if debug_mode: print(f"to add blocs [{fn:#x} ~ {fn_end:#x}]")
    
    # iterate all the blocks
    blocks, instrs = [],[]
    for bloc in idaapi.FlowChart(func):
        if bloc.start_ea >= fn_end: continue
        if bloc.start_ea == bloc.end_ea: continue
        assert(fn_end > fn)
        if debug_mode is True: 
            print(f"add bloc[{bloc.start_ea:#x} ~ {bloc.end_ea:#x}]")
        blocks.append(BasicBlock(bloc.start_ea, bloc.end_ea))

        # get instructions inside the block
        for head in Heads(bloc.start_ea, bloc.end_ea):
            # Get disassembled instruction
            disasm=idc.generate_disasm_line(head, 0)
            #fd.write(disasm+"\n")
            instrs.append(disasm)
    
    # save blocks
    ret["instrs"]=instrs
    
    if len(blocks)==0:
        assert(len(instrs)==0)
        print(f"no blocks checked for {ea:#x}")
        return ret
    
    
    # to generate the CFG by connecting blocks
    ret['cfg'] = connect_basic_blocks(blocks, fn, fn_end)
    
    return ret

def display_cfg(cfg):
    if cfg is None: return

    """Print the CFG to the console."""
    for block in cfg:
        print(block)

def get_imports():
    # Get the start address of the imports table
    imports={}
    for i in range(idaapi.get_import_module_qty()):
        # Get the name of the imported module (DLL)
        dll_name = idaapi.get_import_module_name(i)
        if not dll_name:
            continue

        imports[dll_name]=[]
        
        # Iterate over the imports in the DLL
        def imp_cb(ea, name, ord):
            if name:
                #print(f"  0x{ea:X} {name}")
                imports[dll_name].append(f"{name}")
            else:
                #print(f"  0x{ea:X} ord({ord})")
                imports[dll_name].append(f"ord({ord})")
            return True
        
        # Enumerate the imported functions from the DLL
        idaapi.enum_import_names(i, imp_cb)
    return imports

def main():
    global info, cpu_arch, debug_mode
    global info
    global cpu_arch

    info = idaapi.get_inf_structure()
    cpu_arch=info.procname.lower()
    print(cpu_arch)

    #print len(ARGV)

    # get log
    log_file=""
    mode="gui"
    if len(ARGV) >= 2:
        mode="backend"
        log_file=ARGV[1]
        fd=open(log_file, "w", encoding='utf-8')
    else:
        # the result is too large, so it's better storing them into some file
        fd=open("d:\\ida.scripts\\ida_func_insight.log", "wt") 
        #fd.write("%s\n" % (str(datetime.datetime.now())))
    
    ts_start=time.time()
    
    should_end=False
    if len(ARGV) >= 3:
        if int(ARGV[2]) == 1: 
            should_end = True

    debug_mode=False
    
    if mode =="gui":
        # debug only
        # Example: Generate CFG for the function at the current cursor location.
        ea = idaapi.get_screen_ea()  # Get the current cursor address in IDA
        debug_mode=True
        info=ana_func(ea)
        display_cfg(info['cfg'])
        json.dump(info, sys.stdout)
        debug_mode=False
        #return
    
    # cpu
    jresult={"ts": str(datetime.datetime.now()), 'time_consumed':0, "cpu":cpu_arch, \
             'func_basics':{}, 'cfg':{}, 'instrs':{}, 'imports':None}

    # function information one by one
    analyzed=0
    for func_ea in Functions():
        try:
            info=ana_func(func_ea)
            # Display the generated CFG
            print(f"To analyze function @ {func_ea:#x}:")
            jresult['func_basics'][func_ea]={'name':info['name'], 'start': func_ea, \
                    'end': info['end'], 'callers':info['callers']}
            jresult['cfg'][func_ea]=info['cfg']
            jresult['instrs'][func_ea]=info['instrs']
            analyzed+=1
        except Exception as e:
            print(f"Exception {str(e)} caught when CFGing func of {func_ea:#x}!")
            break
    print(f"{analyzed:#d} functions have been analyzed!")

    # get imports
    imports=get_imports()
    jresult['imports']=imports

    time_delta=time.time()-ts_start
    jresult['time_consumed']=time_delta

    json.dump(jresult, fd) #fd.write(json.dumps(ret)) 

    if mode=="gui": print(str(datetime.datetime.now()))

    fd.close()

    if should_end is True: ida_pro.qexit(0)
    
if __name__ == '__main__':
    main()