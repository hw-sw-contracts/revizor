from iced_x86 import *
from typing import Dict, Sequence
from types import ModuleType
import copy

def create_enum_dict(module: ModuleType) -> Dict[int, str]:
    return {module.__dict__[key]:key for key in module.__dict__ if isinstance(module.__dict__[key], int)}

REGISTER_TO_STRING: Dict[int, str] = create_enum_dict(Register)
def register_to_string(value: int) -> str:
    s = REGISTER_TO_STRING.get(value)
    if s is None:
        return str(value) + " /*Register enum*/"
    return s

OP_ACCESS_TO_STRING: Dict[int, str] = create_enum_dict(OpAccess)
def op_access_to_string(value: int) -> str:
    s = OP_ACCESS_TO_STRING.get(value)
    if s is None:
        return str(value) + " /*OpAccess enum*/"
    return s

FLOW_CONTROL_TO_STRING: Dict[int, str] = create_enum_dict(FlowControl)
def flow_control_to_string(value: int) -> str:
    s = FLOW_CONTROL_TO_STRING.get(value)
    if s is None:
        return str(value) + " /*FlowControl enum*/"
    return s

MEMORY_SIZE_TO_STRING: Dict[int, str] = create_enum_dict(MemorySize)
def memory_size_to_string(value: int) -> str:
    s = MEMORY_SIZE_TO_STRING.get(value)
    if s is None:
        return str(value) + " /*MemorySize enum*/"
    return s

def used_reg_to_string(reg_info: UsedRegister) -> str:
    return register_to_string(reg_info.register) + ":" + op_access_to_string(reg_info.access)

def used_mem_to_string(mem_info: UsedMemory) -> str:
    sb = "[" + register_to_string(mem_info.segment) + ":"
    need_plus = mem_info.base != Register.NONE
    if need_plus:
        sb += register_to_string(mem_info.base)
    if mem_info.index != Register.NONE:
        if need_plus:
            sb += "+"
        need_plus = True
        sb += register_to_string(mem_info.index)
        if mem_info.scale != 1:
            sb += "*" + str(mem_info.scale)
    if mem_info.displacement != 0 or not need_plus:
        if need_plus:
            sb += "+"
        sb += f"0x{mem_info.displacement:X}"
    sb += ";" + memory_size_to_string(mem_info.memory_size) + ";" + op_access_to_string(mem_info.access) + "]"
    return sb

def decode_rflags_bits(rf: int) -> list:
    sb = []
    if (rf & RflagsBits.OF) != 0:
        sb.append("OF")
    if (rf & RflagsBits.SF) != 0:
        sb.append("SF")
    if (rf & RflagsBits.ZF) != 0:
        sb.append("ZF")
    if (rf & RflagsBits.AF) != 0:
        sb.append("AF")
    if (rf & RflagsBits.CF) != 0:
        sb.append("CF")
    if (rf & RflagsBits.PF) != 0:
        sb.append("PF")
    if (rf & RflagsBits.DF) != 0:
        sb.append("DF")
    if (rf & RflagsBits.IF) != 0:
        sb.append("IF")
    if (rf & RflagsBits.AC) != 0:
        sb.append("AC")
    if (rf & RflagsBits.UIF) != 0:
        sb.append("UIF")
    return sb

def getRegisterLabel(regTracking, register_name:str) -> set:
    if register_name not in regTracking.keys():
        return {register_name}
    else:
        label = set()
        for reg in registerDeps(register_name):
            if reg not in regTracking.keys():
                label.add(reg)
            else:
                label = label.union(regTracking[reg])
        return label
        # return regTracking[register_name]



def getFlagLabel(flagTracking, flag_name:str) -> set:
    if flag_name not in flagTracking.keys():
        return {flag_name}
    else:
        return flagTracking[flag_name]

def getMemLabel(memTracking, address:int) -> set:
    if address not in memTracking.keys():
        return {address}
    else:
        return memTracking[address]


def desugarRegister(reg:str) -> str:
    if reg == "PC":
        return reg
    for i in {"A","B","C","D"}:
        if reg in {f"{i}L", f"{i}H", f"{i}X", f"E{i}X", f"R{i}X"}:
            return f"R{i}X"
    for i in {"BP","SI","DI","SP", "IP"}:
        if reg in {f"{i}L", f"{i}", f"E{i}", f"R{i}"}:
            return f"R{i}"
    for i in range(8,16):
        if reg in {f"R{i}B", f"R{i}W", f"R{i}D", f"R{i}"}:
            return f"R{i}"


def registerDeps(reg:str) -> set:
    if reg == "PC":
        return {reg}
    for i in {"A","B","C","D"}:
        if reg ==  f"R{i}X":
            return {f"{i}L", f"{i}H", f"{i}X", f"E{i}X", f"R{i}X"}
        elif reg == f"E{i}X":
            return {f"{i}L", f"{i}H", f"{i}X", f"E{i}X"}
        elif reg == f"{i}X":
            return {f"{i}L", f"{i}H", f"{i}X"}
        elif reg == f"{i}L":
            return {f"{i}L"}
        elif reg == f"{i}H":
            return {f"{i}H"}
    
    for i in {"BP","SI","DI","SP", "IP"}:
        if reg == f"R{i}":
            return {f"{i}L", f"{i}", f"E{i}", f"R{i}"}
        elif reg == f"E{i}":
            return {f"{i}L", f"{i}", f"E{i}"}
        elif reg == f"{i}":
            return {f"{i}L", f"{i}"}
        elif reg == f"{i}L":
            return {f"{i}L"}

    for i in range(8,16):
        if reg == f"R{i}":
            return {f"R{i}B", f"R{i}W", f"R{i}D", f"R{i}"}
        elif reg ==  f"R{i}D":
            return {f"R{i}B", f"R{i}W", f"R{i}D"}
        elif reg ==  f"R{i}W":
            return {f"R{i}B", f"R{i}W"}
        elif reg ==  f"R{i}B":
            return {f"R{i}B"}

    print(f"Unsupported register {reg}")
    exit(1)



class DependencyTracker:

    ## TODO: 
    # 1) When we observe an instruction operands, right now we do not distinguish between 1st and 2nd operand. Fix that!!

    def __init__(self, code_biteness, initialObservations = []):
        self.flagTracking = {}
        self.regTracking = {}
        self.memTracking = {}
        self.code_biteness = code_biteness
        self.srcRegs = set()
        self.srcFlags = set()
        self.srcMems = set()
        self.trgRegs = set()
        self.trgFlags = set()
        self.trgMems = set()
        self.debug = False
        self.initialObservations = initialObservations
        self.observedLabels = set(self.initialObservations)
        self.strictUndefined = True
        self.checkpoints = []

    def reset(self):
        self.flagTracking = {}
        self.regTracking = {}
        self.memTracking = {}
        self.observedLabels = set(self.initialObservations)
        self.srcRegs = set()
        self.srcFlags = set()
        self.srcMems = set()
        self.trgRegs = set()
        self.trgFlgs = set()
        self.trgMems = set()
        self.checkpoints = []

    def initialize(self, instruction):
        ## Collect source and target registers/flags

        self.srcRegs = set()
        self.srcFlags = set()
        self.srcMems = set()
        self.trgRegs = set()
        self.trgFlgs = set()
        self.trgMems = set()
        
        decoder = Decoder(self.code_biteness, instruction)
        formatter = FastFormatter(FormatterSyntax.NASM) #Formatter(FormatterSyntax.NASM)
        info_factory = InstructionInfoFactory()
        index = 0
        for instr in decoder:
            info = info_factory.info(instr)

            if self.debug:
                ### DEBUG
                print(f"{instr}")
                for reg_info in info.used_registers():
                    print(f"    Used reg: {used_reg_to_string(reg_info)}")
                for mem_info in info.used_memory():
                    print(f"    Used mem: {used_mem_to_string(mem_info)}")
                if instr.rflags_read != RflagsBits.NONE:
                    print(f"    RFLAGS Read: {decode_rflags_bits(instr.rflags_read)}")
                if instr.rflags_written != RflagsBits.NONE:
                    print(f"    RFLAGS Written: {decode_rflags_bits(instr.rflags_written)}")
                if instr.rflags_cleared != RflagsBits.NONE:
                    print(f"    RFLAGS Cleared: {decode_rflags_bits(instr.rflags_cleared)}")
                if instr.rflags_set != RflagsBits.NONE:
                    print(f"    RFLAGS Set: {decode_rflags_bits(instr.rflags_set)}")
                if instr.rflags_undefined != RflagsBits.NONE:
                    print(f"    RFLAGS Undefined: {decode_rflags_bits(instr.rflags_undefined)}")
                if instr.rflags_modified != RflagsBits.NONE:
                    print(f"    RFLAGS Modified: {decode_rflags_bits(instr.rflags_modified)}")
                print(f"    FlowControl: {flow_control_to_string(instr.flow_control)}")
        

            for reg_info in info.used_registers():
                if op_access_to_string(reg_info.access) in ["READ", "READ_WRITE", "COND_READ"]:
                    self.srcRegs.add(register_to_string(reg_info.register))
                if op_access_to_string(reg_info.access) in ["WRITE", "READ_WRITE", "COND_WRITE"]:
                    self.trgRegs.add(register_to_string(reg_info.register))
            if flow_control_to_string(instr.flow_control) != "NEXT":
                self.trgRegs.add("PC")
      
            self.srcFlags = set(decode_rflags_bits(instr.rflags_read))
            if self.strictUndefined:
                 self.srcFlags =  self.srcFlags.union( set(decode_rflags_bits(instr.rflags_undefined)) )
            self.trgFlags = set(decode_rflags_bits(instr.rflags_modified))

            if self.debug:
                print(f"    Source Registers: {self.srcRegs}")
                print(f"    Target Registers: {self.trgRegs}")
                print(f"    Source Flags: {self.srcFlags}")
                print(f"    Target Flags: {self.trgFlags}")

            index = index + 1
            assert(index <= 1)

    def trackMemoryAccess(self, address, size, mode):
        if self.debug:
            print(f"Track Memory Access {address} {size} {mode}")

        ## Tracking concrete memory accesses
        if mode == "READ":
            for i in range(0,size):
                self.srcMems.add(address + i)
        elif mode == "WRITE":
            for i in range(0,size):
                self.trgMems.add(address + i)
        else:
            print(f"Unsupported mode {mode}")
            exit(1)


    def finalizeTracking(self):
        #Compute the new dependency maps

        ## Compute source label
        srcLabel = set()
        for reg in self.srcRegs:
            srcLabel = srcLabel.union(getRegisterLabel(self.regTracking, reg))
        for flag in self.srcFlags:
            srcLabel = srcLabel.union(getFlagLabel(self.flagTracking, flag))
        for addr in self.srcMems:
            srcLabel = srcLabel.union(getMemLabel(self.memTracking, addr))

        ## Propagate label to all targets
        for reg in self.trgRegs:
            self.regTracking[reg] = list(srcLabel)
        for flg in self.trgFlags:
            self.flagTracking[flg] = list(srcLabel)
        for mem in self.trgMems:
            self.memTracking[mem] = list(srcLabel)

        if self.debug:
            print("Tracking information")
            print(f"Source label: {srcLabel}")
            print(f"Registers: {self.regTracking}")
            print(f"Flags: {self.flagTracking}")
            print(f"Memory: {self.memTracking}")

    def observeInstruction(self, mode):
        if self.debug:
            print(f"ObservedLabels: {self.observedLabels}")
        if mode == "PC":
            ## Add regLabel(PC) to the set of observed labels
            self.observedLabels = self.observedLabels.union(getRegisterLabel(self.regTracking, "PC"))
        elif mode == "OPS":
            ## For all registers r in the instruction operands (i.e., all source registers), Add regLabel(r) to the set of observed labels
            for reg in self.srcRegs:
                self.observedLabels = self.observedLabels.union(getRegisterLabel(self.regTracking, reg))
        else:
            print(f"Invalid mode {mode}")
            exit(1)
        if self.debug:
            print(f"ObserveInstruction {mode} : {self.observedLabels}")

    def observerMemoryAddress(self, address:int, size:int):
        ## Add memLabel(address) to the set of observed labels
        if self.debug:
            print(f"ObservedLabels: {self.observedLabels}")
        for i in range(0,size):
            self.observedLabels = self.observedLabels.union(getMemLabel(self.memTracking, addr+i))
        if self.debug:
            print(f"observerMemoryAddress {address} {size} : {self.observedLabels}")

    def saveState(self):
        # return a copy of the tracker state!
        return copy.deepcopy(self.flagTracking), copy.deepcopy(self.regTracking), copy.deepcopy(self.memTracking), copy.deepcopy(self.observedLabels)

    def restoreState(self, flagTracking, regTracking, memTracking, observedLabels):
        self.flagTracking = copy.deepcopy(flagTracking)
        self.regTracking = copy.deepcopy(regTracking)
        self.memTracking = copy.deepcopy(memTracking)
        self.observedLabels = copy.deepcopy(observedLabels)

    def checkpoint(self):
        t = self.saveState()
        self.checkpoints.append(t)

    def rollback(self):
        if len(self.checkpoints)>0:
            t = self.checkpoints.pop()
            self.restoreState(*t)
        else:
            print("There are no more checkpoints")
            exit(1)

    def get_observed_dependencies(self):
        return copy.deepcopy(self.observedLabels)