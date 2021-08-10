"""
File: Model Interface and its implementations

Copyright (C) 2021 Oleksii Oleksenko
Copyright (C) 2020 Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from abc import ABC, abstractmethod
import os
from unicorn import *
from unicorn.x86_const import *

from config import CONF
from custom_types import List, Tuple, CTrace
from helpers import assemble, pretty_bitmap

from dependency_tracking import *

POW32 = pow(2, 32)


class Model(ABC):
    coverage_tracker = None
    RUNTIME_R_SIZE = 1024 * 1024
    CODE_SIZE = 4 * 1024
    RSP_OFFSET = RUNTIME_R_SIZE // 2
    RBP_OFFSET = RUNTIME_R_SIZE // 2
    R14_OFFSET = RUNTIME_R_SIZE // 2

    def __init__(self, sandbox_base, stack_base, code_base):
        super().__init__()
        self.sandbox_base: int = sandbox_base
        self.stack_base: int = stack_base
        self.code_base: int = code_base
        self.rsp_init = stack_base + self.RSP_OFFSET
        self.rbp_init = stack_base + self.RBP_OFFSET
        self.r14_init = sandbox_base + self.R14_OFFSET

    @abstractmethod
    def load_test_case(self, test_case_asm: str) -> None:
        pass

    @abstractmethod
    def trace_test_case(self, inputs: List[int], nesting: int, debug: bool = False):
        pass

    def set_coverage(self, coverage_tracker):
        self.coverage_tracker = coverage_tracker


# =============================================================================
# Unicorn-based predictors
# =============================================================================
FLAGS_CF = 0b000000000001
FLAGS_PF = 0b000000000100
FLAGS_AF = 0b000000010000
FLAGS_ZF = 0b000001000000
FLAGS_SF = 0b000010000000
FLAGS_OF = 0b100000000000


class X86UnicornTracer(ABC):
    """
    A superclass that encodes the attacker capabilities
    """
    trace: List[int]
    full_execution_trace: List[Tuple[bool, int]]

    def __init__(self):
        super().__init__()
        self.trace = []

    def reset_trace(self, emulator) -> None:
        self.trace = []
        self.full_execution_trace = []

    def get_trace(self) -> CTrace:
        return hash(tuple(self.trace))

    def get_full_execution_trace(self):
        return self.full_execution_trace

    def observe_mem_access(self, access, address: int, size: int, value: int, model) -> None:
        if not model.in_speculation:
            self.full_execution_trace.append((False, address - model.r14_init))
            if model.debug:
                if access == UC_MEM_READ:
                    val = int.from_bytes(model.emulator.mem_read(address, size), byteorder='little')
                    print(f"  > read: +0x{address - model.r14_init:x} = 0x{val:x}")
                else:
                    print(f"  > write: +0x{address - model.r14_init:x} = 0x{value:x}")

    def observe_instruction(self, address: int, size: int, model) -> None:
        if not model.in_speculation:
            self.full_execution_trace.append((True, address - model.code_base))
            if model.debug:
                print(f"{address - model.code_base:2x}: ", end="")
                model.print_state(oneline=True)


class L1DTracer(X86UnicornTracer):
    def reset_trace(self, emulator):
        self.trace = [0, 0]
        self.full_execution_trace = []

    def observe_mem_access(self, access, address, size, value, model):
        page_offset = (address & 4032) >> 6  # 4032 = 0b111111000000
        cache_set_index = 9223372036854775808 >> page_offset
        if model.in_speculation:
            self.trace[1] |= cache_set_index
        else:
            self.trace[0] |= cache_set_index
        # print(f"{cache_set_index:064b}")
        super(L1DTracer, self).observe_mem_access(access, address, size, value, model)

    def observe_instruction(self, address: int, size: int, model):
        super(L1DTracer, self).observe_instruction(address, size, model)

    def get_trace(self) -> CTrace:
        if CONF.ignore_first_cache_line:
            self.trace[0] &= 9223372036854775807
            self.trace[1] &= 9223372036854775807
        return (self.trace[1] << 64) + self.trace[0]


class PCTracer(X86UnicornTracer):
    def observe_instruction(self, address: int, size: int, model):
        self.trace.append(address)
        if model.dependencyTracker is not None:
            model.dependencyTracker.observeInstruction("PC")
        super(PCTracer, self).observe_instruction(address, size, model)


class MemoryTracer(X86UnicornTracer):
    def observe_mem_access(self, access, address, size, value, model):
        self.trace.append(address)
        if model.dependencyTracker is not None:
            model.dependencyTracker.observeInstruction("OPS")
        super(MemoryTracer, self).observe_mem_access(access, address, size, value, model)


class CTTracer(MemoryTracer):
    def observe_instruction(self, address: int, size: int, model):
        self.trace.append(address)
        if model.dependencyTracker is not None:
            model.dependencyTracker.observeInstruction("PC")
        super(CTTracer, self).observe_instruction(address, size, model)


class CTNonSpecStoreTracer(CTTracer):
    def observe_mem_access(self, access, address, size, value, model):
        if not model.in_speculation:  # all non-spec mem accesses
            self.trace.append(address)
        if access == UC_MEM_READ:  # and speculative loads
            self.trace.append(address)
        super(CTNonSpecStoreTracer, self).observe_mem_access(access, address, size, value, model)


class CTRTracer(CTTracer):
    def reset_trace(self, emulator):
        self.trace = [
            emulator.reg_read(UC_X86_REG_RAX),
            emulator.reg_read(UC_X86_REG_RBX),
            emulator.reg_read(UC_X86_REG_RCX),
            emulator.reg_read(UC_X86_REG_RDX),
            emulator.reg_read(UC_X86_REG_EFLAGS),
        ]
        self.full_execution_trace = []


class ArchTracer(CTRTracer):
    def observe_mem_access(self, access, address, size, value, model):
        if access == UC_MEM_READ:
            val = int.from_bytes(model.emulator.mem_read(address, size), byteorder='little')
            self.trace.append(val)
            if self.dependencyTracker is not None:
                self.dependencyTracker.observerMemoryAddress(address,size)

        self.trace.append(address)
        super(ArchTracer, self).observe_mem_access(access, address, size, value, model)


class X86UnicornModel(Model):
    """
    Base class for all Unicorn-based models.
    Serves as an adapter between Unicorn and our fuzzer.
    """
    code: bytes
    emulator: Uc
    in_speculation: bool = False
    speculation_window: int = 0
    checkpoints: List
    store_logs: List
    previous_store: Tuple[int, int, int, int]
    tracer: X86UnicornTracer
    nesting: int = 0
    debug: bool = True
    dependencyTracker: DependencyTracker

    def load_test_case(self, test_case_asm: str) -> None:

        # create a binary
        assemble(test_case_asm, 'tmp.o')

        # read the binary
        with open('tmp.o', 'rb') as f:
            self.code = f.read()

        # initialize emulator in x86-64 mode
        emulator = Uc(UC_ARCH_X86, UC_MODE_64)

        try:
            # map 3 memory regions for this emulation, 1 MB each
            # it is in line with the nanoBench memory layout
            emulator.mem_map(self.stack_base, self.RUNTIME_R_SIZE)
            emulator.mem_map(self.sandbox_base, self.RUNTIME_R_SIZE)
            emulator.mem_map(self.code_base, self.CODE_SIZE)

            # point our utility regs into it the middle of the corresponding regions
            emulator.reg_write(UC_X86_REG_RBP, self.rbp_init)
            emulator.reg_write(UC_X86_REG_RSP, self.rsp_init)
            emulator.reg_write(UC_X86_REG_R14, self.r14_init)

            # write machine code to be emulated to memory
            emulator.mem_write(self.code_base, self.code)

            # initialize machine registers
            emulator.reg_write(UC_X86_REG_RAX, 0x0)
            emulator.reg_write(UC_X86_REG_RBX, 0x0)
            emulator.reg_write(UC_X86_REG_RCX, 0x0)
            emulator.reg_write(UC_X86_REG_RDX, 0x0)
            emulator.reg_write(UC_X86_REG_RSI, 0x0)
            emulator.reg_write(UC_X86_REG_R8, 0x0)
            emulator.reg_write(UC_X86_REG_R9, 0x0)
            emulator.reg_write(UC_X86_REG_R10, 0x0)
            emulator.reg_write(UC_X86_REG_R11, 0x0)
            emulator.reg_write(UC_X86_REG_R12, 0x0)
            emulator.reg_write(UC_X86_REG_R13, 0x0)
            emulator.reg_write(UC_X86_REG_R15, 0x0)

            emulator.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self.trace_mem_access, self)
            emulator.hook_add(UC_HOOK_CODE, self.trace_code, self)

            self.emulator = emulator

        except UcError as e:
            print("Model error [load_test_case]: %s" % e)
            raise e

    def trace_test_case(self, inputs: List[int], nesting, debug: bool = False) -> List[CTrace]:
        self.nesting = nesting
        self.debug = debug

        traces = []
        full_execution_traces = []
        deltas = []

        for i, input_ in enumerate(inputs):

            if i < CONF.equivalence_class_boost_nr or not(CONF.equivalence_class_boost):
                try:
                    self.reset_model()
                    self.reset_emulator(input_)
                    self.tracer.reset_trace(self.emulator)
                    if self.dependencyTracker is not None:
                        self.dependencyTracker.reset()
                    self.emulator.emu_start(self.code_base, self.code_base + len(self.code),
                                            timeout=10000)
                except UcError as e:
                    if not self.in_speculation:
                        self.print_state()
                        print("Model error [trace_test_case]: %s" % e)
                        raise e

                # if we use one of the SPEC contracts, we might have some residual simulations
                # that did not reach the spec. window by the end of simulation. Those need
                # to be rolled back
                while self.in_speculation:
                    try:
                        self.rollback()
                    except UcError:
                        continue

                # store the results
                traces.append(self.tracer.get_trace())
                full_execution_traces.append(self.tracer.get_full_execution_trace())


                if self.dependencyTracker is not None:
                    dependencies = self.dependencyTracker.get_observed_dependencies()
                    self.reset_emulator(input_)
                    delta = self.get_emulator_values(dependencies)
                    deltas.append(delta)
                    # if self.debug:
                    #     print(f"DEPENDENCIES: {dependencies}")
                    #     print(f"DELTA {delta}")
            else:
                index = i % CONF.equivalence_class_boost_nr
                trace = traces[index] 
                full_execution_trace = full_execution_traces[index]
                traces.append(trace)
                full_execution_traces.append(full_execution_trace)
                deltas.append(index)
                
                # if self.debug:
                #     delta = deltas[index]
                #     print(f"Input[{i}] {input_}")
                #     print(f"Delta[{index}] {delta}")
                #     try:
                #         self.reset_model()
                #         self.reset_emulator(input_)
                #         self.apply_delta(delta)
                #         ## Continue as before
                #         self.tracer.reset_trace(self.emulator)
                #         if self.dependencyTracker is not None:
                #             self.dependencyTracker.reset()
                #         self.emulator.emu_start(self.code_base, self.code_base + len(self.code),
                #                                 timeout=10000)
                #     except UcError as e:
                #         if not self.in_speculation:
                #             self.print_state()
                #             print("Model error [trace_test_case]: %s" % e)
                #             raise e

                #     # if we use one of the SPEC contracts, we might have some residual simulations
                #     # that did not reach the spec. window by the end of simulation. Those need
                #     # to be rolled back
                #     while self.in_speculation:
                #         try:
                #             self.rollback()
                #         except UcError:
                #             continue

                #     if trace == self.tracer.get_trace():
                #         print(f">>>>> Same trace: {trace}")
                #     else:
                #         print(f">>>>> ORIGINAL TRACE: {trace}")
                #         print(f">>>>> REPLAYED TRACE: {self.tracer.get_trace()}")

                #     if full_execution_trace == self.tracer.get_full_execution_trace():
                #         print(f">>>>> Same full trace: {full_execution_trace}")
                #     else:
                #         print(f">>>>> ORIGINAL FULL TRACE: {full_execution_trace}")
                #         print(f">>>>> REPLAYED FULL TRACE: {self.tracer.get_full_execution_trace()}")
                #         exit(1)

        if self.coverage_tracker:
            self.coverage_tracker.model_hook(full_execution_traces)

        return (traces, deltas)

    def reset_emulator(self, seed):
        self.checkpoints = []
        self.in_speculation = False
        self.speculation_window = 0

        self.emulator.reg_write(UC_X86_REG_RSP, self.rsp_init)
        self.emulator.reg_write(UC_X86_REG_RBP, self.rbp_init)
        self.emulator.reg_write(UC_X86_REG_R14, self.r14_init)

        # Values in assist page + 4 bytes after it (for overflows)
        input_mask = pow(2, (CONF.prng_entropy_bits % 33)) - 1
        random_value = seed
        for i in range(0, 4096 + 4, 4):
            random_value = ((random_value * 2891336453) % POW32 + 12345) % POW32
            masked_rvalue = (random_value ^ (random_value >> 16)) & input_mask
            masked_rvalue = masked_rvalue << 6
            self.emulator.mem_write(self.r14_init + 4096 + i,
                                    masked_rvalue.to_bytes(4, byteorder='little'))

        # Values in sandbox memory
        for i in range(0, 4096, 4):
            random_value = ((random_value * 2891336453) % POW32 + 12345) % POW32
            masked_rvalue = (random_value ^ (random_value >> 16)) & input_mask
            masked_rvalue = masked_rvalue << 6
            self.emulator.mem_write(self.r14_init + i,
                                    masked_rvalue.to_bytes(4, byteorder='little'))

        # Values in registers
        for reg in [UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX]:
            random_value = ((random_value * 2891336453) % POW32 + 12345) % POW32
            masked_rvalue = (random_value ^ (random_value >> 16)) & input_mask
            masked_rvalue = masked_rvalue << 6
            self.emulator.reg_write(reg, masked_rvalue)

        # FLAGS
        random_value = ((random_value * 2891336453) % POW32 + 12345) % POW32
        self.emulator.reg_write(UC_X86_REG_EFLAGS, (random_value & 2263) | 2)

        self.emulator.reg_write(UC_X86_REG_RDI, random_value)


    def get_emulator_values(self, identifiers):
        def getFlag(emulator, flag):
            flagsDict = {"CF" : 0x0001, "PF": 0x0004, "AF": 0x0010, "ZF": 0x0040, "SF":0x0080, "TF": 0x0100, "IF": 0x0200, "DF": 0x0400, "OF": 0x0800, "AC": 0x00040000}
            if flag in flagsDict.keys():
                flags = self.emulator.reg_read(UC_X86_REG_EFLAGS)
                mask = flagsDict[flag]
                value = flags & mask
                return value
            else:
                print(f"Unsupported flag {flag}")
                exit(1)

        def getRegister(emulator, reg):
            regDict = { 
                "RAX": UC_X86_REG_RAX,
                "RBX": UC_X86_REG_RBX,
                "RCX": UC_X86_REG_RCX,
                "RDX": UC_X86_REG_RDX,
                "RDI": UC_X86_REG_RDI,
                "RSI": UC_X86_REG_RSI,
                "RSP": UC_X86_REG_RSP,
                "RBP": UC_X86_REG_RBP,
                "R8": UC_X86_REG_R8,
                "R9": UC_X86_REG_R9,
                "R10": UC_X86_REG_R10,
                "R11": UC_X86_REG_R11,
                "R12": UC_X86_REG_R12,
                "R13": UC_X86_REG_R13,
                "R14": UC_X86_REG_R14,
            }

            for i in {"A","B","C","D"}:
                if reg ==  f"R{i}X":
                    mask = 0xFFFFFFFFFFFFFFFF
                    value = self.emulator.reg_read(regDict[f"R{i}X"])
                    return mask & value 
                elif reg == f"E{i}X":
                    mask = 0x00000000FFFFFFFF
                    value = self.emulator.reg_read(regDict[f"R{i}X"])
                    return mask & value 
                elif reg == f"{i}X":
                    mask = 0x000000000000FFFF
                    value = self.emulator.reg_read(regDict[f"R{i}X"])
                    return mask & value 
                elif reg == f"{i}L":
                    mask = 0x00000000000000FF
                    value = self.emulator.reg_read(regDict[f"R{i}X"])
                    return mask & value 
                elif reg == f"{i}H":
                    mask = 0x000000000000FF00
                    value = self.emulator.reg_read(regDict[f"R{i}X"])
                    return mask & value 

            
            for i in {"BP","SI","DI","SP", "IP"}:
                if reg == f"R{i}":
                    mask = 0xFFFFFFFFFFFFFFFF
                    value = self.emulator.reg_read(regDict[f"R{i}"])
                    return mask & value 
                elif reg == f"E{i}":
                    mask = 0x00000000FFFFFFFF
                    value = self.emulator.reg_read(regDict[f"R{i}"])
                    return mask & value 
                elif reg == f"{i}":
                    mask = 0x000000000000FFFF
                    value = self.emulator.reg_read(regDict[f"R{i}"])
                    return mask & value 
                elif reg == f"{i}L":
                    mask = 0x00000000000000FF
                    value = self.emulator.reg_read(regDict[f"R{i}"])
                    return mask & value 

            for i in range(8,16):
                if reg == f"R{i}":
                    mask = 0xFFFFFFFFFFFFFFFF
                    value = self.emulator.reg_read(regDict[f"R{i}"])
                    return mask & value 
                elif reg ==  f"R{i}D":
                    mask = 0x00000000FFFFFFFF
                    value = self.emulator.reg_read(regDict[f"R{i}"])
                    return mask & value 
                elif reg ==  f"R{i}W":
                    mask = 0x000000000000FFFF
                    value = self.emulator.reg_read(regDict[f"R{i}"])
                    return mask & value 
                elif reg ==  f"R{i}B":
                    mask = 0x00000000000000FF
                    value = self.emulator.reg_read(regDict[f"R{i}"])
                    return mask & value 
            
            print(f"Unsupported identifier {reg}")
            exit(1)

        values = {}
        for d in identifiers:
            if d == "PC":
                pass
            elif type(d) is int:
                values[d] = self.emulator.mem_read(d, 1)
            elif d in {"CF", "PF", "AF", "ZF", "SF", "TF", "IF", "DF", "OF", "AC"}:
                values[d] = getFlag(self.emulator, d)
            else: 
                values[d] = getRegister(self.emulator, d)

        return values
        
    def apply_delta(self, values):
        def setFlag(emulator, flag, value):
            flagsDict = {"CF" : 0x0001, "PF": 0x0004, "AF": 0x0010, "ZF": 0x0040, "SF":0x0080, "TF": 0x0100, "IF": 0x0200, "DF": 0x0400, "OF": 0x0800, "AC": 0x00040000}
            if flag in flagsDict.keys():
                flags = self.emulator.reg_read(UC_X86_REG_EFLAGS)
                mask = flagsDict[flag]
                value = flags & mask
                if value != values[d]:
                    if values[d] == 0:
                        # Clearing bit
                        flags |= 1 << mask
                    else:
                        # Setting bit
                        flags &= ~(1 << mask)
                else:
                    # no need to change stuff 
                    pass
                # Write back the updated flags
                self.emulator.reg_write(UC_X86_REG_EFLAGS, flags)
            else:
                print(f"Unsupported flag {flag}")
                exit(1)

        def setRegister(emulator, reg, value):
            regDict = { "RAX": UC_X86_REG_RAX,"RBX": UC_X86_REG_RBX,"RCX": UC_X86_REG_RCX,"RDX": UC_X86_REG_RDX,"RDI": UC_X86_REG_RDI,"RSI": UC_X86_REG_RSI,"RSP": UC_X86_REG_RSP,"RBP": UC_X86_REG_RBP,"R8": UC_X86_REG_R8,"R9": UC_X86_REG_R9,"R10": UC_X86_REG_R10,"R11": UC_X86_REG_R11,"R12": UC_X86_REG_R12,"R13": UC_X86_REG_R13,"R14": UC_X86_REG_R14 }
            
            for i in {"A","B","C","D"}:
                if reg ==  f"R{i}X":
                    self.emulator.reg_write(regDict[f"R{i}X"], values[d])
                    return
                elif reg == f"E{i}X":
                    init = bytearray(self.emulator.reg_read(regDict[f"R{i}X"]).to_bytes(8, 'little'))
                    toSet = bytearray(value.to_bytes(8, 'little'))
                    init[0] = toSet[0]
                    init[1] = toSet[1]
                    init[2] = toSet[2]
                    init[3] = toSet[3]
                    self.emulator.reg_write(regDict[f"R{i}X"], int.from_bytes(bytes(init), byteorder='little'))
                    return
                elif reg == f"{i}X":
                    init = bytearray(self.emulator.reg_read(regDict[f"R{i}X"]).to_bytes(8, 'little'))
                    toSet = bytearray(value.to_bytes(8, 'little'))
                    init[0] = toSet[0]
                    init[1] = toSet[1]
                    self.emulator.reg_write(regDict[f"R{i}X"], int.from_bytes(bytes(init), byteorder='little'))
                    return
                elif reg == f"{i}L":
                    init = bytearray(self.emulator.reg_read(regDict[f"R{i}X"]).to_bytes(8, 'little'))
                    toSet = bytearray(value.to_bytes(8, 'little'))
                    init[0] = toSet[0]
                    self.emulator.reg_write(regDict[f"R{i}X"], int.from_bytes(bytes(init), byteorder='little'))
                    return
                elif reg == f"{i}H":
                    init = bytearray(self.emulator.reg_read(regDict[f"R{i}X"]).to_bytes(8, 'little'))
                    toSet = bytearray(value.to_bytes(8, 'little'))
                    init[1] = toSet[1]
                    self.emulator.reg_write(regDict[f"R{i}X"], int.from_bytes(bytes(init), byteorder='little'))
                    return

            for i in {"BP","SI","DI","SP", "IP"}:
                if reg == f"R{i}":
                    self.emulator.reg_write(regDict[f"R{i}"], values[d])
                    return
                elif reg == f"E{i}":
                    init = bytearray(self.emulator.reg_read(regDict[f"R{i}"]).to_bytes(8, 'little'))
                    toSet = bytearray(value.to_bytes(8, 'little'))
                    init[0] = toSet[0]
                    init[1] = toSet[1]
                    init[2] = toSet[2]
                    init[3] = toSet[3]
                    self.emulator.reg_write(regDict[f"R{i}"], int.from_bytes(bytes(init), byteorder='little'))
                    return
                elif reg == f"{i}":
                    init = bytearray(self.emulator.reg_read(regDict[f"R{i}"]).to_bytes(8, 'little'))
                    toSet = bytearray(value.to_bytes(8, 'little'))
                    init[0] = toSet[0]
                    init[1] = toSet[1]
                    self.emulator.reg_write(regDict[f"R{i}"], int.from_bytes(bytes(init), byteorder='little'))
                    return
                elif reg == f"{i}L":
                    init = bytearray(self.emulator.reg_read(regDict[f"R{i}"]).to_bytes(8, 'little'))
                    toSet = bytearray(value.to_bytes(8, 'little'))
                    init[0] = toSet[0]
                    self.emulator.reg_write(regDict[f"R{i}"], int.from_bytes(bytes(init), byteorder='little'))
                    return

            for i in range(8,16):
                if reg == f"R{i}":
                    self.emulator.reg_write(regDict[f"R{i}"], values[d])
                    return
                elif reg ==  f"R{i}D":
                    init = bytearray(self.emulator.reg_read(regDict[f"R{i}"]).to_bytes(8, 'little'))
                    toSet = bytearray(value.to_bytes(8, 'little'))
                    init[0] = toSet[0]
                    init[1] = toSet[1]
                    init[2] = toSet[2]
                    init[3] = toSet[3]
                    self.emulator.reg_write(regDict[f"R{i}"], int.from_bytes(bytes(init), byteorder='little'))
                    return
                elif reg ==  f"R{i}W":
                    init = bytearray(self.emulator.reg_read(regDict[f"R{i}"]).to_bytes(8, 'little'))
                    toSet = bytearray(value.to_bytes(8, 'little'))
                    init[0] = toSet[0]
                    init[1] = toSet[1]
                    self.emulator.reg_write(regDict[f"R{i}"], int.from_bytes(bytes(init), byteorder='little'))
                    return
                elif reg ==  f"R{i}B":
                    init = bytearray(self.emulator.reg_read(regDict[f"R{i}"]).to_bytes(8, 'little'))
                    toSet = bytearray(value.to_bytes(8, 'little'))
                    init[0] = toSet[0]
                    self.emulator.reg_write(regDict[f"R{i}"], int.from_bytes(bytes(init), byteorder='little'))
                    return

            print(f"Unsupported identifier {reg}")
            exit(1)

        for d in values.keys():
            if d == "PC":
                pass
            # elif d == "RAX":
            #     self.emulator.reg_write(UC_X86_REG_RAX, values[d])
            # elif d == "RBX":
            #     self.emulator.reg_write(UC_X86_REG_RBX, values[d])
            # elif d == "RCX":
            #     self.emulator.reg_write(UC_X86_REG_RCX, values[d])
            # elif d == "RDX":
            #     self.emulator.reg_write(UC_X86_REG_RDX, values[d])
            # elif d == "RDI":
            #     self.emulator.reg_write(UC_X86_REG_RDI, values[d])
            # elif d == "RSI":
            #     self.emulator.reg_write(UC_X86_REG_RSI, values[d])
            # elif d == "RSP":
            #     self.emulator.reg_write(UC_X86_REG_RSP, values[d])
            # elif d == "RBP":
            #     self.emulator.reg_write(UC_X86_REG_RBP, values[d])
            # elif d == "R8":
            #     self.emulator.reg_write(UC_X86_REG_R8, values[d])
            # elif d == "R9":
            #     self.emulator.reg_write(UC_X86_REG_R9, values[d])
            # elif d == "R10":
            #     self.emulator.reg_write(UC_X86_REG_R10, values[d])
            # elif d == "R11":
            #     self.emulator.reg_write(UC_X86_REG_R11, values[d])
            # elif d == "R12":
            #     self.emulator.reg_write(UC_X86_REG_R12, values[d])
            # elif d == "R13":
            #     self.emulator.reg_write(UC_X86_REG_R13, values[d])
            # elif d == "R14":
            #     self.emulator.reg_write(UC_X86_REG_R14, values[d])
            elif type(d) is int:
                self.emulator.mem_write(d, bytes(values[d]))
            elif d in {"CF", "PF", "AF", "ZF", "SF", "TF", "IF", "DF", "OF", "AC"}:
                setFlag(self.emulator, d, values[d])
            else:
                setRegister(self.emulator, d, values[d])




    def print_state(self, oneline: bool = False):
        def compressed(val: str):
            return f"0x{val:<16x}" if val < self.r14_init else f"+0x{val - self.r14_init:<15x}"

        emulator = self.emulator
        rax = compressed(emulator.reg_read(UC_X86_REG_RAX))
        rbx = compressed(emulator.reg_read(UC_X86_REG_RBX))
        rcx = compressed(emulator.reg_read(UC_X86_REG_RCX))
        rdx = compressed(emulator.reg_read(UC_X86_REG_RDX))
        rsi = compressed(emulator.reg_read(UC_X86_REG_RSI))
        rdi = compressed(emulator.reg_read(UC_X86_REG_RDI))

        if not oneline:
            print("\n\nRegisters:")
            print(f"RAX: {rax}")
            print(f"RBX: {rbx}")
            print(f"RCX: {rcx}")
            print(f"RDX: {rdx}")
            print(f"RSI: {rsi}")
            print(f"RDI: {rdi}")
        else:
            print(f"rax={rax} "
                  f"rbx={rbx} "
                  f"rcx={rcx} "
                  f"rdx={rdx} "
                  f"flags={emulator.reg_read(UC_X86_REG_EFLAGS):012b}")

    @staticmethod
    def trace_mem_access(emulator, access, address, size, value, model):
        pass  # Implemented by subclasses

    @staticmethod
    def trace_code(emulator: Uc, address, size, model) -> None:
        pass  # Implemented by subclasses

    @staticmethod
    def checkpoint(emulator, next_instruction):
        pass  # Implemented by subclasses

    def rollback(self):
        pass  # Implemented by subclasses

    def reset_model(self):
        pass  # Implemented by subclasses


class X86UnicornSeq(X86UnicornModel):
    """
    A simple, in-order contract.
    The only thing it does is tracing.
    No manipulation of the control or data flow.
    """

    @staticmethod
    def trace_mem_access(emulator, access, address: int, size, value, model):
        if model.dependencyTracker is not None:
            mode = "WRITE" if access == UC_MEM_WRITE else "READ"
            model.dependencyTracker.trackMemoryAccess(address,size,mode)
        model.tracer.observe_mem_access(access, address, size, value, model)

    @staticmethod
    def trace_code(emulator: Uc, address, size, model) -> None:
        if model.dependencyTracker is not None:
            model.dependencyTracker.finalizeTracking()
            code = bytes(emulator.mem_read(address, size))
            model.dependencyTracker.initialize(code)
        model.tracer.observe_instruction(address, size, model)




class X86UnicornSpec(X86UnicornModel):
    """
    Intermediary class for all speculative contracts.
    Tracks speculative stores
    """

    def __init__(self, *args):
        self.checkpoints = []
        self.store_logs = []
        self.previous_store = (0, 0, 0, 0)
        self.latest_rollback_address = 0
        super(X86UnicornSpec, self).__init__(*args)

    @staticmethod
    def trace_mem_access(emulator, access, address, size, value, model):
        # when in speculation, log all changes to memory
        if access == UC_MEM_WRITE and model.store_logs:
            model.store_logs[-1].append((address, emulator.mem_read(address, 8)))

        model.tracer.observe_mem_access(access, address, size, value, model)

    @staticmethod
    def trace_code(emulator: Uc, address, size, model) -> None:
        model.speculation_window += 1

        if model.in_speculation:
            # rollback on a serializing instruction (lfence, sfence, mfence)
            if emulator.mem_read(address, size) in [b'\x0F\xAE\xE8', b'\x0F\xAE\xF8',
                                                    b'\x0F\xAE\xF0']:
                emulator.emu_stop()

            # and on expired speculation window
            if model.speculation_window > CONF.max_speculation_window:
                emulator.emu_stop()

        model.tracer.observe_instruction(address, size, model)

    def checkpoint(self, emulator, next_instruction):
        flags = emulator.reg_read(UC_X86_REG_EFLAGS)
        context = emulator.context_save()
        spec_window = self.speculation_window
        self.checkpoints.append((context, next_instruction, flags, spec_window))
        self.store_logs.append([])
        self.in_speculation = True

    def rollback(self):
        # restore register values
        state, next_instr, flags, spec_window = self.checkpoints.pop()
        if not self.checkpoints:
            self.in_speculation = False

        self.latest_rollback_address = next_instr

        # restore the speculation state
        self.emulator.context_restore(state)
        self.speculation_window = spec_window

        # rollback memory changes
        mem_changes = self.store_logs.pop()
        while mem_changes:
            addr, val = mem_changes.pop()
            self.emulator.mem_write(addr, bytes(val))

        # if there are any pending speculative store bypasses, cancel them
        self.previous_store = (0, 0, 0, 0)

        # restore the flags last, to avoid corruption by other operations
        self.emulator.reg_write(UC_X86_REG_EFLAGS, flags)

        # restart without misprediction
        self.emulator.emu_start(next_instr, self.code_base + len(self.code), timeout=10000)

    def reset_model(self):
        self.latest_rollback_address = 0


class X86UnicornCond(X86UnicornSpec):
    """
    Contract for conditional branch mispredicitons.
    Forces all cond. branches to speculatively go into a wrong target
    """

    jumps = {
        # c - the byte code of the instruction
        # f - the value of EFLAGS
        0x70: lambda c, f, r: (c[1:], f & FLAGS_OF != 0, False),  # JO
        0x71: lambda c, f, r: (c[1:], f & FLAGS_OF == 0, False),  # JNO
        0x72: lambda c, f, r: (c[1:], f & FLAGS_CF != 0, False),  # JB
        0x73: lambda c, f, r: (c[1:], f & FLAGS_CF == 0, False),  # JAE
        0x74: lambda c, f, r: (c[1:], f & FLAGS_ZF != 0, False),  # JZ
        0x75: lambda c, f, r: (c[1:], f & FLAGS_ZF == 0, False),  # JNZ
        0x76: lambda c, f, r: (c[1:], f & FLAGS_CF != 0 or f & FLAGS_ZF != 0, False),  # JNA
        0x77: lambda c, f, r: (c[1:], f & FLAGS_CF == 0 and f & FLAGS_ZF == 0, False),  # JNBE
        0x78: lambda c, f, r: (c[1:], f & FLAGS_SF != 0, False),  # JS
        0x79: lambda c, f, r: (c[1:], f & FLAGS_SF == 0, False),  # JNS
        0x7A: lambda c, f, r: (c[1:], f & FLAGS_PF != 0, False),  # JP
        0x7B: lambda c, f, r: (c[1:], f & FLAGS_PF == 0, False),  # JPO
        0x7C: lambda c, f, r: (c[1:], (f & FLAGS_SF == 0) != (f & FLAGS_OF == 0), False),  # JNGE
        0x7D: lambda c, f, r: (c[1:], (f & FLAGS_SF == 0) == (f & FLAGS_OF == 0), False),  # JNL
        0x7E: lambda c, f, r:
        (c[1:], f & FLAGS_ZF != 0 or (f & FLAGS_SF == 0) != (f & FLAGS_OF == 0), False),
        0x7F: lambda c, f, r:
        (c[1:], f & FLAGS_ZF == 0 and (f & FLAGS_SF == 0) == (f & FLAGS_OF == 0), False),
        0xE0: lambda c, f, r: (c[1:], r != 1 and (f & FLAGS_ZF == 0), True),  # LOOPNE
        0xE1: lambda c, f, r: (c[1:], r != 1 and (f & FLAGS_ZF != 0), True),  # LOOPE
        0xE2: lambda c, f, r: (c[1:], r != 1, True),  # LOOP
        0xE3: lambda c, f, r: (c[1:], r == 0, False),  # J*CXZ
        0x0F: lambda c, f, r:
        X86UnicornCond.multibyte_jmp.get(c[1], (lambda _, __, ___: ([0], False, False)))(c, f, r)
    }

    multibyte_jmp = {
        0x80: lambda c, f, r: (c[2:], f & FLAGS_OF != 0, False),  # JO
        0x81: lambda c, f, r: (c[2:], f & FLAGS_OF == 0, False),  # JNO
        0x82: lambda c, f, r: (c[2:], f & FLAGS_CF != 0, False),  # JB
        0x83: lambda c, f, r: (c[2:], f & FLAGS_CF == 0, False),  # JAE
        0x84: lambda c, f, r: (c[2:], f & FLAGS_ZF != 0, False),  # JE
        0x85: lambda c, f, r: (c[2:], f & FLAGS_ZF == 0, False),  # JNE
        0x86: lambda c, f, r: (c[2:], f & FLAGS_CF != 0 or f & FLAGS_ZF != 0, False),  # JBE
        0x87: lambda c, f, r: (c[2:], f & FLAGS_CF == 0 and f & FLAGS_ZF == 0, False),  # JA
        0x88: lambda c, f, r: (c[2:], f & FLAGS_SF != 0, False),  # JS
        0x89: lambda c, f, r: (c[2:], f & FLAGS_SF == 0, False),  # JNS
        0x8A: lambda c, f, r: (c[2:], f & FLAGS_PF != 0, False),  # JP
        0x8B: lambda c, f, r: (c[2:], f & FLAGS_PF == 0, False),  # JPO
        0x8C: lambda c, f, r: (c[2:], (f & FLAGS_SF == 0) != (f & FLAGS_OF == 0), False),  # JNGE
        0x8D: lambda c, f, r: (c[2:], (f & FLAGS_SF == 0) == (f & FLAGS_OF == 0), False),  # JNL
        0x8E: lambda c, f, r:
        (c[2:], f & FLAGS_ZF != 0 or (f & FLAGS_SF == 0) != (f & FLAGS_OF == 0), False),
        0x8F: lambda c, f, r:
        (c[2:], f & FLAGS_ZF == 0 and (f & FLAGS_SF == 0) == (f & FLAGS_OF == 0), False),
    }

    @staticmethod
    def trace_code(emulator: Uc, address, size, model) -> None:
        X86UnicornSpec.trace_code(emulator, address, size, model)

        # reached max spec. window? skip
        if len(model.checkpoints) >= model.nesting:
            return

        # decode the instruction
        code = emulator.mem_read(address, size)
        flags = emulator.reg_read(UC_X86_REG_EFLAGS)
        rcx = emulator.reg_read(UC_X86_REG_RCX)
        target, will_jump, is_loop = X86UnicornCond.decode(code, flags, rcx)

        # not a a cond. jump? ignore
        if not target:
            return

        # LOOP instructions must also decrement RCX
        if is_loop:
            emulator.reg_write(UC_X86_REG_RCX, rcx - 1)

        # Take a checkpoint
        next_instr = address + size + target if will_jump else address + size
        model.checkpoint(emulator, next_instr)

        # Simulate misprediction
        if will_jump:
            emulator.reg_write(UC_X86_REG_RIP, address + size)
        else:
            emulator.reg_write(UC_X86_REG_RIP, address + size + target)

    @staticmethod
    def decode(code: bytearray, flags: int, rcx: int) -> (int, bool, bool):
        """
        Decodes the instruction encoded in `code` and, if it's a conditional jump,
        returns its expected target, whether it will jump to the target (based
        on the `flags` value), and whether it is a LOOP instruction
        """
        calculate_target = X86UnicornCond.jumps.get(code[0],
                                                    (lambda _, __, ___: ([0], False, False)))
        target, will_jump, is_loop = calculate_target(code, flags, rcx)
        if len(target) == 1:
            return target[0], will_jump, is_loop
        return int.from_bytes(target, byteorder='little'), will_jump, is_loop


class X86UnicornBpas(X86UnicornSpec):
    @staticmethod
    def trace_mem_access(emulator, access, address, size, value, model):
        """
        Since Unicorn does not have post-instruction hooks,
        I have to implement it in a dirty way:
        Save the information about the store here, but execute all the
        contract logic in a hook before the next instruction (see trace_code)
        """
        if access == UC_MEM_WRITE:
            rip = emulator.reg_read(UC_X86_REG_RIP)
            opcode = emulator.mem_read(rip, 1)[0]
            if opcode not in [0xE8, 0xFF, 0x9A]:  # ignore CALL instructions
                model.previous_store = (address, size, emulator.mem_read(address, size), value)

        X86UnicornSpec.trace_mem_access(emulator, access, address, size, value, model)

    @staticmethod
    def trace_code(emulator: Uc, address, size, model) -> None:
        X86UnicornSpec.trace_code(emulator, address, size, model)

        # reached max spec. window? skip
        if len(model.checkpoints) >= model.nesting:
            return

        if model.previous_store[0]:
            store_addr = model.previous_store[0]
            old_value = bytes(model.previous_store[2])
            new_is_signed = model.previous_store[3] < 0
            new_value = (model.previous_store[3]). \
                to_bytes(model.previous_store[1], byteorder='little', signed=new_is_signed)

            # store a checkpoint
            model.checkpoint(emulator, address)

            # cancel the previous store but preserve its value
            emulator.mem_write(store_addr, old_value)
            model.store_logs[-1].append((store_addr, new_value))
        model.previous_store = (0, 0, 0, 0)


class X86UnicornNull(X86UnicornSpec):
    instruction_address: int

    @staticmethod
    def trace_mem_access(emulator, access, address, size, value, model):
        X86UnicornSpec.trace_mem_access(emulator, access, address, size, value, model)

        # reached max spec. window? skip
        if len(model.checkpoints) >= model.nesting:
            return

        # applicable only to loads
        if access == UC_MEM_WRITE:
            return

        # make sure we do not repeat the same injection all over again
        if model.instruction_address == model.latest_rollback_address:
            return

        # store a checkpoint
        model.checkpoint(emulator, model.instruction_address)
        model.store_logs[-1].append((address, emulator.mem_read(address, 8)))

        # emulate zero-injection by writing zero to the target address of the load
        zero_value = bytes([0 for _ in range(size)])
        emulator.mem_write(address, zero_value)

    @staticmethod
    def trace_code(emulator: Uc, address, size, model) -> None:
        X86UnicornSpec.trace_code(emulator, address, size, model)
        model.instruction_address = address


class X86UnicornCondBpas(X86UnicornSpec):
    @staticmethod
    def trace_mem_access(emulator, access, address, size, value, model):
        X86UnicornBpas.trace_mem_access(emulator, access, address, size, value, model)

    @staticmethod
    def trace_code(emulator: Uc, address, size, model):
        X86UnicornCond.trace_code(emulator, address, size, model)
        X86UnicornBpas.trace_code(emulator, address, size, model)


def get_model(bases) -> Model:
    if CONF.model == 'x86-unicorn':
        # functional part of the contract
        if "cond" in CONF.contract_execution_mode and "bpas" in CONF.contract_execution_mode:
            model = X86UnicornCondBpas(bases[0], bases[1], bases[2])
        elif "cond" in CONF.contract_execution_mode:
            model = X86UnicornCond(bases[0], bases[1], bases[2])
        elif "bpas" in CONF.contract_execution_mode:
            model = X86UnicornBpas(bases[0], bases[1], bases[2])
        elif "null-injection" in CONF.contract_execution_mode:
            model = X86UnicornNull(bases[0], bases[1], bases[2])
        elif "seq" in CONF.contract_execution_mode:
            model = X86UnicornSeq(bases[0], bases[1], bases[2])
        else:
            print("Error: unknown value of `contract_execution_mode` configuration option")
            exit(1)

        # observational part of the contract
        if CONF.contract_observation_mode == "l1d":
            model.tracer = L1DTracer()
        elif CONF.contract_observation_mode == 'pc':
            model.tracer = PCTracer()
        elif CONF.contract_observation_mode == 'memory':
            model.tracer = MemoryTracer()
        elif CONF.contract_observation_mode == 'ct':
            model.tracer = CTTracer()
        elif CONF.contract_observation_mode == 'ct-nonspecstore':
            model.tracer = CTNonSpecStoreTracer()
        elif CONF.contract_observation_mode == 'ctr':
            model.tracer = CTRTracer()
        elif CONF.contract_observation_mode == 'arch':
            model.tracer = ArchTracer()
        else:
            print("Error: unknown value of `contract_observation_mode` configuration option")
            exit(1)

        if CONF.equivalence_class_boost:
            model.dependencyTracker = DependencyTracker(64)

        return model
    else:
        print("Error: unknown value of `model` configuration option")
        exit(1)
