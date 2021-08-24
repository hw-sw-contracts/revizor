"""
File: Executor Interface

Copyright (C) 2021 Oleksii Oleksenko
Copyright (C) 2020 Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from abc import ABC, abstractmethod
from collections import Counter
import subprocess
import os.path

from helpers import assemble, load_measurement, write_to_pseudo_file, write_to_pseudo_file_bytes
from custom_types import List, Tuple, CombinedHTrace, Dependencies
from config import CONF


class Executor(ABC):
    coverage = None

    @abstractmethod
    def load_test_case(self, test_case_asm: str):
        pass

    @abstractmethod
    def trace_test_case(self, inputs: List[int], deps:List[Dependencies] = [], num_measurements: int = 0) \
            -> List[CombinedHTrace]:
        pass

    @abstractmethod
    def read_base_addresses(self) -> Tuple[int, int, int]:
        pass

    def set_coverage(self, coverage):
        self.coverage = coverage


class X86Intel(Executor):
    previous_num_inputs: int = 0

    def __init__(self):
        super().__init__()
        write_to_pseudo_file(CONF.warmups, '/sys/x86-executor/warmups')
        write_to_pseudo_file("1" if CONF.enable_ssbp_patch else "0",
                             "/sys/x86-executor/enable_ssbp_patch")
        write_to_pseudo_file("1" if CONF.enable_pre_run_flush else "0",
                             "/sys/x86-executor/enable_pre_run_flush")
        write_to_pseudo_file("1" if CONF.enable_mds else "0",
                             "/sys/x86-executor/enable_mds")
        write_to_pseudo_file(CONF.attack_variant, "/sys/x86-executor/measurement_mode")
        write_to_pseudo_file("1" if CONF.equivalence_class_boost else "0",
                             "/sys/x86-executor/enable_deltas")

    def load_test_case(self, test_case_asm: str):
        assemble(test_case_asm, 'generated.o')
        write_to_pseudo_file("generated.o", "/sys/x86-executor/code")

    def trace_test_case(self, inputs: List[int], deps:List[Dependencies] = [], num_measurements: int = 0, priming: bool = False) \
            -> List[CombinedHTrace]:
            
        # make sure it's not a dummy call
        if not inputs:
            return []

        # is kernel module ready?
        if not os.path.isfile("/proc/x86-executor"):
            print("Error: x86 Intel Executor: kernel module not loaded")

        # change inputs if there are delta snapshots
        inputs_ = inputs.copy()
        if deps != []:

            if len(inputs) != len(deps):
                print("Lenght of inputs and deps is different!")
                exit(1)

            if not(CONF.equivalence_class_boost):
                print("Deps are unsupported")
                exit(1)

            dependencies = []
            delta_inputs = []
            if not priming:
                delta_inputs = [inputs_[i] for i in range(CONF.boost_threshold, len(inputs_))]
                for i in range(len(inputs_)):
                    if i < CONF.boost_threshold:
                        dependencies.append(deps[i][2])
                    else:
                        # i >= CONF.boost_threshold: replace input
                        inputs_[i] = deps[i][1]
            else:
                inputs_ = [d[1] for d in deps ]
                delta_inputs = [d[0] for d in deps]
                dependencies = [d[2] for d in deps]

            # for i in range(len(inputs_)):
            #     if i < CONF.boost_threshold:
            #         dependencies.append(deltas[i])
            #     else:
            #         # i >= CONF.boost_threshold: replace input
            #         inputs_[i] = old_inputs[deltas[i]]

        if num_measurements == 0:
            num_measurements = CONF.num_measurements

        # set entropy
        input_mask = pow(2, (CONF.prng_entropy_bits % 33)) - 1
        write_to_pseudo_file(input_mask, '/sys/x86-executor/input_mask')

        # convert the inputs into a byte sequence
        byte_inputs = bytes().join([ i.to_bytes(8, byteorder='little') for i in inputs_ ])

        # protocol of loading inputs (must be in this order):
        # 1) Announce the number of inputs
        write_to_pseudo_file(str(len(inputs_)), "/sys/x86-executor/n_inputs")
        # 2) Load the inputs
        write_to_pseudo_file_bytes(byte_inputs, "/sys/x86-executor/inputs")
        # 3) Check that the load was successful
        with open('/sys/x86-executor/n_inputs', 'r') as f:
            if f.readline() == '0\n':
                print("Failure loading inputs!")
                raise Exception()

        # 4) Write the delta information
        if deps != []:
            # 1. prepare dependencies 
            deps_size = 0
            deps_bytes = []
            for d in dependencies:
                sandbox_base, stack_base, code_base = self.read_base_addresses()
                # collect memory dependencies relative to sandbox base
                # mem_deps = [ (i - sandbox_base) for i in d.keys() if isinstance(i, int)]
                mem_deps = [ i for i in d.keys() if isinstance(i, int)]
                mem_deps.sort()
                if len(mem_deps) > 255:
                    print("We only support at most 255 dependencies!")
                    exit(1)
                ## Each dependency is encoded with at most 4 bytes
                mem_bytes = [ i.to_bytes(8, byteorder='little') for i in mem_deps]
                len_byte = len(mem_deps).to_bytes(1, byteorder='little')
                deps_bytes += [len_byte]
                deps_bytes += mem_bytes
                deps_size += 1 + 8 * len(mem_deps)
            
            # 2. write dependencies 
            write_to_pseudo_file(str(deps_size), "/sys/x86-executor/deps_size")
            write_to_pseudo_file_bytes(bytes().join(deps_bytes), "/sys/x86-executor/deps")
            with open('/sys/x86-executor/deps', 'r') as f:
                if f.readline() == '0\n':
                    print("Failure loading dependencies!")
                    raise Exception()
            
            # 3. write delta_threshold
            if not priming:
                write_to_pseudo_file(str(CONF.boost_threshold), "/sys/x86-executor/delta_threshold")
            else:
                write_to_pseudo_file(str(0), "/sys/x86-executor/delta_threshold")

            # 4. prepare delta_inputs
            delta_inputs_bytes = bytes().join( [ i.to_bytes(8, byteorder='little') for i in delta_inputs ] )

            # 5. write delta_inputs
            write_to_pseudo_file(str(len(delta_inputs)), "/sys/x86-executor/delta_inputs_size")
            write_to_pseudo_file_bytes(delta_inputs_bytes, "/sys/x86-executor/delta_inputs")
            with open('/sys/x86-executor/delta_inputs', 'r') as f:
                if f.readline() == '0\n':
                    print("Failure loading delta inputs!")
                    raise Exception()

        traces = [[] for _ in inputs_]
        pfc_readings = [[[], [], []] for _ in inputs_]
        for _ in range(num_measurements):
            # measure
            subprocess.run(f"taskset -c {CONF.measurement_cpu} cat /proc/x86-executor "
                           "| sudo tee measurement.txt >/dev/null",
                           shell=True, check=True)
            # fetch the results
            for i, measurement in enumerate(load_measurement('measurement.txt')):
                traces[i].append(measurement[0])
                pfc_readings[i][0].append(measurement[1])
                pfc_readings[i][1].append(measurement[2])
                pfc_readings[i][2].append(measurement[3])

        if num_measurements == 1:
            if self.coverage:
                self.coverage.executor_hook([[r[0][0], r[1][0], r[2][0]] for r in pfc_readings])
            return [t[0] for t in traces]

        # remove outliers and merge
        merged_traces = [0 for _ in inputs_]
        for i, trace_list in enumerate(traces):
            num_occurrences = Counter()
            for trace in trace_list:
                num_occurrences[trace] += 1
                # print(pretty_bitmap(trace))
                if num_occurrences[trace] <= CONF.max_outliers:
                    # if we see too few occurrences of this specific htrace,
                    # it might be noise, ignore it for now
                    continue
                elif num_occurrences[trace] == CONF.max_outliers + 1:
                    # otherwise, merge it
                    merged_traces[i] |= trace

        # same for PFC readings, except select max. values instead of merging
        filtered_pfc_readings = [[0, 0, 0] for _ in inputs_]
        for i, reading_lists in enumerate(pfc_readings):
            num_occurrences = Counter()

            for reading in reading_lists[0]:
                num_occurrences[reading] += 1
                if num_occurrences[reading] <= CONF.max_outliers * 2:
                    # if we see too few occurrences of this specific htrace,
                    # it might be noise, ignore it for now
                    continue
                elif num_occurrences[reading] == CONF.max_outliers * 2 + 1:
                    # otherwise, update max
                    filtered_pfc_readings[i][0] = max(filtered_pfc_readings[i][0], reading)

        if self.coverage:
            self.coverage.executor_hook(filtered_pfc_readings)

        return merged_traces

    def read_base_addresses(self):
        with open('/sys/x86-executor/print_sandbox_base', 'r') as f:
            sandbox_base = f.readline()
        with open('/sys/x86-executor/print_stack_base', 'r') as f:
            stack_base = f.readline()
        with open('/sys/x86-executor/print_code_base', 'r') as f:
            code_base = f.readline()
        return int(sandbox_base, 16), int(stack_base, 16), int(code_base, 16)

class Dummy(Executor):

    code_base: int  = 4198400 
    sandbox_base: int = 5251072
    stack_base: int = 7340032

    
    def __init__(self):
        super().__init__()
        

    def load_test_case(self, test_case_asm: str):
        pass

    def trace_test_case(self, inputs: List[int], deltas:List = [], num_measurements: int = 0) \
            -> List[CombinedHTrace]:
        return [0 for i in range (0, len(inputs))]

    def read_base_addresses(self):
        return self.sandbox_base, self.stack_base, self.code_base

def get_executor() -> Executor:
    options = {
        'x86-intel': X86Intel,
        'dummy': Dummy
    }
    if CONF.executor not in options:
        print("Error: unknown executor in config.py")
        exit(1)
    return options[CONF.executor]()
