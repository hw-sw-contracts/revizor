"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import unittest
import sys

sys.path.insert(0, '..')
from model import TaintTracker
from interfaces import Instruction, RegisterOperand, MemoryOperand, InputTaint, LabelOperand, \
    FlagsOperand


class X86UnicornModelTest(unittest.TestCase):

    def test_dependency_tracking(self):
        tracker = TaintTracker([])

        # reg -> reg
        tracker.start_instruction(Instruction("ADD")
                                  .add_op(RegisterOperand("RAX", 64, True, True))
                                  .add_op(RegisterOperand("RBX", 64, True, False)))  # yapf: disable
        tracker._finalize_instruction()
        self.assertCountEqual(tracker.src_regs, ["A", "B"])
        self.assertCountEqual(tracker.dest_regs, ["A"])
        self.assertCountEqual(tracker.reg_dependencies['A'], ['A', 'B'])

        # chain of dependencies
        tracker.start_instruction(Instruction("MOV")
                                  .add_op(RegisterOperand("RCX", 64, False, True))
                                  .add_op(RegisterOperand("RAX", 64, True, False)))  # yapf: disable
        tracker._finalize_instruction()
        self.assertCountEqual(tracker.reg_dependencies['A'], ['A', 'B'])
        self.assertCountEqual(tracker.reg_dependencies['C'], ['A', 'B', 'C'])

        # memory -> reg
        tracker.start_instruction(Instruction("MOV")
                                  .add_op(RegisterOperand("RDX", 64, False, True))
                                  .add_op(MemoryOperand("RCX", 64, True, False)))  # yapf: disable
        tracker.track_memory_access(0x87, 8, False)
        tracker._finalize_instruction()
        self.assertCountEqual(tracker.reg_dependencies['D'], ['0x80', '0x88', 'D'])

        # reg -> mem
        tracker.start_instruction(Instruction("MOV")
                                  .add_op(MemoryOperand("RAX", 64, False, True))
                                  .add_op(RegisterOperand("RSI", 64, True, False)))  # yapf: disable
        tracker.track_memory_access(0x80, 8, True)
        tracker._finalize_instruction()
        self.assertCountEqual(tracker.mem_dependencies['0x80'], ['0x80', 'SI'])

        # store -> load
        tracker.start_instruction(Instruction("MOV")
                                  .add_op(RegisterOperand("RDI", 64, False, True))
                                  .add_op(MemoryOperand("RAX", 64, True, False)))  # yapf: disable
        tracker.track_memory_access(0x80, 8, False)
        tracker._finalize_instruction()
        self.assertCountEqual(tracker.reg_dependencies['DI'], ['SI', 'DI', '0x80'])

    def test_tainting(self):
        tracker = TaintTracker([])

        # Initial dependency
        tracker.start_instruction(Instruction("ADD")
                                  .add_op(RegisterOperand("RAX", 64, True, True))
                                  .add_op(RegisterOperand("RBX", 64, True, False)))  # yapf: disable
        tracker._finalize_instruction()
        tracker.start_instruction(Instruction("MOV")
                                  .add_op(MemoryOperand("RAX", 64, False, True))
                                  .add_op(RegisterOperand("RAX", 64, True, False)))  # yapf: disable
        tracker.track_memory_access(0x80, 8, True)
        tracker._finalize_instruction()

        # Taint memory address
        tracker.start_instruction(Instruction("MOV")
                                  .add_op(RegisterOperand("RBX", 64, True, False))
                                  .add_op(MemoryOperand("RCX + 8 -16", 64, False, True))
                                  )  # yapf: disable
        tracker.track_memory_access(0x80, 8, False)
        tracker.taint_memory_access_address()
        taint: InputTaint = tracker.get_taint()
        reg_offset = taint.register_start

        self.assertCountEqual(tracker.mem_dependencies['0x80'], ['A', 'B', '0x80'])
        self.assertCountEqual(tracker.tainted_labels, {'C'})
        self.assertEqual(taint[reg_offset + 2], True)  # RCX

        # Taint PC
        tracker.tainted_labels = set()
        tracker.start_instruction(Instruction("CMPC")
                                  .add_op(RegisterOperand("RAX", 64, True, False))
                                  .add_op(RegisterOperand("RDX", 64, True, False))
                                  .add_op(FlagsOperand(["w", "", "", "", "", "", "", "", ""]), True)
                                  )  # yapf: disable
        tracker._finalize_instruction()
        jmp_instruction = Instruction("JC").add_op(LabelOperand(".bb0"))\
                          .add_op(FlagsOperand(["r", "", "", "", "", "", "", "", ""]), True)\
                          .add_op(RegisterOperand("RIP", 64, True, True), True)
        jmp_instruction.control_flow = True
        tracker.start_instruction(jmp_instruction)
        tracker.taint_pc()
        taint: InputTaint = tracker.get_taint()
        self.assertEqual(taint[reg_offset], True)  # RAX - through flags
        self.assertEqual(taint[reg_offset + 1], True)  # RBX - through flags + register
        self.assertEqual(taint[reg_offset + 3], True)  # RDX - through flags

        # Taint load value
        tracker.tainted_labels = set()
        tracker.start_instruction(Instruction("MOV")
                                  .add_op(RegisterOperand("RBX", 64, False, True))
                                  .add_op(MemoryOperand("RCX", 64, True, False))
                                  )  # yapf: disable
        tracker.track_memory_access(0x80, 8, is_write=False)
        tracker.taint_memory_load()
        taint: InputTaint = tracker.get_taint()
        # 0x80 -> A -> [A, B]
        self.assertEqual(taint[reg_offset + 0], True)
        self.assertEqual(taint[reg_offset + 1], True)

    def test_label_to_taint(self):
        tracker = TaintTracker([])
        tracker.tainted_labels = {'0x0', '0x40', '0x640', 'D', 'SI', '8', '14', 'DF', 'RIP'}
        taint: InputTaint = tracker.get_taint()
        register_start = taint.register_start
        taint_size = taint.size

        expected = [False for i in range(taint_size)]
        expected[0] = True  # 0x0
        expected[8] = True  # 0x40
        expected[200] = True  # 640
        expected[register_start + 3] = True  # D
        expected[register_start + 4] = True  # SI
        expected[register_start + 6] = True  # DF - flags
        # 8, 14, RIP - not a part of the input

        self.assertListEqual(list(taint), expected)



if __name__ == '__main__':
    unittest.main()
