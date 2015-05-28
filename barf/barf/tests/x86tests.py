# Copyright (c) 2014, Fundacion Dr. Manuel Sadosky
# All rights reserved.

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:

# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.

# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import os
import pickle
import random
import unittest

import pyasmjit

from barf.arch import ARCH_X86_MODE_32
from barf.arch import ARCH_X86_MODE_64
from barf.arch.x86.x86base import X86ArchitectureInformation
from barf.arch.x86.x86parser import X86Parser
from barf.arch.x86.x86translator import FULL_TRANSLATION
from barf.arch.x86.x86translator import X86Translator
from barf.core.reil import ReilEmulator
from barf.core.smt.smtlibv2 import Z3Solver as SmtSolver
from barf.core.smt.smttranslator import SmtTranslator


class X86Parser32BitsTests(unittest.TestCase):

    def setUp(self):
        self._parser = X86Parser(ARCH_X86_MODE_32)

    def test_two_oprnd_reg_reg(self):
        asm = self._parser.parse("add eax, ebx")

        self.assertEqual(str(asm), "add eax, ebx")

    def test_two_oprnd_reg_imm(self):
        asm = self._parser.parse("add eax, 0x12345678")

        self.assertEqual(str(asm), "add eax, 0x12345678")

    def test_two_oprnd_reg_mem(self):
        asm = self._parser.parse("add eax, [ebx + edx * 4 + 0x10]")

        self.assertEqual(str(asm), "add eax, [ebx+edx*4+0x10]")

    def test_two_oprnd_mem_reg(self):
        asm = self._parser.parse("add [ebx + edx * 4 + 0x10], eax")

        self.assertEqual(str(asm), "add [ebx+edx*4+0x10], eax")

    def test_one_oprnd_reg(self):
        asm = self._parser.parse("inc eax")

        self.assertEqual(str(asm), "inc eax")

    def test_one_oprnd_imm(self):
        asm = self._parser.parse("jmp 0x12345678")

        self.assertEqual(str(asm), "jmp 0x12345678")

    def test_one_oprnd_mem(self):
        asm = self._parser.parse("inc dword ptr [ebx+edx*4+0x10]")

        self.assertEqual(str(asm), "inc dword ptr [ebx+edx*4+0x10]")

    def test_zero_oprnd(self):
        asm = self._parser.parse("nop")

        self.assertEqual(str(asm), "nop")

    # Misc
    # ======================================================================== #
    def test_misc_1(self):
        asm = self._parser.parse("mov dword ptr [-0x21524111], ecx")

        self.assertEqual(str(asm), "mov dword ptr [0xdeadbeef], ecx")

    def test_misc_2(self):
        asm = self._parser.parse("fucompi st(1)")

        self.assertEqual(str(asm), "fucompi st1")


class X86Parser64BitsTests(unittest.TestCase):

    def setUp(self):
        self._parser = X86Parser(ARCH_X86_MODE_64)

    def test_64_two_oprnd_reg_reg(self):
        asm = self._parser.parse("add rax, rbx")

        self.assertEqual(str(asm), "add rax, rbx")

    def test_64_two_oprnd_reg_reg_2(self):
        asm = self._parser.parse("add rax, r8")

        self.assertEqual(str(asm), "add rax, r8")

    def test_64_two_oprnd_reg_mem(self):
        asm = self._parser.parse("add rax, [rbx + r15 * 4 + 0x10]")

        self.assertEqual(str(asm), "add rax, [rbx+r15*4+0x10]")

    # Misc
    # ======================================================================== #
    def test_misc_offset_1(self):
        asm = self._parser.parse("add byte ptr [rax+0xffffff89], cl")

        self.assertEqual(str(asm), "add byte ptr [rax+0xffffff89], cl")

class X86TranslationTests(unittest.TestCase):

    def setUp(self):
        self.trans_mode = FULL_TRANSLATION

        self.arch_mode = ARCH_X86_MODE_64

        self.arch_info = X86ArchitectureInformation(self.arch_mode)

        self.x86_parser = X86Parser(self.arch_mode)
        self.x86_translator = X86Translator(self.arch_mode, self.trans_mode)
        self.smt_solver = SmtSolver()
        self.smt_translator = SmtTranslator(self.smt_solver, self.arch_info.address_size)
        self.reil_emulator = ReilEmulator(self.arch_info.address_size)

        self.reil_emulator.set_arch_registers(self.arch_info.registers_gp_all)
        self.reil_emulator.set_arch_registers_size(self.arch_info.registers_size)
        self.reil_emulator.set_reg_access_mapper(self.arch_info.alias_mapper)

        self.smt_translator.set_reg_access_mapper(self.arch_info.alias_mapper)
        self.smt_translator.set_arch_registers_size(self.arch_info.registers_size)

        self.context_filename = "failing_context.data"

    def test_lea(self):
        asm = ["lea eax, [ebx + 0x100]"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cld(self):
        asm = ["cld"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_clc(self):
        asm = ["clc"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_nop(self):
        asm = ["nop"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_test(self):
        asm = ["test eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        # Undefined flags...
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "af")

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_not(self):
        asm = ["not eax"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_xor(self):
        asm = ["xor eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        # Undefined flags...
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "af")

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_or(self):
        asm = ["or eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        # Undefined flags...
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "af")

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_and(self):
        asm = ["and eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        # Undefined flags...
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "af")

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cmp(self):
        asm = ["cmp eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_neg(self):
        asm = ["neg eax"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_dec(self):
        asm = ["dec eax"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_inc(self):
        asm = ["inc eax"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_div(self):
        asm = ["div ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = {
            'rax'    : 0x10,
            'rbx'    : 0x2,
            'rdx'    : 0x0,
            'rflags' : 0x202,
        }

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        # Undefined flags...
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "cf")
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "of")
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "sf")
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "zf")
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "af")
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "pf")

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    # TODO: Uncomment once imul translation gets fixed.
    # def test_imul(self):
    #     asm = ["imul eax, ebx"]

    #     x86_instrs = map(self.x86_parser.parse, asm)

    #     self.__set_address(0xdeadbeef, x86_instrs)

    #     reil_instrs = map(self.x86_translator.translate, x86_instrs)

    #     ctx_init = self.__init_context()

    #     x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
    #     reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
    #         reil_instrs,
    #         0xdeadbeef << 8,
    #         context=ctx_init
    #     )

    #     # Undefined flags...
    #     reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "sf")
    #     reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "zf")
    #     reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "af")
    #     reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "pf")

    #     reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

    #     cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

    #     if not cmp_result:
    #         self.__save_failing_context(ctx_init)

    #     self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_mul(self):
        asm = ["mul ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        # Undefined flags...
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "sf")
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "zf")
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "af")
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "pf")

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_sbb(self):
        asm = ["sbb eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        # FIX: Remove this once the sbb translation gets fixed.
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "of")

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_sub(self):
        asm = ["sub eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_adc(self):
        asm = ["adc eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_add(self):
        asm = ["add eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_xchg(self):
        asm = ["xchg eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_movzx(self):
        asm = ["movzx eax, bx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_mov(self):
        asm = ["mov eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cmova(self):
        asm = ["cmova eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cmovae(self):
        asm = ["cmovae eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cmovb(self):
        asm = ["cmovb eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cmovbe(self):
        asm = ["cmovbe eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cmovc(self):
        asm = ["cmovc eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cmove(self):
        asm = ["cmove eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cmovg(self):
        asm = ["cmovg eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cmovge(self):
        asm = ["cmovge eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cmovl(self):
        asm = ["cmovl eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cmovle(self):
        asm = ["cmovle eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cmovna(self):
        asm = ["cmovna eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cmovnae(self):
        asm = ["cmovnae eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cmovnb(self):
        asm = ["cmovnb eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cmovnbe(self):
        asm = ["cmovnbe eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cmovnc(self):
        asm = ["cmovnc eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cmovne(self):
        asm = ["cmovne eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cmovng(self):
        asm = ["cmovng eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cmovnge(self):
        asm = ["cmovnge eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cmovnl(self):
        asm = ["cmovnl eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cmovnle(self):
        asm = ["cmovnle eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cmovno(self):
        asm = ["cmovno eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cmovnp(self):
        asm = ["cmovnp eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cmovns(self):
        asm = ["cmovns eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cmovnz(self):
        asm = ["cmovnz eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cmovo(self):
        asm = ["cmovo eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cmovp(self):
        asm = ["cmovp eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cmovpe(self):
        asm = ["cmovpe eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cmovpo(self):
        asm = ["cmovpo eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cmovs(self):
        asm = ["cmovs eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cmovz(self):
        asm = ["cmovz eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_seta(self):
        asm = ["seta al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_setae(self):
        asm = ["setae al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_setb(self):
        asm = ["setb al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_setbe(self):
        asm = ["setbe al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_setc(self):
        asm = ["setc al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_sete(self):
        asm = ["sete al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_setg(self):
        asm = ["setg al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_setge(self):
        asm = ["setge al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_setl(self):
        asm = ["setl al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_setle(self):
        asm = ["setle al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_setna(self):
        asm = ["setna al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_setnae(self):
        asm = ["setnae al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_setnb(self):
        asm = ["setnb al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_setnbe(self):
        asm = ["setnbe al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_setnc(self):
        asm = ["setnc al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_setne(self):
        asm = ["setne al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_setng(self):
        asm = ["setng al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_setnge(self):
        asm = ["setnge al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_setnl(self):
        asm = ["setnl al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_setnle(self):
        asm = ["setnle al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_setno(self):
        asm = ["setno al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_setnp(self):
        asm = ["setnp al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_setns(self):
        asm = ["setns al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_setnz(self):
        asm = ["setnz al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_seto(self):
        asm = ["seto al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_setp(self):
        asm = ["setp al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_setpe(self):
        asm = ["setpe al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_setpo(self):
        asm = ["setpo al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_sets(self):
        asm = ["sets al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_setz(self):
        asm = ["setz al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_all_jcc(self):
        conds = ['a','ae','b','be','c','e','g','ge','l','le','na','nae','nb','nbe','nc','ne','ng','nge','nl','nle','no','np','ns','nz','o','p','pe','po','s','z']
        for c in conds:
            self._test_jcc(c)
            
    def _test_jcc(self, jmp_cond):
        
        untouched_value = 0x45454545
        touched_value = 0x31313131

        asm = ["mov rax, 0x{:x}".format(untouched_value),
               "j" + jmp_cond + " {:s}",
               "mov rax, 0x{:x}".format(touched_value),
               "xchg rax, rax",
        ]
        
        asm_reil = list(asm)
        asm_reil[1] = asm_reil[1].format(str(0xdeadbeef + 0x3))
        
        asm_pyasmjit = list(asm)
        asm_pyasmjit[1] = asm_pyasmjit[1].format("$+0x07")
        
        x86_instrs = map(self.x86_parser.parse, asm_reil)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm_pyasmjit), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_shr(self):
        asm = ["shr eax, 3"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        # Undefined flags...
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "af")

        # NOTE: OF and CF can be left undefined in some cases. They are
        # not cover by this test.
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "cf")
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "of")

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_shl(self):
        asm = ["shl eax, 3"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        # Undefined flags...
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "af")

        # NOTE: OF and CF can be left undefined in some cases. They are
        # not cover by this test.
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "cf")
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "of")

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_sal(self):
        asm = ["sal eax, 3"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        # Undefined flags...
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "af")

        # NOTE: OF and CF can be left undefined in some cases. They are
        # not cover by this test.
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "cf")
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "of")

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_sar(self):
        asm = ["sar eax, 3"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        # Undefined flags...
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "af")

        # NOTE: OF and CF can be left undefined in some cases. They are
        # not cover by this test.
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "cf")
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "of")

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_stc(self):
        asm = ["stc"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)

        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_seta(self):
        asm = ["seta al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.execute("\n".join(asm), ctx_init)

        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_setne(self):
        asm = ["setne al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)

        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_sete(self):
        asm = ["sete al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)

        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_setb(self):
        asm = ["setb al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)

        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_setbe(self):
        asm = ["setbe al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)

        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_setg(self):
        asm = ["setg al"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)

        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_rol(self):
        asm = ["rol eax, 8"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        # NOTE: OF and CF can be left undefined in some cases. They are
        # not cover by this test.
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "cf")
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "of")

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_ror(self):
        asm = ["ror eax, 8"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        # NOTE: OF and CF can be left undefined in some cases. They are
        # not cover by this test.
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "cf")
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "of")

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_rcl(self):
        asm = ["rcl eax, 8"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        # set carry flag
        ctx_init['rflags'] = ctx_init['rflags'] | 0x1

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        # NOTE: OF and CF can be left undefined in some cases. They are
        # not cover by this test.
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "cf")
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "of")

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_rcr(self):
        asm = ["rcr eax, 3"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        # set carry flag
        ctx_init['rflags'] = ctx_init['rflags'] | 0x1

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        # NOTE: OF and CF can be left undefined in some cases. They are
        # not cover by this test.
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "cf")
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "of")

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_bt(self):
        asm = ["bt eax, ebx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        # NOTE: The OF, SF, AF, and PF flags are undefined.
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "of")
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "sf")
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "af")
        reil_ctx_out = self.__fix_reil_flag(reil_ctx_out, x86_ctx_out, "pf")

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_cmpxchg(self):
        asm = ["cmpxchg ebx, ecx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            end_address=(0xdeadbeef + 0x1) << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def test_movsx(self):
        asm = ["movsx eax, bx"]

        x86_instrs = map(self.x86_parser.parse, asm)

        self.__set_address(0xdeadbeef, x86_instrs)

        reil_instrs = map(self.x86_translator.translate, x86_instrs)

        ctx_init = self.__init_context()

        x86_rv, x86_ctx_out = pyasmjit.x86_execute("\n".join(asm), ctx_init)
        reil_ctx_out, reil_mem_out = self.reil_emulator.execute(
            reil_instrs,
            0xdeadbeef << 8,
            context=ctx_init
        )

        reil_ctx_out = self.__fix_reil_flags(reil_ctx_out, x86_ctx_out)

        cmp_result = self.__compare_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        if not cmp_result:
            self.__save_failing_context(ctx_init)

        # print self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out)

        self.assertTrue(cmp_result, self.__print_contexts(ctx_init, x86_ctx_out, reil_ctx_out))

    def __init_context(self):
        """Initialize register with random values.
        """
        if os.path.isfile(self.context_filename):
            context = self.__load_failing_context()
        else:
            context = self.__create_random_context()

        return context

    def __create_random_context(self):
        context = {}

        for reg in self.arch_info.registers_gp_base:
            if reg not in ['rsp', 'rip', 'rbp']:
                min_value, max_value = 0, 2**self.arch_info.operand_size - 1
                context[reg] = random.randint(min_value, max_value)

        context['rflags'] = self.__create_random_flags()

        return context

    def __create_random_flags(self):
        # TODO: Check why PyAsmJIT throws an exception when DF flag is
        # set.
        flags_mapper = {
             0 : "cf",  # bit 0
             2 : "pf",  # bit 2
             4 : "af",  # bit 4
             6 : "zf",  # bit 6
             7 : "sf",  # bit 7
            11 : "of",  # bit 11
            # 10 : "df",  # bit 10 # TODO: Enable.
        }

        # Set 'mandatory' flags.
        flags = 0x202

        for bit, flag in flags_mapper.items():
            flags = flags | (2**bit * random.randint(0, 1))

        return flags

    def __load_failing_context(self):
        f = open(self.context_filename, "rb")
        context = pickle.load(f)
        f.close()

        return context

    def __save_failing_context(self, context):
        f = open(self.context_filename, "wb")
        pickle.dump(context, f)
        f.close()

    def __compare_contexts(self, context_init, x86_context, reil_context):
        match = True
        mask = 2**64-1

        for reg in sorted(context_init.keys()):
            if (x86_context[reg] & mask) != (reil_context[reg] & mask):
                match = False
                break

        return match

    def __print_contexts(self, context_init, x86_context, reil_context):
        out = "Contexts don't match!\n\n"

        header_fmt = " {0:^8s} : {1:^16s} | {2:>16s} ?= {3:<16s}\n"
        header = header_fmt.format("Register", "Initial", "x86", "REIL")
        ruler = "-" * len(header) + "\n"

        out += header
        out += ruler

        fmt = " {0:>8s} : {1:016x} | {2:016x} {eq} {3:016x} {marker}\n"

        mask = 2**64-1

        for reg in sorted(context_init.keys()):
            if (x86_context[reg] & mask) != (reil_context[reg] & mask):
                eq, marker = "!=", "<"
            else:
                eq, marker = "==", ""

            out += fmt.format(
                reg,
                context_init[reg] & mask,
                x86_context[reg] & mask,
                reil_context[reg] & mask,
                eq=eq,
                marker=marker
            )

        # Pretty print flags.
        reg = "rflags"
        fmt = "{0:s} ({1:>7s}) : {2:016x} ({3:s})"

        init_value = context_init[reg] & mask
        x86_value = x86_context[reg] & mask
        reil_value = reil_context[reg] & mask

        init_flags_str = self.__print_flags(context_init[reg])
        x86_flags_str = self.__print_flags(x86_context[reg])
        reil_flags_str = self.__print_flags(reil_context[reg])

        out += "\n"
        out += fmt.format(reg, "initial", init_value, init_flags_str) + "\n"
        out += fmt.format(reg, "x86", x86_value, x86_flags_str) + "\n"
        out += fmt.format(reg, "reil", reil_value, reil_flags_str)

        return out

    def __print_registers(self, registers):
        out = ""

        header_fmt = " {0:^8s} : {1:^16s}\n"
        header = header_fmt.format("Register", "Value")
        ruler = "-" * len(header) + "\n"

        out += header
        out += ruler

        fmt = " {0:>8s} : {1:016x}\n"

        for reg in sorted(registers.keys()):
            out += fmt.format(reg, registers[reg])

        print(out)

    def __print_flags(self, flags):
        # flags
        flags_mapper = {
             0 : "cf",  # bit 0
             2 : "pf",  # bit 2
             4 : "af",  # bit 4
             6 : "zf",  # bit 6
             7 : "sf",  # bit 7
            11 : "of",  # bit 11
            # 10 : "df",  # bit 10
        }

        out = ""

        for bit, flag in flags_mapper.items():
            flag_str = flag.upper() if flags & 2**bit else flag.lower()
            out +=  flag_str + " "

        return out[:-1]

    def __fix_reil_flag(self, reil_context, x86_context, flag):
        reil_context_out = dict(reil_context)

        flags_reg = 'eflags' if 'eflags' in reil_context_out else 'rflags'

        arch_size = self.arch_info.architecture_size

        _, bit = self.arch_info.alias_mapper[flag]

        # Clean flag.
        reil_context_out[flags_reg] &= ~(2**bit) & (2**32-1)

        # Copy flag.
        reil_context_out[flags_reg] |= (x86_context[flags_reg] & 2**bit)

        return reil_context_out

    def __fix_reil_flags(self, reil_context, x86_context):
        reil_context_out = dict(reil_context)

        # Remove this when AF and PF are implemented.
        reil_context_out = self.__fix_reil_flag(reil_context_out, x86_context, "af")
        reil_context_out = self.__fix_reil_flag(reil_context_out, x86_context, "pf")

        return reil_context_out

    def __set_address(self, address, x86_instrs):
        addr = address

        for x86_instr in x86_instrs:
            x86_instr.address = addr
            x86_instr.size = 1
            addr += 1

def main():
    unittest.main()


if __name__ == '__main__':
    main()
