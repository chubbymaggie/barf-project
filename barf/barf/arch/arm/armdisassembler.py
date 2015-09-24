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

"""
This modules contains a ARM disassembler based on the Capstone
disassembly framework.

"""
import logging

from capstone import CS_MODE_ARM
from capstone import CS_MODE_THUMB
from capstone import Cs
from capstone import CS_ARCH_ARM
from capstone.arm import ARM_CC_EQ
from capstone.arm import ARM_CC_NE
from capstone.arm import ARM_CC_MI
from capstone.arm import ARM_CC_PL
from capstone.arm import ARM_CC_VS
from capstone.arm import ARM_CC_VC
from capstone.arm import ARM_CC_HI
from capstone.arm import ARM_CC_LS
from capstone.arm import ARM_CC_GE
from capstone.arm import ARM_CC_LT
from capstone.arm import ARM_CC_GT
from capstone.arm import ARM_CC_LE
from capstone.arm import ARM_CC_AL
from capstone.arm import ARM_CC_HS
from capstone.arm import ARM_CC_LO
from capstone.arm import ARM_SFT_ASR
from capstone.arm import ARM_SFT_LSL
from capstone.arm import ARM_SFT_LSR
from capstone.arm import ARM_SFT_ROR
from capstone.arm import ARM_SFT_RRX
from capstone.arm import ARM_SFT_ASR_REG
from capstone.arm import ARM_SFT_LSL_REG
from capstone.arm import ARM_SFT_LSR_REG
from capstone.arm import ARM_SFT_ROR_REG
from capstone.arm import ARM_SFT_RRX_REG
from capstone.arm import ARM_OP_REG
from capstone.arm import ARM_OP_IMM
from capstone.arm import ARM_OP_MEM
from capstone.arm import ARM_CC_INVALID


from barf.arch import ARCH_ARM_MODES_MAX
from barf.arch import ARCH_ARM_MODE_32
from barf.arch import ARCH_ARM_MODE_ARM
from barf.arch import ARCH_ARM_MODE_THUMB
from barf.arch.arm.armbase import ARM_COND_CODE_EQ
from barf.arch.arm.armbase import ARM_COND_CODE_NE
from barf.arch.arm.armbase import ARM_COND_CODE_MI
from barf.arch.arm.armbase import ARM_COND_CODE_PL
from barf.arch.arm.armbase import ARM_COND_CODE_VS
from barf.arch.arm.armbase import ARM_COND_CODE_VC
from barf.arch.arm.armbase import ARM_COND_CODE_HI
from barf.arch.arm.armbase import ARM_COND_CODE_LS
from barf.arch.arm.armbase import ARM_COND_CODE_GE
from barf.arch.arm.armbase import ARM_COND_CODE_LT
from barf.arch.arm.armbase import ARM_COND_CODE_GT
from barf.arch.arm.armbase import ARM_COND_CODE_LE
from barf.arch.arm.armbase import ARM_COND_CODE_AL
from barf.arch.arm.armbase import ARM_COND_CODE_HS
from barf.arch.arm.armbase import ARM_COND_CODE_LO
from barf.arch.arm.armbase import ArmInstruction
from barf.arch.arm.armbase import ArmRegisterListOperand
from barf.arch.arm.armbase import ArmImmediateOperand
from barf.arch.arm.armbase import ArmMemoryOperand
from barf.arch.arm.armbase import CapstoneOperandNotSupported
from barf.arch.arm.armbase import InvalidDisassemblerData
from barf.arch.arm.armbase import ArmRegisterOperand
from barf.arch.arm.armbase import ArmShiftedRegisterOperand
from barf.arch.arm.armbase import ArmArchitectureInformation
from barf.arch.arm.armbase import ARM_MEMORY_INDEX_OFFSET
from barf.arch.arm.armbase import cc_inverse_mapper
from barf.arch.arm.armparser import ArmParser
from barf.core.disassembler import Disassembler

cc_capstone_barf_mapper = {
    ARM_CC_EQ : ARM_COND_CODE_EQ,
    ARM_CC_NE : ARM_COND_CODE_NE,
    ARM_CC_MI : ARM_COND_CODE_MI,
    ARM_CC_PL : ARM_COND_CODE_PL,
    ARM_CC_VS : ARM_COND_CODE_VS,
    ARM_CC_VC : ARM_COND_CODE_VC,
    ARM_CC_HI : ARM_COND_CODE_HI,
    ARM_CC_LS : ARM_COND_CODE_LS,
    ARM_CC_GE : ARM_COND_CODE_GE,
    ARM_CC_LT : ARM_COND_CODE_LT,
    ARM_CC_GT : ARM_COND_CODE_GT,
    ARM_CC_LE : ARM_COND_CODE_LE,
    ARM_CC_AL : ARM_COND_CODE_AL,
    ARM_CC_HS : ARM_COND_CODE_HS,
    ARM_CC_LO : ARM_COND_CODE_LO,
}

arch_mode_barf_to_capstone_mapper = {
    ARCH_ARM_MODE_ARM : CS_MODE_ARM,
    ARCH_ARM_MODE_THUMB : CS_MODE_THUMB,
}

logger = logging.getLogger(__name__)


class ArmDisassembler(Disassembler):
    """ARM Disassembler.
    """

    def __init__(self, architecture_mode=ARCH_ARM_MODE_32):
        super(ArmDisassembler, self).__init__()

        self._architecture_mode = architecture_mode
        self._arch_info = ArmArchitectureInformation(architecture_mode)

#         arch_mode_map = {
#             # TODO: ARM vs CS_MODE_THUMB
#             ARCH_ARM_MODE_32 : CS_MODE_THUMB,
#         }

        self._parser = ArmParser(architecture_mode)

        self._avaliable_disassemblers = [None] * ARCH_ARM_MODES_MAX
        self._avaliable_disassemblers[ARCH_ARM_MODE_ARM] = Cs(CS_ARCH_ARM, arch_mode_barf_to_capstone_mapper[ARCH_ARM_MODE_ARM])
        self._avaliable_disassemblers[ARCH_ARM_MODE_THUMB] = Cs(CS_ARCH_ARM, arch_mode_barf_to_capstone_mapper[ARCH_ARM_MODE_THUMB])
        # TODO: DECOUPLE: detail true vs false
        self._avaliable_disassemblers[ARCH_ARM_MODE_ARM].detail = True
        self._avaliable_disassemblers[ARCH_ARM_MODE_THUMB].detail = True

        # TODO: define default disassembler externally
        self._disassembler = self._avaliable_disassemblers[1]

    def _cs_reg_idx_to_arm_op_reg(self, cs_reg_idx, cs_insn):
        name = cs_insn.reg_name(cs_reg_idx)
        if name in self._arch_info.registers_size:
            size = self._arch_info.registers_size[name]
        else:
            size = self._arch_info.architecture_size
        return ArmRegisterOperand(name, size)

    def _cs_shift_to_arm_op(self, cs_op, cs_insn, arm_base):

        if cs_op.shift.type == 0:
            raise Exception("_cs_shift_to_arm_op: Invalid shift type")

        cs_shift_mapper = {
            ARM_SFT_ASR : "asr",
            ARM_SFT_LSL : "lsl",
            ARM_SFT_LSR : "lsr",
            ARM_SFT_ROR : "ror",
            ARM_SFT_RRX : "rrx",
            ARM_SFT_ASR_REG : "asr",
            ARM_SFT_LSL_REG : "lsl",
            ARM_SFT_LSR_REG : "lsr",
            ARM_SFT_ROR_REG : "ror",
            ARM_SFT_RRX_REG : "rrx",
        }
        # The base register (arm_base) is not included in the shift struct in Capstone, so it's provided separately
        sh_type = cs_shift_mapper[cs_op.shift.type]

        if cs_op.shift.type <= ARM_SFT_RRX:
            amount = ArmImmediateOperand(cs_op.shift.value, self._arch_info.operand_size)
            # TODO: check if this is a valid case
            if cs_op.shift.value == 0:
                raise Exception("_cs_shift_to_arm_op: shift value == 0")
        elif cs_op.shift.type <= ARM_SFT_RRX_REG:
            amount = self._cs_reg_idx_to_arm_op_reg(cs_op.shift.value, cs_insn)
        else:
            raise Exception("_cs_shift_to_arm_op: Unknown shift type.")

        return ArmShiftedRegisterOperand(arm_base, sh_type, amount, arm_base.size)


    def _cs_translate_operand(self, cs_op, cs_insn):

        if cs_op.type == ARM_OP_REG:
            oprnd = self._cs_reg_idx_to_arm_op_reg(cs_op.value.reg, cs_insn)

        elif cs_op.type == ARM_OP_IMM:
            size = self._arch_info.operand_size
            oprnd = ArmImmediateOperand(cs_op.value.imm, size)

        elif cs_op.type == ARM_OP_MEM:
            reg_base = self._cs_reg_idx_to_arm_op_reg(cs_op.mem.base, cs_insn)

            # TODO: memory index type
            index_type = ARM_MEMORY_INDEX_OFFSET

            if cs_op.mem.index > 0:

                if cs_op.mem.disp > 0:
                    raise Exception("ARM_OP_MEM: Both index and disp > 0, only one can be.")

                displacement = self._cs_reg_idx_to_arm_op_reg(cs_op.mem.index, cs_insn)

                # NOTE: In the case of a memory operand, in the second position (slot [1]),
                # the information regarding wheter or not the displacement of the operand has
                # a shifted register is encoded in the first operand (slot [0]), that doesn't
                # have a direct relation with the other.
                # TODO: Check if this has to be reported to CS.

                if cs_insn.operands[0].shift.type > 0:
                    # There's a shift operation, the displacement extracted earlier was just the
                    # base register of the shifted register that is generating the disaplacement.
                    displacement = self._cs_shift_to_arm_op(cs_insn.operands[0], cs_insn, displacement)

            else:
                displacement = ArmImmediateOperand(cs_op.mem.disp, self._arch_info.operand_size)

            disp_minus = True if cs_op.mem.index == -1 else False

            oprnd = ArmMemoryOperand(reg_base, index_type, displacement, disp_minus, self._arch_info.operand_size)

#             # DEBUG:
#             if cs_insn.operands[0].shift.type > 0:
#                 print cs_insn.op_str
#                 print "ArmShiftedRegisterOperand: " + str(displacement)
#                 print "ArmMemoryOperand: " + str(oprnd)

        else:
            oprnd = None
            error_msg =  "Instruction: " + cs_insn.mnemonic  + " " + cs_insn.op_str + ". Unkown operand type: " + str(cs_op.type)

            logger.error(error_msg)

            raise CapstoneOperandNotSupported(error_msg)


        return oprnd

    def _cs_translate_insn(self, cs_insn):

        operands = [self._cs_translate_operand(op, cs_insn) for op in cs_insn.operands]

        mnemonic = cs_insn.mnemonic

        # Special case: register list "{rX - rX}", stored as a series of registers has
        # to be converted to ArmRegisterListOperand.
        if "{" in cs_insn.op_str:
            reg_list = []
            op_translated = []
            if not("push" in mnemonic or "pop" in mnemonic):
                # First operand is the base (in push/pop, the base register, sp,  is omitted)
                op_translated.append(operands[0])
                operands = operands[1:]

            for r in operands:
                reg_list.append([r])

            op_translated.append(ArmRegisterListOperand(reg_list, reg_list[0][0].size))

            operands = op_translated

        # Remove narrow/wide compiler suffixes (.w/.n), they are of no interest for tranlation purpouses
        if mnemonic[-2:] == ".w" or mnemonic[-2:] == ".n":
            mnemonic = mnemonic[:-2]

        # Remove condition code from the mnemonic, this goes first than the removal of the update flags suffix,
        # because according to UAL syntax the this suffix goes after the update flags suffix in the mnemonic.
        if cs_insn.cc != ARM_CC_INVALID and cs_insn.cc != ARM_CC_AL:
            cc_suffix_str = cc_inverse_mapper[cc_capstone_barf_mapper[cs_insn.cc]]
            if cc_suffix_str == mnemonic[-2:]:
                mnemonic = mnemonic[:-2]

        # Remove update flags suffix (s)
        if cs_insn.update_flags and mnemonic[-1] == 's':
            mnemonic = mnemonic[:-1]

        # TODO: Temporary hack to accommodate THUMB short notation:
        # "add r0, r1" -> "add r0, r0, r1"
        if len(operands) == 2 and (mnemonic == "add" or
                                   mnemonic == "eor" or
                                   mnemonic == "orr" or
                                   mnemonic == "sub"):
            operands = [operands[0],operands[0],operands[1]]

        instr = ArmInstruction(
            mnemonic + " " + cs_insn.op_str,
            mnemonic,
            operands,
            self._architecture_mode
        )

        if cs_insn.cc != ARM_CC_INVALID:
            instr.condition_code = cc_capstone_barf_mapper[cs_insn.cc]

        if cs_insn.update_flags:
            instr.update_flags = True

        # TODO: LOAD/STORE MODE (it may be necessary to parse the mnemonic).

        return instr

    def disassemble(self, data, address, used_disassembler=1):
        """Disassemble the data into an instruction.
        """
        self._disassembler = self._avaliable_disassemblers[used_disassembler]

        # TODO: DECOUPLE: parser vs capstone translation
        disasm = self._cs_disassemble_one(data, address)

        instr =  self._cs_translate_insn(disasm)

        if instr:
            instr.address = address
            instr.size = disasm.size
            instr.bytes = data[0:disasm.size]

        return instr

#         asm, size = self._cs_disassemble_one(data, address)
#
#         instr = self._parser.parse(asm) if asm else None
#
#         if instr:
#             instr.address = address
#             instr.size = size
#             instr.bytes = data[0:size]
#
#         return instr

    def disassemble_all(self, data, address):
        """Disassemble the data into multiple instructions.
        """
        raise NotImplementedError()

    def _cs_disassemble_one(self, data, address):
        """Disassemble the data into an instruction in string form.
        """
        # TODO: DECOUPLE: disasm_lite vs disasm
        disasm = list(self._disassembler.disasm(data, address))

        if len(disasm) > 0:
            return disasm[0]
        else:
            cs_arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
            disasm = list(cs_arm.disasm(data, address))
            if len(disasm) > 0:
                return disasm[0]
            else:
                raise InvalidDisassemblerData("CAPSTONE: Unknown instruction (Addr: {:s}).".format(hex(address)))

#         asm, size = "", 0
#
#         disasm = list(self._disassembler.disasm(data, address))
#
#         if len(disasm) > 0:
#             address, size, mnemonic, op_str = disasm[0]
#
#             asm = str(mnemonic + " " + op_str).strip()
#         else:
#             # FIXME: Hack to bypass immediate constants embedded in the
#             # text section that do not conform to any valid instruction.
#             asm = "mov r0, r0" # Preferred ARM no-operation code
#             size = 4
#
#         return asm, size
