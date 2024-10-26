import json
from dataclasses import dataclass
import dataclasses
from capstone.x86 import *
from typing import ClassVar, Literal
from enum import Enum, auto
import re

@dataclass
class ImmOperand:
    type: ClassVar[int] = X86_OP_IMM
    size: int
    imm: int

    @classmethod
    def from_dict(cls, data):
        if data.get("type") != X86_OP_IMM:
            raise ValueError()

        if not isinstance(size := data.get("size"), int):
            raise ValueError()

        if not isinstance(imm := data.get("imm"), int):
            raise ValueError()

        return cls(
            size=size,
            imm=imm,
        )

    def __str__(self):
        return hex(self.imm)

@dataclass
class RegOperand:
    type: ClassVar[int] = X86_OP_REG
    size: int
    reg: int | Literal["MXCSR"]
    from_context: bool

    @classmethod
    def from_dict(cls, data):
        if data.get("type") != X86_OP_REG:
            raise ValueError()

        if not isinstance(size := data.get("size"), int):
            raise ValueError()

        if not isinstance(reg := data.get("reg"), int) and reg != "MXCSR":
            raise ValueError()
        
        if not isinstance(from_context := data.get("from_context", False), bool):
            raise ValueError()
        
        return cls(
            size=size,
            reg=reg,
            from_context=from_context
        )

    def __str__(self):
        if self.reg == "MXCSR":
            return "mxcsr"

        return REG_STRS[self.reg]

@dataclass
class MemOperand:
    type: ClassVar[int] = X86_OP_MEM
    size: int
    segment: int
    base: int
    index: int
    scale: int
    disp: int

    @classmethod
    def from_dict(cls, data):
        if data.get("type") != X86_OP_MEM:
            raise ValueError()

        for field in dataclasses.fields(cls):
            if not isinstance(data.get(field.name), field.type):
                raise ValueError()

        fields = {**data}
        del fields["type"]
        return cls(**fields)

    def __str__(self):
        match self.size:
            case 1:
                prefix = "byte ptr"
            case 2:
                prefix = "word ptr"
            case 4:
                prefix = "dword ptr"
            case 8:
                prefix = "qword ptr"
            case _:
                raise ValueError()

        if self.segment != 0 or self.index != 0 or self.scale != 1:
            raise ValueError()

        disp_str = f" + {hex(self.disp)}" if self.disp > 0 else ""

        return f"{prefix} [{REG_STRS[self.base]}{disp_str}]"

def parse_operand(data):
    if data.get("type") == X86_OP_IMM:
        return ImmOperand.from_dict(data)
    if data.get("type") == X86_OP_REG:
        return RegOperand.from_dict(data)
    if data.get("type") == X86_OP_MEM:
        return MemOperand.from_dict(data)

    raise ValueError()


@dataclass
class Instruction:
    address: int
    mnemonic: str
    operands: list[ImmOperand | RegOperand | MemOperand]

    @classmethod
    def from_dict(cls, data):
        if not isinstance(address := data.get("address"), int):
            raise ValueError()

        if not isinstance(mnemonic := data.get("mnemonic"), str):
            raise ValueError()

        raw_operands = data.get("operands")
        if not isinstance(raw_operands, list) or any(not isinstance(op, dict) for op in raw_operands):
            raise ValueError()

        return cls(
            address=address,
            mnemonic=mnemonic,
            operands=[
                parse_operand(op)
                for op in raw_operands
            ]
        )

    def __str__(self):
        op_str = ", ".join(map(str, self.operands))
        
        return f"{self.mnemonic} {op_str}"

@dataclass
class LiftedBlock:
    unwind_ops: list[str]
    insns: list[Instruction]

    @classmethod
    def from_dict(cls, data):
        unwind_ops = data.get("unwind_ops")
        if not isinstance(unwind_ops, list) or any(not isinstance(o, str) for o in unwind_ops):
            raise ValueError()
        
        raw_insns = data.get("insns")
        if not isinstance(raw_insns, list) or any(not isinstance(insn, dict) for insn in raw_insns):
            raise ValueError()

        return cls(
            unwind_ops=unwind_ops,
            insns=[
                Instruction.from_dict(insn)
                for insn in raw_insns
            ]
        )

with open("./lifted.json", "r") as f:
    lifted_blocks = [
        LiftedBlock.from_dict(raw_block)
        for raw_block in json.load(f)
    ]

REG_STRS = {
    X86_REG_AH: "ah",
    X86_REG_AL: "al",
    X86_REG_AX: "ax",
    X86_REG_BH: "bh",
    X86_REG_BL: "bl",
    X86_REG_BP: "bp",
    X86_REG_BPL: "bpl",
    X86_REG_BX: "bx",
    X86_REG_CH: "ch",
    X86_REG_CL: "cl",
    X86_REG_CS: "cs",
    X86_REG_CX: "cx",
    X86_REG_DH: "dh",
    X86_REG_DI: "di",
    X86_REG_DIL: "dil",
    X86_REG_DL: "dl",
    X86_REG_DS: "ds",
    X86_REG_DX: "dx",
    X86_REG_EAX: "eax",
    X86_REG_EBP: "ebp",
    X86_REG_EBX: "ebx",
    X86_REG_ECX: "ecx",
    X86_REG_EDI: "edi",
    X86_REG_EDX: "edx",
    X86_REG_EFLAGS: "eflags",
    X86_REG_EIP: "eip",
    X86_REG_EIZ: "eiz",
    X86_REG_ES: "es",
    X86_REG_ESI: "esi",
    X86_REG_ESP: "esp",
    X86_REG_FPSW: "fpsw",
    X86_REG_FS: "fs",
    X86_REG_GS: "gs",
    X86_REG_IP: "ip",
    X86_REG_RAX: "rax",
    X86_REG_RBP: "rbp",
    X86_REG_RBX: "rbx",
    X86_REG_RCX: "rcx",
    X86_REG_RDI: "rdi",
    X86_REG_RDX: "rdx",
    X86_REG_RIP: "rip",
    X86_REG_RIZ: "riz",
    X86_REG_RSI: "rsi",
    X86_REG_RSP: "rsp",
    X86_REG_SI: "si",
    X86_REG_SIL: "sil",
    X86_REG_SP: "sp",
    X86_REG_SPL: "spl",
    X86_REG_SS: "ss",
    X86_REG_CR0: "cr0",
    X86_REG_CR1: "cr1",
    X86_REG_CR2: "cr2",
    X86_REG_CR3: "cr3",
    X86_REG_CR4: "cr4",
    X86_REG_CR5: "cr5",
    X86_REG_CR6: "cr6",
    X86_REG_CR7: "cr7",
    X86_REG_CR8: "cr8",
    X86_REG_CR9: "cr9",
    X86_REG_CR10: "cr10",
    X86_REG_CR11: "cr11",
    X86_REG_CR12: "cr12",
    X86_REG_CR13: "cr13",
    X86_REG_CR14: "cr14",
    X86_REG_CR15: "cr15",
    X86_REG_DR0: "dr0",
    X86_REG_DR1: "dr1",
    X86_REG_DR2: "dr2",
    X86_REG_DR3: "dr3",
    X86_REG_DR4: "dr4",
    X86_REG_DR5: "dr5",
    X86_REG_DR6: "dr6",
    X86_REG_DR7: "dr7",
    X86_REG_DR8: "dr8",
    X86_REG_DR9: "dr9",
    X86_REG_DR10: "dr10",
    X86_REG_DR11: "dr11",
    X86_REG_DR12: "dr12",
    X86_REG_DR13: "dr13",
    X86_REG_DR14: "dr14",
    X86_REG_DR15: "dr15",
    X86_REG_FP0: "fp0",
    X86_REG_FP1: "fp1",
    X86_REG_FP2: "fp2",
    X86_REG_FP3: "fp3",
    X86_REG_FP4: "fp4",
    X86_REG_FP5: "fp5",
    X86_REG_FP6: "fp6",
    X86_REG_FP7: "fp7",
    X86_REG_K0: "k0",
    X86_REG_K1: "k1",
    X86_REG_K2: "k2",
    X86_REG_K3: "k3",
    X86_REG_K4: "k4",
    X86_REG_K5: "k5",
    X86_REG_K6: "k6",
    X86_REG_K7: "k7",
    X86_REG_MM0: "mm0",
    X86_REG_MM1: "mm1",
    X86_REG_MM2: "mm2",
    X86_REG_MM3: "mm3",
    X86_REG_MM4: "mm4",
    X86_REG_MM5: "mm5",
    X86_REG_MM6: "mm6",
    X86_REG_MM7: "mm7",
    X86_REG_R8: "r8",
    X86_REG_R9: "r9",
    X86_REG_R10: "r10",
    X86_REG_R11: "r11",
    X86_REG_R12: "r12",
    X86_REG_R13: "r13",
    X86_REG_R14: "r14",
    X86_REG_R15: "r15",
    X86_REG_ST0: "st0",
    X86_REG_ST1: "st1",
    X86_REG_ST2: "st2",
    X86_REG_ST3: "st3",
    X86_REG_ST4: "st4",
    X86_REG_ST5: "st5",
    X86_REG_ST6: "st6",
    X86_REG_ST7: "st7",
    X86_REG_XMM0: "xmm0",
    X86_REG_XMM1: "xmm1",
    X86_REG_XMM2: "xmm2",
    X86_REG_XMM3: "xmm3",
    X86_REG_XMM4: "xmm4",
    X86_REG_XMM5: "xmm5",
    X86_REG_XMM6: "xmm6",
    X86_REG_XMM7: "xmm7",
    X86_REG_XMM8: "xmm8",
    X86_REG_XMM9: "xmm9",
    X86_REG_XMM10: "xmm10",
    X86_REG_XMM11: "xmm11",
    X86_REG_XMM12: "xmm12",
    X86_REG_XMM13: "xmm13",
    X86_REG_XMM14: "xmm14",
    X86_REG_XMM15: "xmm15",
    X86_REG_XMM16: "xmm16",
    X86_REG_XMM17: "xmm17",
    X86_REG_XMM18: "xmm18",
    X86_REG_XMM19: "xmm19",
    X86_REG_XMM20: "xmm20",
    X86_REG_XMM21: "xmm21",
    X86_REG_XMM22: "xmm22",
    X86_REG_XMM23: "xmm23",
    X86_REG_XMM24: "xmm24",
    X86_REG_XMM25: "xmm25",
    X86_REG_XMM26: "xmm26",
    X86_REG_XMM27: "xmm27",
    X86_REG_XMM28: "xmm28",
    X86_REG_XMM29: "xmm29",
    X86_REG_XMM30: "xmm30",
    X86_REG_XMM31: "xmm31",
    X86_REG_YMM0: "ymm0",
    X86_REG_YMM1: "ymm1",
    X86_REG_YMM2: "ymm2",
    X86_REG_YMM3: "ymm3",
    X86_REG_YMM4: "ymm4",
    X86_REG_YMM5: "ymm5",
    X86_REG_YMM6: "ymm6",
    X86_REG_YMM7: "ymm7",
    X86_REG_YMM8: "ymm8",
    X86_REG_YMM9: "ymm9",
    X86_REG_YMM10: "ymm10",
    X86_REG_YMM11: "ymm11",
    X86_REG_YMM12: "ymm12",
    X86_REG_YMM13: "ymm13",
    X86_REG_YMM14: "ymm14",
    X86_REG_YMM15: "ymm15",
    X86_REG_YMM16: "ymm16",
    X86_REG_YMM17: "ymm17",
    X86_REG_YMM18: "ymm18",
    X86_REG_YMM19: "ymm19",
    X86_REG_YMM20: "ymm20",
    X86_REG_YMM21: "ymm21",
    X86_REG_YMM22: "ymm22",
    X86_REG_YMM23: "ymm23",
    X86_REG_YMM24: "ymm24",
    X86_REG_YMM25: "ymm25",
    X86_REG_YMM26: "ymm26",
    X86_REG_YMM27: "ymm27",
    X86_REG_YMM28: "ymm28",
    X86_REG_YMM29: "ymm29",
    X86_REG_YMM30: "ymm30",
    X86_REG_YMM31: "ymm31",
    X86_REG_ZMM0: "zmm0",
    X86_REG_ZMM1: "zmm1",
    X86_REG_ZMM2: "zmm2",
    X86_REG_ZMM3: "zmm3",
    X86_REG_ZMM4: "zmm4",
    X86_REG_ZMM5: "zmm5",
    X86_REG_ZMM6: "zmm6",
    X86_REG_ZMM7: "zmm7",
    X86_REG_ZMM8: "zmm8",
    X86_REG_ZMM9: "zmm9",
    X86_REG_ZMM10: "zmm10",
    X86_REG_ZMM11: "zmm11",
    X86_REG_ZMM12: "zmm12",
    X86_REG_ZMM13: "zmm13",
    X86_REG_ZMM14: "zmm14",
    X86_REG_ZMM15: "zmm15",
    X86_REG_ZMM16: "zmm16",
    X86_REG_ZMM17: "zmm17",
    X86_REG_ZMM18: "zmm18",
    X86_REG_ZMM19: "zmm19",
    X86_REG_ZMM20: "zmm20",
    X86_REG_ZMM21: "zmm21",
    X86_REG_ZMM22: "zmm22",
    X86_REG_ZMM23: "zmm23",
    X86_REG_ZMM24: "zmm24",
    X86_REG_ZMM25: "zmm25",
    X86_REG_ZMM26: "zmm26",
    X86_REG_ZMM27: "zmm27",
    X86_REG_ZMM28: "zmm28",
    X86_REG_ZMM29: "zmm29",
    X86_REG_ZMM30: "zmm30",
    X86_REG_ZMM31: "zmm31",
    X86_REG_R8B: "r8b",
    X86_REG_R9B: "r9b",
    X86_REG_R10B: "r10b",
    X86_REG_R11B: "r11b",
    X86_REG_R12B: "r12b",
    X86_REG_R13B: "r13b",
    X86_REG_R14B: "r14b",
    X86_REG_R15B: "r15b",
    X86_REG_R8D: "r8d",
    X86_REG_R9D: "r9d",
    X86_REG_R10D: "r10d",
    X86_REG_R11D: "r11d",
    X86_REG_R12D: "r12d",
    X86_REG_R13D: "r13d",
    X86_REG_R14D: "r14d",
    X86_REG_R15D: "r15d",
    X86_REG_R8W: "r8w",
    X86_REG_R9W: "r9w",
    X86_REG_R10W: "r10w",
    X86_REG_R11W: "r11w",
    X86_REG_R12W: "r12w",
    X86_REG_R13W: "r13w",
    X86_REG_R14W: "r14w",
    X86_REG_R15W: "r15w",
}

INPUT_OFFSET = 0x14089b8e8

index_map = {}

for block in lifted_blocks:
    for i in range(len(block.unwind_ops)):
        unwind_op = block.unwind_ops[i]
        if not unwind_op.startswith("UWOP_SAVE_NONVOL"):
            continue

        addr = int(unwind_op.split(", ")[1].split(")")[0], 16)
        if not INPUT_OFFSET <= addr <= INPUT_OFFSET + 0x20:
            continue

        block.unwind_ops[i] = unwind_op.replace(hex(addr), f"&INPUT_KEY[0x{addr - INPUT_OFFSET:02x}]")
        index_map[block.unwind_ops[i]] = addr - INPUT_OFFSET

def print_lifted_blocks(lifted_blocks):
    for i, block in enumerate(lifted_blocks):
        print("; LIFTED BLOCK START", i)
        for unwind_op in block.unwind_ops:
            print(f"\t{unwind_op}")
        for insn in block.insns:
            comment = ""
            for i, op in enumerate(insn.operands):
                if op.type == X86_OP_REG and op.from_context:
                    if len(insn.operands) == 1 or i == 1:
                        comment = " ; src from prev. CONTEXT"
                    elif len(insn.operands) and i == 0:
                        comment = " ; dst from prev. CONTEXT"
                    else:
                        raise Exception()

                    break
            print(f"\t{insn.address:06x} {insn}{comment}")

AND_LUT = 0x1400942c0
XOR_LUT = 0x140094ac0
OR_LUT = 0x1400952c0
ADDITIVE_SET_LUT = 0x140095ac0
ADDITIVE_CARRY_LUT = 0x1400962c0
SUBTRACTIVE_SET_LUT = 0x140096ac0
SUBTRACTIVE_CARRY_LUT = 0x1400972c0

class SerpentineOpType(Enum):
    AND = auto()
    XOR = auto()
    OR  = auto()
    ADD = auto()
    SUB = auto()

@dataclass
class SerpentineOp:
    type: SerpentineOpType
    shift: int
    right: int

STACK_BASE = 0x7f0000000000
class SerpentineBlock:
    blocks: list[LiftedBlock]
    input_index: int
    mul_const: int
    compression_op: SerpentineOpType | None
    operations: list[SerpentineOp]

    def __init__(self, blocks, first_of_superblock):
        self.blocks = blocks
        self.operations = []

        for start_offset in range(2):
            block = self.blocks[start_offset]
            if len(block.unwind_ops) == 0:
                continue

            unwind_op = block.unwind_ops[-1]
            if unwind_op in index_map:
                break
        else:
            raise Exception()

        self.input_index = index_map[unwind_op]

        start_offset += 1
        mul_const = None
        for insn in self.blocks[start_offset].insns:
            if insn.mnemonic == "movabs":
                c = insn.operands[1]
                if c.type != X86_OP_IMM:
                    raise Exception()
                if mul_const is not None:
                    raise Exception()

                mul_const = c.imm
                continue

            if insn.mnemonic == "mul":
                break

        else:
            raise Exception()

        if mul_const is None:
            raise Exception()

        self.mul_const = mul_const

        if not first_of_superblock:
            start_offset += 1
            block = self.blocks[start_offset]
            if len(block.insns) != 2:
                raise Exception()

            match block.insns[-1].mnemonic:
                case "add":
                    self.compression_op = SerpentineOpType.ADD
                case "sub":
                    self.compression_op = SerpentineOpType.SUB
                case "xor":
                    self.compression_op = SerpentineOpType.XOR
                case _:
                    raise Exception()
        else:
            self.compression_op = None

        SAVE_NONVOL_REGEX = re.compile(r"^UWOP_SAVE_NONVOL\(.+, (0x.+)\) = ")
        ALLOC_LARGE_REGEX = re.compile(r"^UWOP_ALLOC_LARGE\((0x.+)\)")
        def get_stack_save(block: LiftedBlock):
            if not (2 <= len(block.unwind_ops) <= 3):
                return None

            if not block.unwind_ops[0].startswith("UWOP_PUSH_MACHFRAME") and not block.unwind_ops[0].startswith("UWOP_SET_FPREG"):
                return None
            if (match := re.match(SAVE_NONVOL_REGEX, block.unwind_ops[-1])) is None:
                return None

            
            if (rsp := int(match[1], 16)) < STACK_BASE:
                return None
        
            shift = 0
            if len(block.unwind_ops) == 3:
                if (match := re.match(ALLOC_LARGE_REGEX, block.unwind_ops[1])) is None:
                    return None
                
                shift = int(match[1], 16) * 8
            
            return shift

        start_offset += 1
        current_op_shift = None
        for block in self.blocks[start_offset:]:
            if (shift := get_stack_save(block)) is not None:
                if current_op_shift is not None:
                    raise Exception("unprocessed op")

                current_op_shift = shift
                continue

            if len(block.unwind_ops) >= 2 and (match := re.match(SAVE_NONVOL_REGEX, block.unwind_ops[-1])) is not None:
                address = int(match[1], 16)

                if ADDITIVE_SET_LUT <= address < ADDITIVE_SET_LUT + 0x800:
                    offset = address - ADDITIVE_SET_LUT
                    op_type = SerpentineOpType.ADD
                elif SUBTRACTIVE_SET_LUT <= address < SUBTRACTIVE_SET_LUT + 0x800:
                    offset = address - SUBTRACTIVE_SET_LUT
                    op_type = SerpentineOpType.SUB
                elif AND_LUT <= address < AND_LUT + 0x800:
                    offset = address - AND_LUT
                    op_type = SerpentineOpType.AND
                elif XOR_LUT <= address < XOR_LUT + 0x800:
                    offset = address - XOR_LUT
                    op_type = SerpentineOpType.XOR
                elif OR_LUT <= address < OR_LUT + 0x800:
                    offset = address - OR_LUT
                    op_type=SerpentineOpType.OR
                else:
                    continue

                if op_type in [SerpentineOpType.ADD, SerpentineOpType.SUB] and current_op_shift != 0x7 * 8:
                    last_op = self.operations[-1]
                    if last_op.type != op_type and last_op.right == offset // 8:
                        raise Exception("unexpected ADD LUT")
                    continue
                if offset % 8 != 0:
                    raise Exception()

                if current_op_shift is None:
                    raise Exception()

                self.operations.append(SerpentineOp(
                    type=op_type,
                    shift=current_op_shift,
                    right=(offset // 8)
                ))

                current_op_shift = None
                continue


            for i, insn in enumerate(block.insns):
                if insn.mnemonic == "movabs":
                    op = insn.operands[1]
                    if op.type != X86_OP_IMM:
                        continue

                    if op.imm == ADDITIVE_CARRY_LUT:
                        op_type = SerpentineOpType.ADD
                    elif op.imm == SUBTRACTIVE_CARRY_LUT:
                        op_type = SerpentineOpType.SUB
                    else:
                        continue

                    after = block.insns[i + 1]
                    if after.mnemonic != "mov":
                        continue

                    op = after.operands[1]
                    if op.type != X86_OP_MEM:
                        continue

                    if op.disp % 8 != 0:
                        raise Exception()

                    if current_op_shift is None:
                        raise Exception()

                    self.operations.append(SerpentineOp(
                        type=op_type,
                        shift=current_op_shift,
                        right=(op.disp // 8)
                    ))

                    current_op_shift = None

class SerpentineSuperBlock:
    blocks: list[SerpentineBlock]

    def __init__(self, raw_blocks):
        self.blocks = []

        current_block = []
        for block in raw_blocks:
            if any("&INPUT_KEY[" in unwind_op for unwind_op in block.unwind_ops):
                if len(current_block) > 1:
                    self.blocks.append(SerpentineBlock(current_block, len(self.blocks) == 0))
                    current_block = []
            current_block.append(block)

        self.blocks.append(SerpentineBlock(current_block, len(self.blocks) == 0))

superblocks = []
current_superblock = []
for block in lifted_blocks:
    current_superblock.append(block)

    if any(insn.mnemonic == "cmovne" for insn in block.insns):
        superblocks.append(SerpentineSuperBlock(current_superblock))
        current_superblock = []


def lift_ops(operations):
    current_run = []

    def lift_run():
        if all(c.type == SerpentineOpType.ADD for c in current_run):
            const = sum(c.right << c.shift for c in current_run)
            return f"t += {const:#x}"

        if all(c.type == SerpentineOpType.SUB for c in current_run):
            const = sum(c.right << c.shift for c in current_run)
            return f"t -= {const:#x}"

        if all(c.type == SerpentineOpType.XOR for c in current_run):
            const = sum(c.right << c.shift for c in current_run)
            return f"t ^= {const:#x}"

        # if all(c.type == SerpentineOpType.OR for c in current_run):
        #     const = sum(c.right << c.shift for c in current_run)
        #     return f"t |= {const:#x}"

        return None

    for o in operations:
        if len(current_run) == 0 or o.type == current_run[-1].type:
            current_run.append(o)
            continue

        if o.type != current_run[-1].type:
            if (lifted := lift_run()) is not None:
                yield lifted
            else:
                yield from current_run

            current_run = [o]

    if (lifted := lift_run()) is not None:
        yield lifted
    else:
        yield from current_run

print_lifted_blocks(lifted_blocks)
print("""from z3 import Solver, sat, BitVec, Or
import string

s = Solver()

INPUT_KEY = [BitVec(f"input{i}", 64) for i in range(0x20)]
for i, k in enumerate(INPUT_KEY):
    constraints = [
        k == ord(c)
        for c in string.ascii_letters + string.digits + "!#$%&'*+-/=?^_`{|}~" + "."
    ]
    s.add(
        Or(
            *constraints
        )
    )
""")
for i, s in enumerate(superblocks):
    for b in s.blocks:
        match b.compression_op:
            case None:
                print(f"t  = INPUT_KEY[0x{b.input_index:02x}] * {b.mul_const:#x}")
            case SerpentineOpType.ADD:
                print(f"t += INPUT_KEY[0x{b.input_index:02x}] * {b.mul_const:#x}")
            case SerpentineOpType.SUB:
                print(f"t -= INPUT_KEY[0x{b.input_index:02x}] * {b.mul_const:#x}")
            case SerpentineOpType.XOR:
                print(f"t ^= INPUT_KEY[0x{b.input_index:02x}] * {b.mul_const:#x}")
            case _:
                raise Exception()

        for o in lift_ops(b.operations):
            if isinstance(o, SerpentineOp):
                match o.type:
                    case SerpentineOpType.ADD:
                        print(f"t += {o.right:#x} << {o.shift:#x}")
                    case SerpentineOpType.SUB:
                        print(f"t -= {o.right:#x} << {o.shift:#x}")
                    case SerpentineOpType.XOR:
                        print(f"t ^= {o.right:#x} << {o.shift:#x}")
                    case SerpentineOpType.OR:
                        if o.right == 0x00:
                            continue

                        print(f"t |= {o.right:#x} << {o.shift:#x}")
                    case SerpentineOpType.AND:
                        if o.right == 0xff:
                            continue

                        print(f"t &= {o.right:#x} << {o.shift:#x}")
            else:
                print(o)
    
    print(f"s.add(t == 0)\n")

print("""
if s.check() == sat:
    model = s.model()
    print("".join(chr(model[INPUT_KEY[i]].as_long()) for i in range(0x20)))
""")
