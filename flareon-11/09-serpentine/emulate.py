import sys
sys.path.append("..")

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import *
from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
from qiling.os.windows.api import DWORDLONG, DWORD, POINTER, PVOID, PCWSTR, LPVOID, SIZE_T
from qiling.os.windows.fncc import *
from unicorn.x86_const import UC_X86_REG_MXCSR

import re

INPUT = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"

FUNCTION_TABLES = {}

SHELLCODE_BASE = None

@winsdkapi(cc=CDECL, params={
    "TableIdentifier" : DWORDLONG,
    "BaseAddress": DWORDLONG,
    "Length": DWORD,
    "Callback": POINTER,
    "Context": PVOID,
    "OutOfProcessCallbackDll": PCWSTR,
})
def RtlInstallFunctionTableCallback(ql: Qiling, address: int, params):
    global FUNCTION_TABLES, SHELLCODE_BASE
    FUNCTION_TABLES[params["TableIdentifier"]] = (params["BaseAddress"], params["Length"], params["Callback"])

    ql.hook_code(log_deobfuscated, begin=SHELLCODE_BASE, end=SHELLCODE_BASE + 0x800000)
    ql.hook_code(monitor_function_table, begin=SHELLCODE_BASE, end=SHELLCODE_BASE + 0x800000)
    ql.hook_mem_write(mem_modify, begin=SHELLCODE_BASE, end=SHELLCODE_BASE + 0x800000)

    ql.os.stats.clear()

    return 0x1

UNWIND_REGS = [
    "rax",
    "rcx",
    "rdx",
    "rbx",
    "rsp",
    "rbp",
    "rsi",
    "rdi",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
]

CONTEXT_OFFSETS = {
    0x34: "MXCSR",
    0x78: X86_REG_RAX,
    0x80: X86_REG_RCX,
    0x88: X86_REG_RDX,
    0x90: X86_REG_RBX,
    0x98: X86_REG_RSP,
    0xa0: X86_REG_RBP,
    0xa8: X86_REG_RSI,
    0xb0: X86_REG_RDI,
    0xb8: X86_REG_R8,
    0xc0: X86_REG_R9,
    0xc8: X86_REG_R10,
    0xd0: X86_REG_R11,
    0xd8: X86_REG_R12,
    0xe0: X86_REG_R13,
    0xe8: X86_REG_R14,
    0xf0: X86_REG_R15,
    0xf8: X86_REG_RIP,
}

def insn_op_to_json(op):
    if op.type == X86_OP_IMM:
        o = {"imm": op.imm}
    elif op.type == X86_OP_REG:
        o = {"reg": op.reg}
    elif op.type == X86_OP_MEM:
        o = {
            "segment": op.mem.segment,
            "base": op.mem.base,
            "index": op.mem.index,
            "scale": op.mem.scale,
            "disp": op.mem.disp,
        }
    else:
        raise Exception()

    return {
        "type": op.type,
        "size": op.size,
        **o,
    }


def insn_to_json(insn):
    return {
        "address": insn.address,
        "mnemonic": insn.mnemonic,
        "operands": [insn_op_to_json(op) for op in insn.operands]
    }

DEOBFUSCATED_BLOCKS = []
class SerpentineRawBlock:
    context: dict | None
    unwind_ops: list[str]
    insns: list

    def __init__(self, ql: Qiling):
        self.context = None
        self.unwind_ops = []
        self.insns = []

    def append(self, insn):
        self.insns.append(insn)

    def lift(self, md: Cs):
        global SHELLCODE_BASE
        self.insns = [
            next(md.disasm(insn.bytes, insn.address - SHELLCODE_BASE))
            for insn in self.insns
        ]

        overwritten_regs = set()
        current_context_reg = None
        lifted = []
        def get_context_store(insn):
            if X86_REG_R9 in overwritten_regs:
                return None

            if insn.mnemonic != "mov":
                return None

            dst, src = insn.operands
            if dst.type != X86_OP_REG:
                return None
            
            if src.type != X86_OP_MEM:
                return None

            if src.mem.base != X86_REG_R9:
                return None

            if src.mem.disp != 0x28:
                return None

            overwritten_regs.add(dst.reg)

            return dst.reg

        def get_context_read(op):
            if op.type != X86_OP_MEM:
                return None

            if op.mem.base != current_context_reg:
                return None

            if op.mem.disp not in CONTEXT_OFFSETS:
                breakpoint()
                raise Exception()

            return CONTEXT_OFFSETS[op.mem.disp]

        def lift_context_access(insn):
            nonlocal current_context_reg, overwritten_regs
            if current_context_reg is None:
                return None

            if insn.mnemonic == "mov":
                dst, src = insn.operands
                if dst.type != X86_OP_REG:
                    return None

                if (context_read := get_context_read(src)) is None:
                    return None

                if dst.reg == current_context_reg:
                    current_context_reg = None

                lifted = insn_to_json(insn)
                lifted["operands"][1] = {
                    "type": X86_OP_REG,
                    "size": 8,
                    "reg": context_read,
                    "from_context": True
                }

                return lifted
            
            if insn.mnemonic in ("add", "sub", "xor"):
                if len(insn.operands) == 1:
                    src = insn.operands[0]
                    if (context_read := get_context_read(src)) is None:
                        return None

                    if context_read in overwritten_regs:
                        raise Exception()

                    lifted = insn_to_json(insn)
                    lifted["operands"][0] = {
                        "type": X86_OP_REG,
                        "size": 8,
                        "reg": context_read,
                        "from_context": True
                    }

                    return lifted

                if len(insn.operands) != 2:
                    raise Exception()

                for i, op in enumerate(insn.operands):
                    if (context_read := get_context_read(op)) is None:
                        continue

                    lifted = insn_to_json(insn)
                    lifted["operands"][i] = {
                        "type": X86_OP_REG,
                        "size": 8,
                        "reg": context_read,
                        "from_context": True
                    }

                    return lifted
                else:
                    raise Exception()

            if insn.mnemonic == "ldmxcsr":
                src = insn.operands[0]
                if (context_read := get_context_read(src)) is None:
                    return None

                lifted = insn_to_json(insn)
                lifted["operands"][0] = {
                    "type": X86_OP_REG,
                    "size": 8,
                    "reg": context_read,
                    "from_context": True
                }
                return lifted

            return None

        def get_obfuscated_movabs(insn, i):
            prev = self.insns[i - 1]
            if insn.mnemonic != "add":
                return None
            if prev.mnemonic not in ("movabs", "mov"):
                return None

            acc, add_const = insn.operands
            reg, init_const = prev.operands

            if acc.type != X86_OP_REG:
                return None
            if reg.type != X86_OP_REG:
                return None
            if add_const.type != X86_OP_IMM:
                return None
            if init_const.type != X86_OP_IMM:
                return None
            
            return (init_const.imm + add_const.imm) & 0xFFFFFFFFFFFFFFFF

        def lift_machframe(insn, i):
            if insn.mnemonic != "add" or len(insn.operands) != 2:
                return None

            dst, src = insn.operands
            if dst.type != X86_OP_MEM:
                return None

            if dst.mem.base != X86_REG_RSP:
                return None

            if src.type != X86_OP_IMM:
                raise Exception()

            right = src.imm

            disp = dst.mem.disp

            if disp == 0x18:
                offset = 5
            elif disp == 0x20:
                offset = 6
            else:
                raise Exception()

            movabs = self.insns[i - offset]
            push = self.insns[i - offset + 1]
            other_pushes = self.insns[i - offset + 2 : i]
            if movabs.mnemonic != "movabs":
                raise Exception()

            op = movabs.operands[1]
            if op.type != X86_OP_IMM:
                raise Exception()
            left = op.imm

            if push.mnemonic != "push":
                raise Exception()

            for p in other_pushes:
                if p.mnemonic != "push":
                    raise Exception()
                if p.operands[0].type != X86_OP_IMM:
                    raise Exception()

            op = movabs.operands[0]
            if op.type != X86_OP_REG:
                raise Exception()

            reg = op.reg
            op = push.operands[0]
            if op.type != X86_OP_REG or op.reg != reg:
                raise Exception()
            

            lifted = [
                {
                    "address": push.address,
                    "mnemonic": "push",
                    "operands": [{
                        "type": X86_OP_IMM,
                        "size": 8,
                        "imm": left + right,
                    }],
                }
            ] + [
                {
                    "address": p.address,
                    "mnemonic": "push",
                    "operands": [{
                        "type": X86_OP_IMM,
                        "size": 8,
                        "imm": 0,
                    }],
                }
                for p in other_pushes
            ]
            return (offset, lifted)

        for i, insn in enumerate(self.insns):
            if (machframe_info := lift_machframe(insn, i)) is not None:
                offset, lifted_machframe = machframe_info
                lifted[-offset:] = lifted_machframe
                continue

            if (const := get_obfuscated_movabs(insn, i)) is not None:
                lifted[-1] = {
                    "address": lifted[-1]["address"],
                    "mnemonic": "movabs",
                    "operands": [
                        lifted[-1]["operands"][0],
                        {
                            "type": X86_OP_IMM,
                            "size": 8,
                            "imm": const,
                        },
                    ],
                }
                continue
            elif (context_reg := get_context_store(insn)) is not None:
                current_context_reg = context_reg
                continue
            
            read_regs, write_regs = insn.regs_access()
            for reg in write_regs:
                overwritten_regs.add(reg)
            if (context_read := lift_context_access(insn)) is not None:
                lifted.append(context_read)
                continue
            
            lifted.append(insn_to_json(insn))

        return lifted


def unwind(ql: Qiling, address: int):
    global DEOBFUSCATED_BLOCKS, SHELLCODE_BASE
    relative_address = address - SHELLCODE_BASE
    unwind_info_relative_address = relative_address + 1 + ql.mem.read_ptr(address + 1, 1) + 1

    unwind_info_relative_address += unwind_info_relative_address & 1
    unwind_info_address = SHELLCODE_BASE + unwind_info_relative_address

    ql.log.info(f"Reading UnwindInfo for {address:#x} (+{relative_address:#x}) @ {unwind_info_address:#x} (+{unwind_info_relative_address:#x})")
    unwind_info_data = ql.mem.read(unwind_info_address, 4)
    if unwind_info_data[0] != 0x09:
        ql.log.warning(f"Unexpected VersionAndFlags for {address:#x} (+{relative_address:#x}) @ {unwind_info_address:#x} (+{unwind_info_relative_address:#x})")
    if unwind_info_data[1] != 0x00:
        ql.log.warning(f"Unexpected SizeOfProlog for {address:#x} (+{relative_address:#x}) @ {unwind_info_address:#x} (+{unwind_info_relative_address:#x})")

    unwind_code_count = unwind_info_data[2]
    frame_offset = unwind_info_data[3] >> 4
    frame_register = UNWIND_REGS[unwind_info_data[3] & 0b1111]

    # ql.log.info(f"RSP: {ql.arch.regs.rsp:#x}")
    prolog_offset = relative_address
    establisher_frame = ql.arch.regs.rsp
    i = 0
    while i < unwind_code_count:
        unwind_code = ql.mem.read(unwind_info_address + 4 + (i * 2), 2)
        code_offset = unwind_code[0]
        op_info = unwind_code[1] >> 4
        op_code = unwind_code[1] & 0b1111

        i += 1

        match op_code:
            case 0:
                old_rsp = ql.arch.regs.rsp
                value = ql.stack_pop()
                ql.arch.regs.write(UNWIND_REGS[op_info], value)
                op = f"UWOP_SAVE_NONVOL({UNWIND_REGS[op_info]}, {old_rsp:#x}) = {value:#x}"
                # ql.log.info(op)
                DEOBFUSCATED_BLOCKS[-1].unwind_ops.append(op)
            case 1:
                if op_info == 0:
                    offset = ql.mem.read_ptr(unwind_info_address + 4 + (i * 2), 2) * 8
                    i += 1
                else:
                    offset = ql.mem.read_ptr(unwind_info_address + 4 + (i * 2), 4)
                    i += 2

                ql.arch.regs.rsp += offset
                op = f"UWOP_ALLOC_LARGE({offset:#x})"
                # ql.log.info(op)
                DEOBFUSCATED_BLOCKS[-1].unwind_ops.append(op)
            case 2:
                offset = (op_info * 8) + 8
                ql.arch.regs.rsp += offset
                op = f"UWOP_ALLOC_SMALL({offset:#x})"
                # ql.log.info(op)
                DEOBFUSCATED_BLOCKS[-1].unwind_ops.append(op)
            case 3:
                ql.arch.regs.rsp = ql.arch.regs.read(frame_register) - (frame_offset * 16)
                op = f"UWOP_SET_FPREG({frame_register}, {frame_offset * 16})"
                # ql.log.info(op)
                DEOBFUSCATED_BLOCKS[-1].unwind_ops.append(op)
            case 10:
                return_address = ql.arch.regs.rsp
                stack_address = ql.arch.regs.rsp + (3 * 8)
                if op_info != 0:
                    return_address += 8
                    stack_address += 8

                ql.arch.regs.arch_pc = ql.mem.read_ptr(return_address, 8)
                ql.arch.regs.rsp = ql.mem.read_ptr(stack_address, 8)
                op = f"UWOP_PUSH_MACHFRAME({return_address:#x}, {stack_address:#x})"
                # ql.log.info(op)
                DEOBFUSCATED_BLOCKS[-1].unwind_ops.append(op)
            case _:
                ql.log.warning(f"Unknown opcode {op_code}")
                break

    dispatcher_context = ql.os.heap.alloc(8 * 8)
    ql.mem.write_ptr(dispatcher_context, address, 8)
    ql.mem.write_ptr(dispatcher_context + 0x8, SHELLCODE_BASE, 8)
    ql.mem.write_ptr(dispatcher_context + 0x10, SHELLCODE_BASE, 8)
    ql.mem.write_ptr(dispatcher_context + 0x18, establisher_frame, 8)

    context = ql.os.heap.alloc(0x4d0)
    ql.mem.write_ptr(context + 0x34, ql.arch.regs.read(UC_X86_REG_MXCSR), 4)
    ql.mem.write_ptr(context + 0x38, ql.arch.regs.cs, 2)
    ql.mem.write_ptr(context + 0x3a, ql.arch.regs.ds, 2)
    ql.mem.write_ptr(context + 0x3c, ql.arch.regs.es, 2)
    ql.mem.write_ptr(context + 0x3e, ql.arch.regs.fs, 2)
    ql.mem.write_ptr(context + 0x40, ql.arch.regs.gs, 2)
    ql.mem.write_ptr(context + 0x42, ql.arch.regs.ss, 2)
    ql.mem.write_ptr(context + 0x44, ql.arch.regs.eflags, 4)
    ql.mem.write_ptr(context + 0x48, ql.arch.regs.dr0, 8)
    ql.mem.write_ptr(context + 0x50, ql.arch.regs.dr1, 8)
    ql.mem.write_ptr(context + 0x58, ql.arch.regs.dr2, 8)
    ql.mem.write_ptr(context + 0x60, ql.arch.regs.dr3, 8)
    ql.mem.write_ptr(context + 0x68, ql.arch.regs.dr6, 8)
    ql.mem.write_ptr(context + 0x70, ql.arch.regs.dr7, 8)
    ql.mem.write_ptr(context + 0x78, ql.arch.regs.rax, 8)
    ql.mem.write_ptr(context + 0x80, ql.arch.regs.rcx, 8)
    ql.mem.write_ptr(context + 0x88, ql.arch.regs.rdx, 8)
    ql.mem.write_ptr(context + 0x90, ql.arch.regs.rbx, 8)
    ql.mem.write_ptr(context + 0x98, ql.arch.regs.rsp, 8)
    ql.mem.write_ptr(context + 0xa0, ql.arch.regs.rbp, 8)
    ql.mem.write_ptr(context + 0xa8, ql.arch.regs.rsi, 8)
    ql.mem.write_ptr(context + 0xb0, ql.arch.regs.rdi, 8)
    ql.mem.write_ptr(context + 0xb8, ql.arch.regs.r8,  8)
    ql.mem.write_ptr(context + 0xc0, ql.arch.regs.r9,  8)
    ql.mem.write_ptr(context + 0xc8, ql.arch.regs.r10, 8)
    ql.mem.write_ptr(context + 0xd0, ql.arch.regs.r11, 8)
    ql.mem.write_ptr(context + 0xd8, ql.arch.regs.r12, 8)
    ql.mem.write_ptr(context + 0xe0, ql.arch.regs.r13, 8)
    ql.mem.write_ptr(context + 0xe8, ql.arch.regs.r14, 8)
    ql.mem.write_ptr(context + 0xf0, ql.arch.regs.r15, 8)
    ql.mem.write_ptr(context + 0xf8, ql.arch.regs.rip, 8)

    assert(DEOBFUSCATED_BLOCKS[-1].context is None)
    DEOBFUSCATED_BLOCKS[-1].context = ql.arch.regs.save()

    ql.mem.write_ptr(dispatcher_context + 0x28, context, 8)

    ql.arch.regs.rsp = establisher_frame
    align = unwind_code_count & 1
    exception_handler = SHELLCODE_BASE + ql.mem.read_ptr(unwind_info_address + 4 + ((unwind_code_count + align) * 2), 4)
    ql.os.fcall.call_native(exception_handler, (
        (POINTER, 0),
        (POINTER, 0),
        (POINTER, 0),
        (POINTER, dispatcher_context),
    ), ql.arch.regs.arch_pc)

def monitor_function_table(ql: Qiling, address: int, size: int):
    global FUNCTION_TABLES

    for base_address, length, callback in FUNCTION_TABLES.values():
        if not base_address <= address <= (base_address + length):
            continue

        # ql.verbose = QL_VERBOSE.DISASM
        if size == 1 and ql.mem.read_ptr(address, 1) == 0xF4: # hlt
            unwind(ql, address)

def is_obfuscated_jmp(ql: Qiling, ret_address: int, size: int):
    if size != 1 or ql.mem.read_ptr(ret_address, 1) != 0xc3:
        return False

    epilogue_start = ret_address - 19
    insns = list(ql.arch.disassembler.disasm(ql.mem.read(epilogue_start, 19), epilogue_start))
    if len(insns) != 4:
        return False

    push, movabs, lea, xchg = insns

    if push.mnemonic != "push" or push.op_str != "rax":
        return False
    
    if movabs.mnemonic != "movabs" or not movabs.op_str.startswith("rax"):
        return False
    
    if lea.mnemonic != "lea" or not lea.op_str.startswith("rax, [rax +"):
        return False

    if xchg.mnemonic != "xchg" or xchg.op_str != "qword ptr [rsp], rax":
        return False

    return True

def is_obfuscation_prologue(ql: Qiling, pop_address: int, size: int):
    if size != 1 or ql.mem.read_ptr(pop_address, 1) != 0x58:
        return False

    if ql.mem.read(pop_address - 6, 6) != bytes.fromhex("890501000000"):
        return False

    insns = list(ql.arch.disassembler.disasm(ql.mem.read(pop_address - 33, 27), pop_address - 33))
    if len(insns) != 5:
        return False

    pop, push, clear, get, add = insns
    
    if pop.mnemonic != "pop" or not pop.op_str.startswith("qword ptr [rip + 0x"):
        return False
    
    if push.mnemonic != "push" or push.op_str != "rax":
        return False

    if clear.mnemonic != "mov" or clear.op_str != "rax, 0":
        return False

    if get.mnemonic != "mov" or not get.op_str.startswith("ah, byte ptr [rip - 0x"):
        return False

    if add.mnemonic != "lea" or not add.op_str.startswith("eax, [eax "):
        return False

    return True

VISITED = []
OBFUSCATED_RIPS = set()
VISITED_BRANCHES = set()
def log_deobfuscated(ql: Qiling, address: int, size: int):
    global VISITED, DEOBFUSCATED_BLOCKS, OBFUSCATED_RIPS

    if len(VISITED) > 0 and address == VISITED[-1]: # The instruction modification causes a double call on hooks
        return

    VISITED.append(address)

    if size == 1 and ql.mem.read_ptr(address, 1) == 0xF4: # hlt
        DEOBFUSCATED_BLOCKS.append(SerpentineRawBlock(ql))
        return

    insn = next(ql.arch.disassembler.disasm(ql.mem.read(address, size), address))
    if insn.mnemonic in ["call", "jmp"] and insn.op_str.startswith("0x"):
        return
    elif is_obfuscation_prologue(ql, address, size):
        DEOBFUSCATED_BLOCKS[-1].insns = DEOBFUSCATED_BLOCKS[-1].insns[:-6]
        OBFUSCATED_RIPS.add(address + 1)
        return
    elif is_obfuscated_jmp(ql, address, size):
        DEOBFUSCATED_BLOCKS[-1].insns = DEOBFUSCATED_BLOCKS[-1].insns[:-4]
        return
    elif insn.mnemonic in "mov" and insn.op_str.startswith("dword ptr [rip - 0x"):
        match = re.match(r"^dword ptr \[rip - (0x.+)\], ", insn.op_str)
        if match is not None:
            displacement = int(match[1], 16)
            target_address = insn.address + insn.size - displacement
            if target_address in OBFUSCATED_RIPS:
                return

    DEOBFUSCATED_BLOCKS[-1].append(insn)

    if insn.mnemonic == "cmovne":
        regs = insn.op_str.split(", ")
        jmp = next(ql.arch.disassembler.disasm(ql.mem.read(address + insn.size, 3), address))
        if jmp.mnemonic == "jmp" and jmp.op_str == regs[0]:
            DEOBFUSCATED_BLOCKS[-1].append(jmp)

            branch_targets = []
            for reg in regs:
                target = ql.arch.regs.read(reg)
                ql.log.info(f"{reg}: {target:#x}")
                if target == 0x1400011f0:
                    continue

                if target in VISITED_BRANCHES:
                    continue

                branch_targets.append(target)

            if len(branch_targets) == 0:
                ql.stop()
                return
            elif len(branch_targets) > 1:
                breakpoint()

            target = branch_targets[0]
            VISITED_BRANCHES.add(target)
            ql.arch.regs.arch_pc = target


TLS_INITED = False
def tls_callback(ql: Qiling):
    global TLS_INITED

    @winsdkapi(cc=STDCALL, params={
        'lpAddress'        : LPVOID,
        'dwSize'           : SIZE_T,
        'flAllocationType' : DWORD,
        'flProtect'        : DWORD
    })
    def hook_VirtualAlloc(ql: Qiling, address: int, params):
        global SHELLCODE_BASE
        # dwSize = params["dwSize"] + 0x1000

        # address = ql.os.heap.alloc(dwSize)
        # address = (address & ~(0x1000-1))
        # ql.mem.add_mapinfo(address, address + params["dwSize"], 7, "shellcode")
        SHELLCODE_BASE = ql.mem.map_anywhere(params["dwSize"], align=0x10000, info="[shellcode]")
        return SHELLCODE_BASE

    if not TLS_INITED:
        ql.log.info("Doing TLS callback...")
        ql.os.set_api("VirtualAlloc", hook_VirtualAlloc, QL_INTERCEPT.CALL)
        ql.os.fcall.call_native(0x1400014f0, [
            (PVOID, 0),
            (DWORD, 1),
            (PVOID, 0),
        ], ql.arch.regs.arch_pc)
        TLS_INITED = True

def wrong_key(ql: Qiling):
    ql.log.info("Wrong key!!")
    ql.stop()

def ql_hook_block_disasm(ql, address, size):
    ql.log.debug("\n[+] Tracing basic block at 0x%x" % (address))

def mem_modify(ql: Qiling, access: int, address: int, size: int, value: int):
    pass

def run(user_input):
    ql = Qiling(
        ["./rootfs/x8664_windows/serpentine.exe", user_input],
        rootfs="./rootfs/x8664_windows",
        archtype=QL_ARCH.X8664,
        ostype=QL_OS.WINDOWS,
        # verbose=QL_VERBOSE.DEBUG,
        profile="./windows.ql"
    )

    ql.os.set_api("RtlInstallFunctionTableCallback", RtlInstallFunctionTableCallback, QL_INTERCEPT.CALL)
    ql.hook_address(tls_callback, 0x140001a14)
    ql.hook_address(wrong_key, 0x1400011f0)

    ql.run()

    global DEOBFUSCATED_BLOCKS, SHELLCODE_BASE
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True

    for block in DEOBFUSCATED_BLOCKS:
        ql.log.info("BLOCK START")
        for op in block.unwind_ops:
            ql.log.info(f"\t{op}")
        for insn in block.insns:
            ql.log.info(f"\t{insn.address - SHELLCODE_BASE:06x} {insn.size:02x} {insn.mnemonic} {insn.op_str}")

    lifted_blocks = []
    for block in DEOBFUSCATED_BLOCKS:
        lifted_blocks.append({
            "unwind_ops": block.unwind_ops,
            "insns": block.lift(disassembler),
        })

    import json
    with open("lifted.json", "w") as f:
        json.dump(lifted_blocks, f)

if __name__ == "__main__":
    run(INPUT)
