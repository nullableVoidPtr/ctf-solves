import sys
from ctypes import c_uint64


class StackOperand:
    index: int

    def __init__(self, index: int):
        self.index = index

    def __eq__(self, other):
        return self.index == other.index

    def __str__(self):
        return f"StackOperand({self.index})"

    def __repr__(self):
        return f"StackOperand({self.index})"

class ScratchOperand:
    index: int | StackOperand

    def __init__(self, index: int | StackOperand):
        self.index = index

    def __eq__(self, other):
        return self.index == other.index
 
    def __str__(self):
        return f"SCRATCH[{self.index:#x}]"

    def __repr__(self):
        return f"SCRATCH[{self.index:#x}]"

def disassemble(program: bytes):
    queue = [0x0]
    disassembled = {}

    def read_imm_short():
        return int.from_bytes(program[ip+1:ip+3], "big")

    while len(queue) > 0:
        ip = queue.pop()
        while ip not in disassembled:
            if ip >= len(program):
                break

            opcode = program[ip]

            match opcode:
                case 0x00:
                    disassembled[ip] = ("hlt", ())
                    break

                case 0x01:
                    imm = read_imm_short()
                    disassembled[ip] = ("push", (imm,))
                    ip += 2

                case 0x02:
                    imm = read_imm_short()
                    disassembled[ip] = ("push", (ScratchOperand(imm),))
                    ip += 2

                case 0x03:
                    imm = read_imm_short()
                    disassembled[ip] = ("add", (ScratchOperand(imm), StackOperand(0)))
                    ip += 2

                case 0x04:
                    imm = read_imm_short()
                    disassembled[ip] = ("pop", (ScratchOperand(imm), ))
                    ip += 2

                case 0x05:
                    disassembled[ip] = ("get_scratch", (StackOperand(0),))

                case 0x06:
                    disassembled[ip] = ("set_scratch", (StackOperand(0), StackOperand(1)))

                case 0x07:
                    disassembled[ip] = ("dup", ())

                case 0x08:
                    disassembled[ip] = ("pop", ())

                case 0x09:
                    disassembled[ip] = ("add", (StackOperand(0), StackOperand(1)))

                case 0x0A:
                    right = read_imm_short()
                    disassembled[ip] = ("add", (StackOperand(0), right))
                    ip += 2

                case 0x0B:
                    disassembled[ip] = ("sub", (StackOperand(0), StackOperand(1)))

                case 0x0C:
                    disassembled[ip] = ("div", (StackOperand(0), StackOperand(1)))

                case 0x0D:
                    disassembled[ip] = ("mul", (StackOperand(0), StackOperand(1)))

                case 0x0E:
                    offset = read_imm_short()
                    disassembled[ip] = ("jmp", (offset,))
                    ip += 2
                    queue.append(offset)
                    break

                case 0x0F:
                    offset = read_imm_short()
                    disassembled[ip] = ("jz", (StackOperand(0), offset))
                    ip += 2
                    queue.append(offset)

                case 0x10:
                    offset = read_imm_short()
                    disassembled[ip] = ("jnz", (StackOperand(0), offset))
                    ip += 2
                    queue.append(offset)

                case 0x11:
                    disassembled[ip] = ("eq", (StackOperand(0), StackOperand(1)))

                case 0x12:
                    disassembled[ip] = ("lt", (StackOperand(0), StackOperand(1)))

                case 0x13:
                    disassembled[ip] = ("lte", (StackOperand(0), StackOperand(1)))

                case 0x14:
                    disassembled[ip] = ("gt", (StackOperand(0), StackOperand(1)))

                case 0x15:
                    disassembled[ip] = ("gte", (StackOperand(0), StackOperand(1)))

                case 0x16:
                    right = read_imm_short()
                    disassembled[ip] = ("gte", (StackOperand(0), right))
                    ip += 2

                case 0x17 | 0x19:
                    disassembled[ip] = ("set_return", (StackOperand(0),))

                case 0x18:
                    disassembled[ip] = ("hlt", ())
                    break

                case 0x1A:
                    disassembled[ip] = ("xor", (StackOperand(0), StackOperand(1)))

                case 0x1B:
                    disassembled[ip] = ("or", (StackOperand(0), StackOperand(1)))

                case 0x1C:
                    disassembled[ip] = ("and", (StackOperand(0), StackOperand(1)))

                case 0x1D:
                    disassembled[ip] = ("mod", (StackOperand(0), StackOperand(1)))

                case 0x1E:
                    disassembled[ip] = ("shl", (StackOperand(0), StackOperand(1)))

                case 0x1F:
                    disassembled[ip] = ("shr", (StackOperand(0), StackOperand(1)))

                case 0x20:
                    disassembled[ip] = ("rol32", (StackOperand(0), StackOperand(1)))

                case 0x21:
                    disassembled[ip] = ("ror32", (StackOperand(0), StackOperand(1)))

                case 0x22:
                    disassembled[ip] = ("rol16", (StackOperand(0), StackOperand(1)))

                case 0x23:
                    disassembled[ip] = ("ror16", (StackOperand(0), StackOperand(1)))

                case 0x24:
                    disassembled[ip] = ("rol8", (StackOperand(0), StackOperand(1)))

                case 0x25:
                    disassembled[ip] = ("ror8", (StackOperand(0), StackOperand(1)))

                case 0x26:
                    disassembled[ip] = ("out", (StackOperand(0),))

            ip += 1

    return sorted([
        (address, *instruction)
        for address, instruction in disassembled.items()
    ], key = lambda t: t[0])

def inline_push(disassembled):
    old_len = 0
    while old_len != len(disassembled):
        old_len = len(disassembled)

        i = 0
        while i < len(disassembled):
            address, instruction, operands = disassembled[i]
            if instruction != "push":
                i += 1
                continue

            _, next_instruction, next_operands = disassembled[i + 1]

            last_stack_operand_index = None
            for j, operand in enumerate(next_operands):
                if isinstance(operand, StackOperand):
                    last_stack_operand_index = j

            if last_stack_operand_index is None:
                i += 1
                continue

            next_operands = list(next_operands)
            next_operands[last_stack_operand_index] = operands[0]
            next_operands = tuple(next_operands)

            disassembled[i:i+2] = [(address, next_instruction, next_operands)]

            i += 1

def inline_get_scratch(disassembled):
    old_len = 0
    while old_len != len(disassembled):
        old_len = len(disassembled)

        i = 0
        while i < len(disassembled):
            address, instruction, operands = disassembled[i]
            if instruction != "get_scratch":
                i += 1
                continue

            _, next_instruction, next_operands = disassembled[i + 1]

            last_stack_operand_index = None
            for j, operand in enumerate(next_operands):
                if isinstance(operand, StackOperand):
                    last_stack_operand_index = j

            if last_stack_operand_index is None:
                i += 1
                continue

            next_operands = list(next_operands)
            next_operands[last_stack_operand_index] = ScratchOperand(operands[0])
            next_operands = tuple(next_operands)

            disassembled[i:i+2] = [(address, next_instruction, next_operands)]

            i += 1

def inline_binops(disassembled):
    old_len = 0
    while old_len != len(disassembled):
        old_len = len(disassembled)

        i = 0
        while i < len(disassembled):
            address, instruction, operands = disassembled[i]

            match instruction:
                case "add":
                    infix = "+"
                case "sub":
                    infix = "-"
                case "div":
                    infix = "/"
                case "mul":
                    infix = "*"
                case "eq":
                    infix = "=="
                case "lt":
                    infix = "<"
                case "lte":
                    infix = "<="
                case "gt":
                    infix = ">"
                case "gte":
                    infix = ">="
                case "xor":
                    infix = "^"
                case "or":
                    infix = "|"
                case "and":
                    infix = "&"
                case "mod":
                    infix = "%"
                case "shl":
                    infix = "<<"
                case "shr":
                    infix = ">>"
                case _:
                    i += 1
                    continue

            assert len(operands) == 2

            if any(isinstance(o, StackOperand) for o in operands):
                i += 1
                continue

            left, right = operands

            if isinstance(left, int):
                left = hex(left)
            if isinstance(right, int):
                right = hex(right)

            _, next_instruction, next_operands = disassembled[i + 1]

            last_stack_operand_index = None
            for j, operand in enumerate(next_operands):
                if isinstance(operand, StackOperand):
                    last_stack_operand_index = j

            if last_stack_operand_index is None:
                i += 1
                continue

            next_operands = list(next_operands)
            next_operands[last_stack_operand_index] = f"({left} {infix} {right})"
            next_operands = tuple(next_operands)

            disassembled[i:i+2] = [(address, next_instruction, next_operands)]

            i += 1

def inline_circular_shifts(disassembled):
    old_len = 0
    while old_len != len(disassembled):
        old_len = len(disassembled)

        i = 0
        while i < len(disassembled):
            address, instruction, operands = disassembled[i]

            match instruction:
                case "rol32":
                    mask = "0xFFFFFFFF"
                case "ror32":
                    mask = "0xFFFFFFFF"
                case "rol16":
                    mask = "0xFFFF"
                case "ror16":
                    mask = "0xFFFF"
                case "rol8":
                    mask = "0xFF"
                case "ror8":
                    mask = "0xFF"
                case _:
                    i += 1
                    continue

            assert len(operands) == 2

            if any(isinstance(o, StackOperand) for o in operands):
                i += 1
                continue

            left, right = operands

            if isinstance(left, int):
                left = hex(left)
            if isinstance(right, int):
                right = hex(right)

            _, next_instruction, next_operands = disassembled[i + 1]

            last_stack_operand_index = None
            for j, operand in enumerate(next_operands):
                if isinstance(operand, StackOperand):
                    last_stack_operand_index = j

            if last_stack_operand_index is None:
                i += 1
                continue

            next_operands = list(next_operands)
            next_operands[last_stack_operand_index] = f"{instruction.upper()}({left} & {mask}, {right})"
            next_operands = tuple(next_operands)

            disassembled[i:i+2] = [(address, next_instruction, next_operands)]

            i += 1

def run(program: bytes, entrypoint = 0):
    stack: list[c_uint64] = []
    scratch: list[c_uint64] = [c_uint64(0) for _ in range(0x10000)]
    ip = entrypoint

    result = 0
    output = ""

    def read_imm_short():
        nonlocal ip

        imm = int.from_bytes(program[ip:ip+2], "big")
        ip += 2
        return imm

    while True:
        opcode = program[ip]
        ip += 1

        match opcode:
            case 0x00:
                print(f"{ip - 1:#04x}: hlt")
                print()
                print(output)
                return result

            case 0x01:
                imm = read_imm_short()
                stack.append(c_uint64(imm))
                print(f"{ip - 1:#04x}: push {imm:#x}")

            case 0x02:
                imm = read_imm_short()
                stack.append(scratch[imm])
                print(f"{ip - 1:#04x}: push_scratch {imm:#x}")

            case 0x03:
                imm = read_imm_short()
                stack.append(c_uint64(scratch[imm].value + stack.pop().value))
                print(f"{ip - 1:#04x}: add_scratch {imm:#x}")

            case 0x04:
                imm = read_imm_short()
                scratch[imm] = stack.pop()
                print(f"{ip - 1:#04x}: pop_scratch {imm:#x}")

            case 0x05:
                stack.append(scratch[stack.pop().value])
                print(f"{ip - 1:#04x}: get_scratch")

            case 0x06:
                value = stack.pop()
                index = stack.pop()
                scratch[index.value] = value
                print(f"{ip - 1:#04x}: set_scratch")

            case 0x07:
                stack.append(stack[-1])
                print(f"{ip - 1:#04x}: dup")

            case 0x08:
                stack.pop()
                print(f"{ip - 1:#04x}: pop")

            case 0x09:
                right = stack.pop()
                left = stack.pop()
                stack.append(c_uint64(left.value + right.value))
                print(f"{ip - 1:#04x}: add")

            case 0x0A:
                right = read_imm_short()
                left = stack.pop()
                stack.append(c_uint64(left.value + right))
                print(f"{ip - 1:#04x}: add_imm {right:#x}")

            case 0x0B:
                right = stack.pop()
                left = stack.pop()
                stack.append(c_uint64(left.value - right.value))
                print(f"{ip - 1:#04x}: sub")

            case 0x0C:
                right = stack.pop()
                left = stack.pop()
                stack.append(c_uint64(left.value // right.value))
                print(f"{ip - 1:#04x}: div")

            case 0x0D:
                right = stack.pop()
                left = stack.pop()
                stack.append(c_uint64(left.value * right.value))
                print(f"{ip - 1:#04x}: mul")

            case 0x0E:
                offset = read_imm_short()
                print(f"{ip - 1:#04x}: jmp {offset:#04x}")
                ip = offset

            case 0x0F:
                predicate = stack.pop()
                offset = read_imm_short()
                print(f"{ip - 1:#04x}: jz {offset:#04x}")
                if predicate.value == 0:
                    ip = offset

            case 0x10:
                predicate = stack.pop()
                offset = read_imm_short()
                print(f"{ip - 1:#04x}: jnz {offset:#04x}")
                if predicate.value != 0:
                    ip = offset

            case 0x11:
                right = stack.pop()
                left = stack.pop()
                stack.append(c_uint64(left.value == right.value))
                print(f"{ip - 1:#04x}: eq")

            case 0x12:
                right = stack.pop()
                left = stack.pop()
                stack.append(c_uint64(left.value < right.value))
                print(f"{ip - 1:#04x}: lt")

            case 0x13:
                right = stack.pop()
                left = stack.pop()
                stack.append(c_uint64(left.value <= right.value))
                print(f"{ip - 1:#04x}: lte")

            case 0x14:
                right = stack.pop()
                left = stack.pop()
                stack.append(c_uint64(left.value > right.value))
                print(f"{ip - 1:#04x}: gt")

            case 0x15:
                right = stack.pop()
                left = stack.pop()
                stack.append(c_uint64(left.value >= right.value))
                print(f"{ip - 1:#04x}: gte")

            case 0x16:
                right = read_imm_short()
                left = stack.pop()
                stack.append(c_uint64(left.value >= right))
                print(f"{ip - 1:#04x}: gte_imm")

            case 0x17 | 0x19:
                value = stack.pop()
                result = value.value
                print(f"{ip - 1:#04x}: set_return")

            case 0x18:
                print(f"{ip - 1:#04x}: return")
                print()
                print(output)
                return result

            case 0x1A:
                right = stack.pop()
                left = stack.pop()
                stack.append(c_uint64(left.value ^ right.value))
                print(f"{ip - 1:#04x}: xor")

            case 0x1B:
                right = stack.pop()
                left = stack.pop()
                stack.append(c_uint64(left.value | right.value))
                print(f"{ip - 1:#04x}: or")

            case 0x1C:
                right = stack.pop()
                left = stack.pop()
                stack.append(c_uint64(left.value & right.value))
                print(f"{ip - 1:#04x}: and")

            case 0x1D:
                right = stack.pop()
                left = stack.pop()
                stack.append(c_uint64(left.value % right.value))
                print(f"{ip - 1:#04x}: mod")

            case 0x1E:
                right = stack.pop()
                left = stack.pop()
                stack.append(c_uint64(left.value << (right.value & 0xFF)))
                print(f"{ip - 1:#04x}: shl")

            case 0x1F:
                right = stack.pop()
                left = stack.pop()
                stack.append(c_uint64(left.value >> (right.value & 0xFF)))
                print(f"{ip - 1:#04x}: shr")

            case 0x20:
                right = stack.pop().value & 0xFF
                left = stack.pop().value & 0xFFFFFFFF
                stack.append(c_uint64((left >> (32 - right)) | (left << right)))
                print(f"{ip - 1:#04x}: rol32")

            case 0x21:
                right = stack.pop().value & 0xFF
                left = stack.pop().value & 0xFFFFFFFF
                stack.append(c_uint64((left << (32 - right)) | (left >> right)))
                print(f"{ip - 1:#04x}: ror32")

            case 0x22:
                right = stack.pop().value & 0xFF
                left = stack.pop().value & 0xFFFF
                stack.append(c_uint64((left >> (16 - right)) | (left << right)))
                print(f"{ip - 1:#04x}: rol16")

            case 0x23:
                right = stack.pop().value & 0xFF
                left = stack.pop().value & 0xFFFF
                stack.append(c_uint64((left << (16 - right)) | (left >> right)))
                print(f"{ip - 1:#04x}: ror16")

            case 0x24:
                right = stack.pop().value & 0xFF
                left = stack.pop().value & 0xFF
                stack.append(c_uint64((left >> (8 - right)) | (left << right)))
                print(f"{ip - 1:#04x}: rol8")

            case 0x25:
                right = stack.pop().value & 0xFF
                left = stack.pop().value & 0xFF
                stack.append(c_uint64((left << (8 - right)) | (left >> right)))
                print(f"{ip - 1:#04x}: ror8")

            case 0x26:
                value = stack.pop().value & 0xFF
                output += chr(value)
                print(f"{ip - 1:#04x}: out")

with open(sys.argv[1], "rb") as f:
    if f.read(4) != b"C4TB":
        raise Exception()

    encrypted_data_size = int.from_bytes(f.read(4), "little")
    vm_program_offset = int.from_bytes(f.read(4), "little")
    vm_program_size = int.from_bytes(f.read(4), "little")

    encrypted_data = f.read(encrypted_data_size)
    with open("encrypted", "wb") as o:
        o.write(encrypted_data)

    f.seek(vm_program_offset)
    vm_program = f.read(vm_program_size)
    disassembled = disassemble(vm_program)

    old_len = 0
    while old_len != len(disassembled):
        old_len = len(disassembled)

        inline_push(disassembled)
        inline_get_scratch(disassembled)
        inline_binops(disassembled)
        inline_circular_shifts(disassembled)

    for address, instruction, operands in disassembled:
        match instruction:
            case "set_scratch":
                assert len(operands) == 2
                left, right = operands

                if isinstance(left, int):
                    left = hex(left)
                if isinstance(right, int):
                    right = hex(right)

                print(f"{address:06x}: SCRATCH[{left}] = {right}")

            case "jnz":
                assert len(operands) == 2
                left, right = operands

                if isinstance(left, int):
                    left = hex(left)
                if isinstance(right, int):
                    right = hex(right)

                print(f"{address:06x}: if ({left}) goto {right}")

            case "jmp":
                assert len(operands) == 1
                target = operands[0]

                if isinstance(target, int):
                    target= hex(target)

                print(f"{address:06x}: goto {target}")

            case _:
                print(f"{address:06x}: {instruction} {', '.join(map(str, operands))}")

    # run(vm_program)
