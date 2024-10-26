import re
import itertools
import string
import zlib
from Crypto.Hash import MD5, SHA256

rules = {}
solved = {}

other = []

def simplify(line):
    if not (match := re.match(r"^(uint(?:8|32)\(.+\)) (.+) (\d+) (.?=) (\d+)", line)):
        return line

    target = match[1]
    operator = match[2]
    c1 = match[3]
    compare = match[4]
    c2 = match[5]

    value = None
    match operator:
        case "^":
            value = int(c2) ^ int(c1)
        case "+":
            value = int(c2) - int(c1)
        case "-":
            value = int(c2) + int(c1)

    if value is None:
        return line

    return f"{target} {compare} {value}"

crc_lookup = {}
md5_lookup = {}
sha_lookup = {}

for s in [
    (a + b).encode()
    for a, b in itertools.product(string.printable, string.printable)
]:
    crc_lookup[zlib.crc32(s) % (1<<32)] = s
    md5_lookup[MD5.new(data=s).digest()] = s
    sha_lookup[SHA256.new(data=s).digest()] = s


with open("aray.edited.yara") as f:
    for line in f:
        line = line.strip()
        if len(line) == 0:
            continue

        if (match := re.match(r"^uint(?:8|32)\((.+)\)", line)):
            index = int(match[1])

            if (match := re.match(r"^uint8\(.+\) % (\d+) < (\d+)", line)) and match[1] == match[2]:
                continue

            line = simplify(line)

            if (match := re.match(r"^uint8\(.+\) == (\d+)", line)):
                if index in solved:
                    raise Exception()

                solved[index] = int(match[1])
            elif (match := re.match(r"^uint32\(.+\) == (\d+)", line)):
                chars = int(match[1]).to_bytes(4, "little")
                for i in range(index, index + 4):
                    if i in solved:
                        raise Exception()

                    solved[i] = chars[i - index]
            else:
                rules.setdefault(index, []).append(line)
        elif (match := re.match(r"^hash.crc32\((\d+), 2\) == (0x.+)", line)):
            index = int(match[1])
            
            if (plain := crc_lookup.get(int(match[2], 16))) is not None:
                for i in range(index, index + 2):
                    if i in solved:
                        raise Exception()

                    solved[i] = plain[i - index]
            else:
                rules.setdefault(index, []).append(line)
        elif (match := re.match(r"^hash.(md5|sha256)\((\d+), 2\) == \"(.+)\"", line)):
            hash_type = match[1]
            index = int(match[2])

            digest = bytes.fromhex(match[3])
            if hash_type == "md5":
                plain = md5_lookup.get(digest)
            else:
                plain = sha_lookup.get(digest)
            
            if plain is not None:
                for i in range(index, index + 2):
                    if i in solved:
                        raise Exception()

                    solved[i] = plain[i - index]
            else:
                rules.setdefault(index, []).append(line)
        else:
            other.append(line)


if all(i in solved for i in range(85)):
    print("".join(chr(solved[i]) for i in range(85)))
else:
    for k in sorted(set(solved.keys()) | set(rules.keys())):
        if k in solved:
            print(f"{k}\t{chr(solved[k])}")
        else:
            for rule in rules[k]:
                print(rule)

for rule in other:
    print(rule)
