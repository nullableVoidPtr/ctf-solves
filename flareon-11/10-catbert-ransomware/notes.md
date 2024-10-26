0002f38e

# Opcodes

## `00` - `hlt`
* Terminates program

## `01` - `push_imm`
* Reads encoded short `imm` following opcode
* Pushes `imm`

## `02` - `push_scratch`
* Reads encoded short `imm` following opcode
* Pushes `SCRATCH[imm]`

## `03` - `add_scratch`
* Reads encoded short `imm` following opcode
* Pops one qword `right`
* Pushes `SCRATCH[imm] + right`

## `04` - `pop_scratch`
* Reads encoded short `imm` following opcode
* Pops one qword `value`
* `SCRATCH[imm] = value`

## `05` - `get_scratch`
* Pops one qword `index`
* Pushes `SCRATCH[index]`

## `06` - `set_scratch`
* Pops two qwords `index` and `value`
* Sets `SCRATCH[index] = value`

## `07` - `dup`
* Copies top qword and pushes

## `08` - `pop`
* Pops one qword and does nothing

## `09` - `add`
* Pop two qwords `left` and `right`
* Push one qword `left + right`

## `0A` - `add_imm`
* Reads encoded short `imm` following opcode
* Pops one qword `left`
* Pushes `left + imm`

## `0B` - `sub`
* Pop two qwords `left` and `right`
* Push one qword `left - right`

## `0C` - `div`
* Pop two qwords `left` and `right`
* Push one qword `left / right`

## `0D` - `mul`
* Pop two qwords `left` and `right`
* Push one qword `left * right`

## `0E` - `jmp`
* Reads encoded short `imm` following opcode
* Set `VmIp += imm`

## `0F` - `jz`
* Pops one qword `predicate`
* Reads encoded short `imm` following opcode
* If `predicate == 0`, set `VmIp += imm`

## `10` - `jnz`
* Pops one qword `predicate`
* Reads encoded short `imm` following opcode
* If `predicate != 0`, set `VmIp += imm`

## `11` - `eq`
* Pop two qwords `left` and `right`
* Push one qword `left == right`

## `12` - `lt`
* Pop two qwords `left` and `right`
* Push one qword `left < right`

## `13` - `lte`
* Pop two qwords `left` and `right`
* Push one qword `left <= right`

## `14` - `gt`
* Pop two qwords `left` and `right`
* Push one qword `left > right`

## `15` - `gte`
* Pop two qwords `left` and `right`
* Push one qword `left >= right`

## `16` - `gte_imm`
* Reads encoded short `imm` following opcode
* Pop one qword `left`
* Push one qword `left >= imm`

## `17` - `set_return`
* Pop one qword `value`
* Sets external `VmStatus` global to `value`

## `18` - `return`
* Terminates program

## `19` - `set_return`
* Pop one qword `value`
* Sets external `VmStatus` global to `value`

## `1A` - `xor`
* Pop two qwords `left` and `right`
* Push one qword `left ^ right`

## `1B` - `or`
* Pop two qwords `left` and `right`
* Push one qword `left | right`

## `1C` - `and`
* Pop two qwords `left` and `right`
* Push one qword `left & right`

## `1D` - `mod`
* Pop two qwords `left` and `right`
* Push one qword `left % right`

## `1E` - `shl`
* Pop two qwords `left` and `right`
* Push one qword `left << right`

## `1F` - `shr`
* Pop two qwords `left` and `right`
* Push one qword `left >> right`

## `20` - `cshl32`
* Pop two qwords `left` and `right`
* Truncate `left` to dword
* Truncate `right` to byte
* Push one qword `(left >> (32 - right)) | (left << right)`

## `21` - `cshr32`
* Pop two qwords `left` and `right`
* Truncate `left` to dword
* Truncate `right` to byte
* Push one qword `(left << (32 - right)) | (left >> right)`

## `22` - `cshl16`
* Pop two qwords `left` and `right`
* Truncate `left` to short
* Truncate `right` to byte
* Push one qword `(left >> (16 - right)) | (left << right)`

## `23` - `cshr16`
* Pop two qwords `left` and `right`
* Truncate `left` to short
* Truncate `right` to byte
* Push one qword `(left << (16 - right)) | (left >> right)`

## `24` - `cshl8`
* Pop two qwords `left` and `right`
* Truncate `left` to byte
* Truncate `right` to byte
* Push one qword `(left >> (8 - right)) | (left << right)`

## `25` - `cshr8`
* Pop two qwords `left` and `right`
* Truncate `left` to byte
* Truncate `right` to byte
* Push one qword `(left << (8 - right)) | (left >> right)`

## `26` - `out`
* Pops one qword `value`
* Performs `printf("%c", value)`
