import hashlib
from pathlib import Path
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from pefile import PE
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RBP, UC_X86_REG_RBX, UC_X86_REG_RCX,
    UC_X86_REG_RDX, UC_X86_REG_RSP, UC_X86_REG_R8, UC_X86_REG_R9,
)

if len(sys.argv) != 2:
    raise SystemExit("Usage: python check_branch.py <TeamfightManager2.exe>")
original = Path(sys.argv[1]).read_bytes()
assert hashlib.sha256(original).hexdigest() == "c74955e11f4845f93dcb73f90c5cdd442615ac72f40ed642a1fdeb5f41def01e"
pe = PE(data=original, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
site = 0x2f752d8
offset = pe.get_offset_from_rva(site)
before = original[offset:offset + 6]
assert before == bytes.fromhex("0f84b8010000")
after = bytes.fromhex("90e9") + before[2:]
instructions = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(after, base + site))
assert [x.mnemonic for x in instructions] == ["nop", "jmp"]
assert int(instructions[-1].op_str, 16) == base + 0x2f75496
patched = original[:offset] + after + original[offset + len(before):]
assert len(patched) == len(original)
print(f"File offset 0x{offset:x} / {offset}")
print("Original:", before.hex())
print("Patched: ", after.hex())
print("SHA-256: ", hashlib.sha256(patched).hexdigest())

# Execute the actual Windows x64 routing function with controlled inputs.
# Only called helpers that populate or free fixture data are mocked.
code_begin = 0x2f75030
code_end = 0x2f755be
raw_begin = pe.get_offset_from_rva(code_begin)
raw_end = raw_begin + code_end - code_begin
game = 0x1000000
server = 0x1100000
human_ids = 0x1200000
regions = human_ids + 0x1000
stack = 0x1300000
return_to = 0x1400000
mapped_hash = game + 0x1f000
code_page = (base + code_begin) & ~4095

def packed(value):
    return struct.pack("<Q", value)

def evaluate(image, *, intensity=0, human=False, special=False, forced=False,
             variant=1, local=True, protected_competition=False):
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    vm.mem_map(code_page, 0x2000)
    vm.mem_write(base + code_begin, image[raw_begin:raw_end])
    vm.mem_map(game, 0x20000)
    vm.mem_map(server, 0x20000)
    vm.mem_map(human_ids, 0x2000)
    vm.mem_map(stack, 0x10000)
    vm.mem_map(return_to, 0x1000)
    vm.mem_write(game + 0x736, bytes([intensity]))
    vm.mem_write(server + 0x13d4, bytes([forced]))
    vm.mem_write(server + 0xb90, packed(server + 0x10000))
    vm.mem_write(game + 0x17900, packed(mapped_hash + 0x100))
    vm.mem_write(game + 0x17918, packed(1))
    vm.mem_write(mapped_hash + 0x100, b"\xff" * 16)
    # Pre-allocate one hash-table record with one team's known league.
    team_id = 22
    key = (team_id * 0xf1357aea2e62a9c5) & ((1 << 64) - 1)
    rotated = ((key << 20) | (key >> 44)) & ((1 << 64) - 1)
    vm.mem_write(mapped_hash + 0x100, bytes([rotated >> 57]) + b"\xff" * 15)
    vm.mem_write(mapped_hash + 0xf0, packed(mapped_hash + 0x200))
    vm.mem_write(mapped_hash + 0xf8, packed(mapped_hash + 0x400))
    vm.mem_write(mapped_hash + 0x200, packed(team_id))
    vm.mem_write(mapped_hash + 0x910, packed(7 if local else 8))
    vm.mem_write(human_ids, packed(team_id if human else 1))
    vm.mem_write(regions, packed(7))
    sp = stack + 0x8000 + 8
    vm.reg_write(UC_X86_REG_RSP, sp)
    vm.reg_write(UC_X86_REG_RCX, game)
    vm.reg_write(UC_X86_REG_RDX, server)
    vm.reg_write(UC_X86_REG_R8, variant)
    vm.reg_write(UC_X86_REG_R9, 42)
    vm.mem_write(sp, packed(return_to))
    vm.mem_write(sp + 0x28, packed(team_id))
    vm.mem_write(sp + 0x30, packed(99))
    stubs = {
        0x2f71aa0: lambda: int(special),
        0x2ed12b0: lambda: int(protected_competition),
        0x2ed1740: lambda: 0,
        0x00128f0: lambda: 0,
    }

    def vec(ptr):
        output = vm.reg_read(UC_X86_REG_RCX)
        vm.mem_write(output, packed(1) + packed(ptr) + packed(1))
        return output

    stubs[0x122dff0] = lambda: vec(human_ids)
    stubs[0x1fbb8d0] = lambda: vec(regions)
    # Replace the known call sites with a mock followed by the normal return address.
    # The rest of the routing function (loops, conditions and epilogue) runs unmodified.
    for page in {(base + stub) & ~4095 for stub in stubs}:
        vm.mem_map(page, 4096)
    for stub in stubs:
        vm.mem_write(base + stub, b"\xc3")

    # Heap cleanup in the early human branch resolves these Win32 imports.
    import_page = (base + 0x3fefd18) & ~4095
    vm.mem_map(import_page, 4096)
    vm.mem_write(base + 0x3fefd18, packed(return_to + 0x100) + packed(return_to + 0x100))
    vm.mem_write(return_to + 0x100, b"\xc3")

    def intercept(uc, address, size, _):
        relative = address - base
        if relative in stubs:
            uc.reg_write(UC_X86_REG_RAX, stubs[relative]())
    vm.hook_add(UC_HOOK_CODE, intercept)
    vm.emu_start(base + code_begin, return_to, count=5000)
    return vm.reg_read(UC_X86_REG_RAX)

checks = [
    ("Simple, AI-only in user's region", {}, 0, 1),
    ("Simple, AI-only in other regions", {"local": False}, 1, 1),
    ("Simple, human in the match", {"human": True}, 0, 0),
    ("Simple, native protected match", {"special": True}, 0, 0),
    ("Simple, native protected competition", {"protected_competition": True}, 0, 0),
    ("Simple, other supported AI-only category", {"variant": 3}, 0, 1),
    ("Moderate, human in the match", {"intensity": 1, "human": True}, 0, 0),
    ("Moderate, AI-only", {"intensity": 1}, 1, 1),
    ("Detailed", {"intensity": 2}, 0, 0),
    ("Existing forced calculation", {"forced": True}, 1, 1),
]
for name, flags, stock, updated in checks:
    observed = evaluate(original, **flags), evaluate(patched, **flags)
    assert observed == (stock, updated), (name, observed, stock, updated)
    print(f"PASS {name}: {stock} -> {updated}")
