"""Check the 0.7.4 CALL sites and emulate the exact Turbo draft assembly."""
import hashlib
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

import pefile
from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_64, Uc
from unicorn.x86_const import (
    UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RBP, UC_X86_REG_RBX,
    UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RSP,
)

if len(sys.argv) != 2:
    raise SystemExit("Usage: python check_draft_relay.py <TeamfightManager2.exe>")

exe = Path(sys.argv[1]).read_bytes()
assert hashlib.sha256(exe).hexdigest() == "c74955e11f4845f93dcb73f90c5cdd442615ac72f40ed642a1fdeb5f41def01e"
game_pe = pefile.PE(data=exe, fast_load=True)
game_base = game_pe.OPTIONAL_HEADER.ImageBase
call_sites = {
    0x2f51968: (bytes.fromhex("e846fbff00"), 0x3f514b3, 0x9ee0),
    0x2f55cff: (bytes.fromhex("e8bce17cff"), 0x2723ec0, 1),
    0x2f5b8c2: (bytes.fromhex("e8f9857cff"), 0x2723ec0, 0x11223302),
}
for site, (expected, callee, _) in call_sites.items():
    actual = game_pe.get_data(site, 5)
    assert actual == expected
    assert site + 5 + struct.unpack("<i", actual[1:])[0] == callee

stub_base = 0x180000000
globals_base = stub_base + 0x1000
relay_base = game_base + 0x5a40000
assembly = Path(__file__).resolve().parent.parent / "src" / "draft.s"
with tempfile.TemporaryDirectory() as tmp_name:
    tmp = Path(tmp_name)
    source = tmp / "draft.s"
    source.write_text(".intel_syntax noprefix\n" + assembly.read_text() + """
.data
.p2align 3
TFM2_TURBO_ORIGINAL_COPY: .quad 0
TFM2_TURBO_ORIGINAL_DISPATCH: .quad 0
TFM2_TURBO_DRAFT_JOBS: .quad 0
""")
    subprocess.run(["as", "--64", str(source), "-o", str(tmp / "draft.o")], check=True)
    subprocess.run([
        "ld", "-e", "tfm2_faster_days_draft", f"-Ttext={stub_base:#x}",
        f"-Tdata={globals_base:#x}", str(tmp / "draft.o"), "-o", str(tmp / "draft"),
    ], check=True)
    subprocess.run(["objcopy", "-O", "binary", "-j", ".text", str(tmp / "draft"), str(tmp / "code")], check=True)
    stub_bytes = (tmp / "code").read_bytes()


def qword(value):
    return struct.pack("<Q", value)


def evaluate(site_rva, *, human_team=77, human_count=1, team_a=44, team_b=45,
             intensity=0, tagged_job=5, existing_flag=0, mode_a=0, mode_b=0,
             bucket=2, bucket_mask=7, valid_database=True, valid_context=True,
             valid_table=True):
    site = game_base + site_rva
    expected_callee = game_base + call_sites[site_rva][1]
    r8 = call_sites[site_rva][2]
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    pages = {(site & ~0xfff), (expected_callee & ~0xfff), relay_base, stub_base, globals_base}
    for page in pages:
        vm.mem_map(page, 4096)
    vm.mem_write(stub_base, stub_bytes)
    vm.mem_write(relay_base, bytes.fromhex("ff2500000000") + qword(stub_base))
    vm.mem_write(site, b"\xe8" + struct.pack("<i", relay_base - site - 5))
    vm.mem_write(expected_callee, b"\xc3")
    vm.mem_write(globals_base, qword(game_base + 0x3f514b3) + qword(game_base + 0x2723ec0))

    scratch = 0x01000000
    vm.mem_map(scratch, 0x40000)
    job = scratch + 0x1000
    db = scratch + 0x2000
    server = scratch + 0x3000
    controls = scratch + 0x6000
    frame = scratch + 0x10000
    stack = scratch + 0x32000
    vm.mem_write(frame + 0x20608, qword(db if valid_database else 0))
    vm.mem_write(frame + 0x205f0, qword(server if valid_context else 0))
    vm.mem_write(db + 0x736, bytes([intensity]))
    vm.mem_write(server + 0xba8, qword(human_count))
    vm.mem_write(server + 0xb98, qword(bucket_mask))
    vm.mem_write(server + 0xb90, qword(controls if valid_table else 0))
    vm.mem_write(server + 0x13d0, bytes([mode_a]))
    vm.mem_write(server + 0x13d4, bytes([mode_b]))
    vm.mem_write(controls, b"\xff" * 4096)
    if bucket is not None:
        vm.mem_write(controls + bucket, b"\x40")
        vm.mem_write(controls - bucket * 16 - 8, qword(human_team))

    vm.mem_write(job, qword(tagged_job))
    vm.mem_write(job + 0x1a8, qword(team_a) + qword(team_b) + bytes([existing_flag]))
    expected_regs = {
        UC_X86_REG_RBP: frame, UC_X86_REG_RBX: 0x1350, UC_X86_REG_RCX: 0x2340,
        UC_X86_REG_RDX: job, UC_X86_REG_R8: r8, UC_X86_REG_R9: 0x3210,
    }
    for register, value in expected_regs.items():
        vm.reg_write(register, value)
    vm.reg_write(UC_X86_REG_RSP, stack)
    seen = []

    def trace(uc, address, size, _):
        if address == expected_callee:
            seen.append(address)
            assert uc.reg_read(UC_X86_REG_RSP) == stack - 8
            assert bytes(uc.mem_read(stack - 8, 8)) == qword(site + 5)

    vm.hook_add(UC_HOOK_CODE, trace)
    vm.emu_start(site, site + 5, count=25000)
    assert seen == [expected_callee]
    assert vm.reg_read(UC_X86_REG_RSP) == stack
    for register, value in expected_regs.items():
        assert vm.reg_read(register) == value
    return vm.mem_read(job + 0x1b8, 1)[0], int.from_bytes(vm.mem_read(globals_base + 16, 8), "little")


cases = [
    ("Simple with two AI teams", {}, (1, 1)),
    ("first bucket", {"bucket": 0}, (1, 1)),
    ("last bucket", {"bucket": 7}, (1, 1)),
    ("first human team", {"team_a": 77}, (0, 0)),
    ("second human team", {"team_b": 77}, (0, 0)),
    ("Moderate", {"intensity": 1}, (0, 0)),
    ("Detailed", {"intensity": 2}, (0, 0)),
    ("special mode A", {"mode_a": 1}, (0, 0)),
    ("special mode B", {"mode_b": 1}, (0, 0)),
    ("no human", {"human_count": 0}, (0, 0)),
    ("multiple humans", {"human_count": 2}, (0, 0)),
    ("unknown human team", {"human_team": 0}, (0, 0)),
    ("unassigned opponent", {"team_b": 0xffffffffffffffff}, (0, 0)),
    ("same team", {"team_b": 44}, (0, 0)),
    ("native fast flag", {"existing_flag": 1}, (1, 0)),
    ("other worker job", {"tagged_job": 8}, (0, 0)),
    ("empty table", {"bucket": None}, (0, 0)),
    ("unavailable database", {"valid_database": False}, (0, 0)),
    ("unavailable server", {"valid_context": False}, (0, 0)),
    ("unavailable map", {"valid_table": False}, (0, 0)),
    ("oversized map", {"bucket_mask": 65535}, (0, 0)),
]
for call_site in call_sites:
    for description, arguments, expected in cases:
        actual = evaluate(call_site, **arguments)
        assert actual == expected, (hex(call_site), description, actual, expected)
    print(f"PASS all {len(cases)} cases through the call relay at RVA {call_site:#x}")
