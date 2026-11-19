#!/usr/bin/python3

"""
Read the bytes of the binary an exported database was made from.

This exists to answer one question the sqlite files cannot: when two databases
of the *same* binary disagree about a function's bytes, which of the two no
longer matches the file on disk? That happens when bytes get patched in a
database, and it is easy to spend a long time reading a diff of it as if it
were a code change. Measured on a real pair of databases of one hvax64.exe,
seven functions disagreed, and in every case the file agreed with one specific
side.

Deliberately no dependency on pefile: a PE section table is twenty lines of
struct.unpack, and this has to run wherever diaphora_ai_export.py runs.

Addresses come from the exported database's `functions.rva` column, which is
already image relative (it holds `ea - image_base` as an integer), so nothing
here has to guess an image base or care whether the database was rebased.

Naming the *side* that diverges needs a disassembler, because the question is
whether the mnemonic and registers the database reports match the bytes.
capstone is used when it can be imported and the check is skipped with a note
when it cannot -- it is an optional extra, not a requirement.
"""

import struct
from hashlib import md5

try:
  import capstone
  CAPSTONE_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the environment
  capstone = None
  CAPSTONE_AVAILABLE = False


class NotAPortableExecutable(Exception):
  pass


# IDA and capstone spell the same opcode differently, and these are aliases for
# one encoding rather than different instructions: IDA's `retn`, `jnz`, `jnb`
# and `mov rdx, <imm64>` are capstone's `ret`, `jne`, `jae` and `movabs`.
# Without folding them, comparing what a database says against what the file
# holds reports a difference on perfectly ordinary code.
MNEMONIC_ALIASES = {}
for _group in (
  ("ret", "retn"), ("retw", "retnw"),
  ("je", "jz"), ("jne", "jnz"),
  ("jae", "jnb", "jnc"), ("jb", "jnae", "jc"),
  ("jbe", "jna"), ("ja", "jnbe"),
  ("jl", "jnge"), ("jge", "jnl"),
  ("jle", "jng"), ("jg", "jnle"),
  ("jp", "jpe"), ("jnp", "jpo"),
  ("sete", "setz"), ("setne", "setnz"),
  ("setae", "setnb", "setnc"), ("setb", "setnae", "setc"),
  ("setbe", "setna"), ("seta", "setnbe"),
  ("setl", "setnge"), ("setge", "setnl"),
  ("setle", "setng"), ("setg", "setnle"),
  ("cmove", "cmovz"), ("cmovne", "cmovnz"),
  ("cmovae", "cmovnb", "cmovnc"), ("cmovb", "cmovnae", "cmovc"),
  ("cmovbe", "cmovna"), ("cmova", "cmovnbe"),
  ("cmovl", "cmovnge"), ("cmovge", "cmovnl"),
  ("cmovle", "cmovng"), ("cmovg", "cmovnle"),
  ("shl", "sal"), ("fwait", "wait"), ("mov", "movabs"),
  ("int3", "int"),
):
  for _name in _group:
    MNEMONIC_ALIASES[_name] = _group[0]


def canonical_mnemonic(mnemonic):
  mnemonic = (mnemonic or "").lower()
  return MNEMONIC_ALIASES.get(mnemonic, mnemonic)


class Image:
  """
  A PE file, mapped well enough to read the bytes at an RVA.
  """

  def __init__(self, path):
    with open(path, "rb") as handle:
      self.data = handle.read()
    self.path = path
    self.md5 = md5(self.data).hexdigest()
    self.sections = []
    self.bitness = 64
    self._parse()

  def _parse(self):
    data = self.data
    if len(data) < 0x40 or data[:2] != b"MZ":
      raise NotAPortableExecutable("%s does not start with MZ" % self.path)

    pe = struct.unpack_from("<I", data, 0x3c)[0]
    if pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0":
      raise NotAPortableExecutable("%s has no PE header" % self.path)

    section_count = struct.unpack_from("<H", data, pe + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    magic = struct.unpack_from("<H", data, pe + 24)[0]
    self.bitness = 64 if magic == 0x20b else 32

    table = pe + 24 + optional_size
    for index in range(section_count):
      offset = table + index * 40
      if offset + 40 > len(data):
        break
      virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
        "<IIII", data, offset + 8
      )
      self.sections.append((virtual_address, virtual_size, raw_pointer, raw_size))

  def offset_of(self, rva):
    """
    The file offset holding @rva, or None when it is not backed by the file.
    """
    for virtual_address, virtual_size, raw_pointer, raw_size in self.sections:
      span = max(virtual_size, raw_size)
      if virtual_address <= rva < virtual_address + span:
        # Past the raw data of the section is uninitialised, so it is not in
        # the file even though it is inside the section.
        if rva - virtual_address >= raw_size:
          return None
        offset = raw_pointer + (rva - virtual_address)
        return offset if offset < len(self.data) else None
    return None

  def bytes_at(self, rva, size):
    """
    @size bytes at @rva, or None when the range is not fully in the file.
    """
    offset = self.offset_of(rva)
    if offset is None or offset + size > len(self.data):
      return None
    return self.data[offset:offset + size]


def open_image(path, expected_md5=None):
  """
  An Image for @path, or (None, reason).

  @expected_md5 is the `program.md5sum` the database recorded. A binary that
  does not match it is not the one the database was made from, and using it
  would produce confident nonsense, so it is refused.
  """
  try:
    image = Image(path)
  except (OSError, NotAPortableExecutable) as exc:
    return None, str(exc)

  if expected_md5 and image.md5.lower() != str(expected_md5).lower():
    return None, (
      "%s has md5 %s but the database was exported from %s"
      % (path, image.md5, expected_md5)
    )
  return image, None


def describe_at(image, rva, size=16):
  """
  The first instruction at @rva as "mnemonic operands", or None.

  Only the first one: the caller is checking a single instruction that two
  databases disagree about, not disassembling a function.
  """
  if not CAPSTONE_AVAILABLE:
    return None
  raw = image.bytes_at(rva, size)
  if not raw:
    return None

  mode = capstone.CS_MODE_64 if image.bitness == 64 else capstone.CS_MODE_32
  engine = capstone.Cs(capstone.CS_ARCH_X86, mode)
  for instruction in engine.disasm(raw, rva, count=1):
    text = instruction.mnemonic
    if instruction.op_str:
      text += " " + instruction.op_str
    return text
  return None
