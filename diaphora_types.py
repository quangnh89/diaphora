#!/usr/bin/python

"""
Carry the type information of one IDA database over to another.

Diaphora already ports struct/enum/union/typedef definitions and function
prototypes, but it prints each type on its own and parses each one back on
its own (CIDABinDiff.import_definitions(), idc.parse_decls per definition).
Types refer to each other, and one at a time cannot resolve that: on a real
pair of builds 155 of 2181 types failed to parse, and a struct whose member
named one of those was created truncated -- a field the old database calls
`VtlRecord` came out as part of a `_pad_03E0` filler. 378 function
prototypes went down with them, since a prototype naming a type that did
not make it cannot be parsed either.

The fix is to stop doing it one at a time. ida_typeinf.print_decls() writes
the whole type library as one C header, in dependency order and with a
forward declaration for everything up front -- it is documented as "the
reverse of parse_decls()" -- and parsing that back in one call resolves the
mutual references. Measured on the same pair of builds: 2181 of 2181 types,
zero parse errors, every size identical to the source.

(Serializing each tinfo_t and deserializing it in the target does not work,
which is worth writing down. A tinfo_t for a named type is a typeref: its
serialized form is four or five bytes naming an *ordinal* in the source type
library, so installing it anywhere else produces a type with no body.)

Function prototypes still have to go as text, one per function, since they
are attached to addresses rather than to the library. They are printed with
PRTYPE_1LINE so that nothing is lost to the line wrapping that truncates
Diaphora's `prototype` column, and applied after the header, so every type
they name is already in place.

Both halves run inside IDA: the dumping side is driven by
diaphora_dump_analysis.py, the applying side by diaphora_auto_import.py.
Dumping is cheap, nothing here decompiles.
"""

import json

import idc
import idautils

import ida_nalt
import ida_typeinf

FORMAT_VERSION = 2

# What to do with a type the target database already has.
MODE_ALL = "all"          # replace it: the old database is the source of truth
MODE_MISSING = "missing"  # leave it alone, only fill in what is absent


def _log(message):
  print(f"[types] {message}")


class _Sink(ida_typeinf.text_sink_t):
  """Collects what print_decls() writes."""

  def __init__(self):
    super().__init__()
    self.parts = []

  def _print(self, text):
    self.parts.append(text)
    return 0

  def text(self):
    return "".join(self.parts)


def _is_complete(name):
  """
  Whether @name already names a type this database can use as is.

  A forward declaration also occupies the name but resolves to nothing and
  has no size, so it does not count. Same test as
  CIDABinDiff.is_complete_local_type(), repeated here so that this module
  needs nothing from Diaphora.
  """
  tinfo = ida_typeinf.tinfo_t()
  if not tinfo.get_named_type(ida_typeinf.get_idati(), name):
    return False
  size = tinfo.get_size()
  return size not in (None, 0, ida_typeinf.BADSIZE)


def dump_types(out_path):
  """
  Write the whole local type library as one C header, plus one prototype
  per function, to @out_path.

  Returns a (local_types, function_types) tuple of counts.
  """
  til = ida_typeinf.get_idati()
  ordinals = list(range(1, ida_typeinf.get_ordinal_limit(til)))

  header = ""
  printed = 0
  if ordinals:
    sink = _Sink()
    # INCL_DEPS pulls in whatever the listed types need, DEF_FWD puts a
    # forward declaration for everything at the top so that types referring
    # to each other both resolve.
    printed = ida_typeinf.print_decls(
      sink, til, ordinals, ida_typeinf.PDF_INCL_DEPS | ida_typeinf.PDF_DEF_FWD
    )
    header = sink.text()
    if printed < 0:
      # Negated count: it produced output but warns that it may not compile.
      printed = -printed
      _log(f"print_decls reported minor errors over {len(ordinals)} ordinal(s)")

  names = [
    ida_typeinf.get_numbered_type_name(til, ordinal) for ordinal in ordinals
  ]
  names = [name for name in names if name]

  functions = {}
  for ea in idautils.Functions():
    tinfo = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tinfo, ea):
      continue
    # PRTYPE_1LINE: the decompiler's own first line wraps, and a wrapped
    # prototype is what makes Diaphora's `prototype` column unparseable.
    decl = ida_typeinf.print_tinfo(
      None, 0, 0, ida_typeinf.PRTYPE_1LINE | ida_typeinf.PRTYPE_SEMI,
      tinfo, "f", None,
    )
    if decl:
      functions["0x%x" % ea] = decl

  data = {
    "format_version": FORMAT_VERSION,
    "source_idb": idc.get_idb_path(),
    "header": header,
    "local_type_names": names,
    "functions": functions,
  }

  with open(out_path, "w", encoding="utf8") as fh:
    json.dump(data, fh, indent=1, ensure_ascii=True)

  return printed, len(functions)


def _load(in_path):
  with open(in_path, "r", encoding="utf8") as fh:
    data = json.load(fh)

  version = data.get("format_version")
  if version != FORMAT_VERSION:
    raise ValueError(
      f"Unsupported type dump version {version}, expected {FORMAT_VERSION}"
    )
  return data


def apply_local_types(in_path, mode=MODE_ALL):
  """
  Parse the dumped header. Runs before Diaphora's own import, so that its
  definition handling finds everything already in place and skips it, and so
  that the prototypes it applies have the types they name.

  @mode decides what happens to a name the target database already uses:
  MODE_ALL replaces it (the old database is the source of truth),
  MODE_MISSING keeps it and only fills in what is absent -- and because the
  header is parsed as a whole, "missing" means dropping the header entirely
  when the target is already complete, rather than cherry-picking from it.
  """
  data = _load(in_path)
  header = data.get("header") or ""
  names = data.get("local_type_names") or []

  counts = {
    "mode": mode,
    "local_types_dumped": len(names),
    "complete_before": sum(1 for name in names if _is_complete(name)),
    "complete_after": 0,
    "parse_errors": None,
    "status": "ok",
  }

  if not header:
    counts["status"] = "nothing to apply"
    return counts

  if mode == MODE_MISSING and counts["complete_before"] == len(names):
    counts["status"] = "skipped, every type is already complete"
    counts["complete_after"] = counts["complete_before"]
    return counts

  # PT_REPLACE is what makes a name the target already uses give way; without
  # it the existing type wins, which is exactly the "missing" mode.
  flags = ida_typeinf.PT_SIL
  if mode != MODE_MISSING:
    flags |= ida_typeinf.PT_REPLACE

  counts["parse_errors"] = idc.parse_decls(header, flags)
  counts["complete_after"] = sum(1 for name in names if _is_complete(name))
  return counts


def apply_function_types(in_path, pairs):
  """
  Give every matched function the prototype of its counterpart. Runs after
  the header and after Diaphora's own import, so it has the last word and
  every type it names already exists.

  @pairs is the list of (ea_new, ea_old) address pairs of the matched
  functions; the dump is keyed by the old database's addresses.
  """
  data = _load(in_path)
  functions = data.get("functions", {})

  counts = {
    "dumped": len(functions),
    "applied": 0,
    "unparsed": 0,
    "failed": 0,
    "unparsed_examples": [],
    "status": "ok",
  }

  for ea_new, ea_old in pairs:
    decl = functions.get("0x%x" % ea_old)
    if not decl:
      continue

    tinfo = ida_typeinf.tinfo_t()
    if ida_typeinf.parse_decl(tinfo, None, decl, ida_typeinf.PT_SIL) is None:
      counts["unparsed"] += 1
      if len(counts["unparsed_examples"]) < 20:
        counts["unparsed_examples"].append(decl[:160])
      continue

    if ida_typeinf.apply_tinfo(ea_new, tinfo, ida_typeinf.TINFO_DEFINITE):
      counts["applied"] += 1
    else:
      counts["failed"] += 1

  return counts
