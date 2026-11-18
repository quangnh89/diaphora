#!/usr/bin/python

"""
Port the stack frame member names and types from one IDA database to another.

This is a different thing from diaphora_lvars.py, and the distinction is easy
to miss. Hex-Rays local variables live in a netnode and show up in the
pseudo-code. Stack frame members live in the function's frame type and show up
in the *disassembly*:

    old:  mov     [rsp+58h+flag], 0          new:  mov  [rsp+58h+var_40], 0
    old:  mov     word ptr [rsp+58h+a2+4], cx      new:  mov  [rsp+58h+var_24], cx

Nothing in Diaphora carries these over, and nothing in diaphora_lvars.py does
either, so until this module ran the new database showed `var_NN` everywhere
the old one had a name. On hvax64 9711 -> 9836 that accounted for 692 of the
1157 matched functions whose disassembly differed -- the single largest
contributor by a wide margin.

Note that this does not exist to make the diff smaller. diaphora_ai_export.py
masks frame member names on both sides before comparing, so the diff is
already right without it. What it buys is a readable new database, which is
the point of porting analysis in the first place.

Both halves run inside IDA: the dumping side is driven by
diaphora_dump_analysis.py, the applying side by diaphora_auto_import.py.
Dumping is cheap -- the frame is a type, so reading it decompiles nothing.

Members are matched by their offset in the frame, which is fixed by the code
the compiler emitted and is therefore the same in both builds as long as the
function's body is. To be sure of that, the whole function is skipped unless
its frame size matches as well; a frame that grew or shrank means the layout
moved and every offset in it would be a guess. Auto-generated names (`var_38`,
`arg_8`, the saved-register and return-address slots) are not dumped at all:
there is nothing in them to port.

Types are transferred as C text and parsed in the target database, never
through tinfo_t.serialize(). A serialised named type is a *typeref* holding an
ordinal, and ordinals do not mean the same thing in two databases: going that
route silently retyped variables to whatever happened to sit at that ordinal.
diaphora_types.py has the same note and the same reason.

Writing goes through tinfo_t.rename_udm()/set_udm_type() on the frame type
itself, which does persist -- verified by renaming a member, saving, and
reading it back in a separate IDA session.

ida_frame.define_stkvar() looks like the obvious API for this and is a trap.
Its `off` argument is not the member offset the frame's udt reports: called
with the udt offset of an existing slot it does not touch that slot at all,
it appends a brand new member elsewhere in the frame. Measured on a test
database: define_stkvar(pfn, "x", 88, tif) returned success, left `var_30` at
offset 88 untouched, and created `x` at offset 224. So it silently corrupts
the frame layout. Do not use it here.

Both calls return a tinfo_code_t, where TERR_OK is 0 -- a falsy success, so
the result has to be compared and never tested for truth.
"""

import json

import idc
import idautils

import ida_frame
import ida_funcs
import ida_typeinf

FORMAT_VERSION = 1

# Frame slots IDA names itself. Nothing to port, and the saved-register and
# return-address slots must never be touched.
_AUTO_PREFIXES = ("var_", "arg_", "anonymous")
_AUTO_NAMES = (" s", " r", "__saved_registers", "__return_address")


def _log(message):
  print(f"[frames] {message}")


def _is_auto_name(name):
  if not name or name in _AUTO_NAMES or name.strip() == "":
    return True
  if name.startswith(_AUTO_PREFIXES):
    return True
  try:
    if ida_frame.is_anonymous_member_name(name):
      return True
  except Exception:  # noqa: BLE001
    pass
  return False


def _type_decl(tinfo):
  """
  The member's type as a declaration of a variable called `x`, which is what
  IDA's parser will take back.

  Not tinfo_t.dstr(): that prints an abstract declarator, and for anything
  whose declarator is not a plain prefix it does not round-trip. An array
  member comes out as "unsigned __int16[4]", and "unsigned __int16[4] x;" is
  not C -- the brackets belong after the name. print_tinfo places the name
  properly, so arrays and function pointers survive.
  """
  try:
    if tinfo is None or tinfo.empty():
      return ""
    return ida_typeinf.print_tinfo(
      None, 0, 0, ida_typeinf.PRTYPE_1LINE | ida_typeinf.PRTYPE_SEMI,
      tinfo, "x", None,
    ) or ""
  except Exception:  # noqa: BLE001
    return ""


def _type_text(tinfo):
  """
  The same type as IDA displays it. Kept only so the dump reads sensibly when
  someone opens it; never parsed back.
  """
  try:
    if tinfo is None or tinfo.empty():
      return ""
    return tinfo.dstr() or ""
  except Exception:  # noqa: BLE001
    return ""


def _frame_members(pfn):
  """
  (tinfo, udt_details) of a function's frame, or (None, None).
  """
  tif = ida_typeinf.tinfo_t()
  if not ida_frame.get_func_frame(tif, pfn):
    return None, None

  udt = ida_typeinf.udt_type_data_t()
  if not tif.get_udt_details(udt):
    return None, None
  return tif, udt


def dump_frames(out_path):
  """
  Write every named stack frame member of the currently open database to
  @out_path.

  Returns a (functions, members) tuple of counts.
  """
  functions = {}
  members = 0

  for ea in idautils.Functions():
    pfn = ida_funcs.get_func(ea)
    if pfn is None:
      continue

    tif, udt = _frame_members(pfn)
    if udt is None:
      continue

    entries = []
    for index in range(udt.size()):
      udm = udt[index]
      if _is_auto_name(udm.name):
        continue

      offset = udm.offset // 8
      try:
        fpoff = ida_frame.soff_to_fpoff(pfn, offset)
      except Exception:  # noqa: BLE001
        fpoff = None

      entries.append(
        {
          "name": udm.name,
          "offset": offset,
          "fpoff": fpoff,
          "size": udm.size // 8,
          "decl": _type_decl(udm.type),
          "type_name": _type_text(udm.type),
          "cmt": getattr(udm, "cmt", "") or "",
        }
      )

    if entries:
      functions["0x%x" % ea] = {
        "frame_size": ida_frame.get_frame_size(pfn),
        "frregs": pfn.frregs,
        "fpd": pfn.fpd,
        "members": entries,
      }
      members += len(entries)

  data = {
    "format_version": FORMAT_VERSION,
    "source_idb": idc.get_idb_path(),
    "functions": functions,
  }

  with open(out_path, "w", encoding="utf8") as fh:
    json.dump(data, fh, indent=1, ensure_ascii=True)

  return len(functions), members


def _parse_type(entry):
  """
  A tinfo_t for the member's saved type, or None.
  """
  decl = entry.get("decl")
  if not decl:
    # Dumps written before `decl` existed only carry the displayed form.
    text = entry.get("type_name")
    decl = f"{text} x;" if text else ""
  if not decl:
    return None

  tif = ida_typeinf.tinfo_t()
  if ida_typeinf.parse_decl(tif, None, decl, ida_typeinf.PT_SIL) is None:
    return None
  return tif if not tif.empty() else None


def _free_name(base, taken):
  """
  A name near @base that no member of this frame holds yet.
  """
  for suffix in range(1, 1000):
    candidate = f"{base}_{suffix}"
    if candidate not in taken:
      return candidate
  return None


def _apply_one(tif, udt, index, entry, taken, counts):
  """
  Rename and retype one frame member. Returns True when anything changed.
  """
  touched = False
  name = entry["name"]
  current = udt[index].name

  if name and current != name:
    holder = taken.get(name)
    if holder is not None and holder != index:
      # Another slot already has this name. Frame member names have to be
      # unique, so move it aside when IDA made it up, and leave it alone when
      # it came from the old database.
      if _is_auto_name(udt[holder].name):
        spare = _free_name(udt[holder].name, taken)
        # rename_udm returns a tinfo_code_t, and TERR_OK is 0 -- so this has
        # to be compared, not tested for truth.
        if spare is not None and tif.rename_udm(holder, spare) == ida_typeinf.TERR_OK:
          taken.pop(udt[holder].name, None)
          taken[spare] = holder
          counts["names_unblocked"] += 1
        else:
          counts["collision"] += 1
          return touched
      else:
        counts["collision"] += 1
        return touched

    if tif.rename_udm(index, name) == ida_typeinf.TERR_OK:
      taken.pop(current, None)
      taken[name] = index
      counts["names_applied"] += 1
      touched = True
    else:
      counts["names_failed"] += 1
      if len(counts["failed_examples"]) < 20:
        counts["failed_examples"].append(name)

  if entry.get("decl") or entry.get("type_name"):
    parsed = _parse_type(entry)
    if parsed is None:
      counts["types_unparsed"] += 1
      if len(counts["unparsed_examples"]) < 20:
        counts["unparsed_examples"].append(entry.get("decl") or entry["type_name"])
    elif tif.set_udm_type(index, parsed) == ida_typeinf.TERR_OK:
      counts["types_applied"] += 1
      touched = True
    else:
      counts["types_failed"] += 1

  return touched


def apply_frames(in_path, pairs):
  """
  Re-create in the currently open database the stack frame members stored in
  @in_path by dump_frames().

  @pairs is the list of (ea_new, ea_old) address pairs of the matched
  functions: the dump is keyed by the old database's addresses.

  Returns a dict of counts. Nothing in here raises for a single function.
  """
  with open(in_path, "r", encoding="utf8") as fh:
    data = json.load(fh)

  version = data.get("format_version")
  if version != FORMAT_VERSION:
    raise ValueError(
      f"Unsupported frame dump version {version}, expected {FORMAT_VERSION}"
    )

  saved = data.get("functions", {})
  counts = {
    "functions_with_data": 0,
    "functions_touched": 0,
    "no_frame": 0,
    "skipped_layout": 0,
    "members_missing": 0,
    "names_applied": 0,
    "names_unblocked": 0,
    "names_failed": 0,
    "collision": 0,
    "types_applied": 0,
    "types_failed": 0,
    "types_unparsed": 0,
    "failed_examples": [],
    "unparsed_examples": [],
  }

  for ea_new, ea_old in pairs:
    record = saved.get("0x%x" % ea_old)
    if not record:
      continue

    counts["functions_with_data"] += 1

    pfn = ida_funcs.get_func(ea_new)
    if pfn is None:
      counts["no_frame"] += 1
      continue

    tif, udt = _frame_members(pfn)
    if udt is None:
      counts["no_frame"] += 1
      continue

    # A frame of a different size means the layout moved, and then every
    # offset in the dump is a guess. Skip the whole function rather than put
    # the old names on the wrong slots.
    if ida_frame.get_frame_size(pfn) != record.get("frame_size"):
      counts["skipped_layout"] += 1
      continue

    by_offset = {}
    taken = {}
    for index in range(udt.size()):
      by_offset[udt[index].offset // 8] = index
      if udt[index].name:
        taken[udt[index].name] = index

    touched = False
    for entry in record["members"]:
      index = by_offset.get(entry["offset"])
      if index is None:
        counts["members_missing"] += 1
        continue
      try:
        if _apply_one(tif, udt, index, entry, taken, counts):
          touched = True
      except Exception as exc:  # noqa: BLE001
        counts["names_failed"] += 1
        _log(f"0x{ea_new:x} +{entry['offset']:#x}: {exc}")

    if touched:
      counts["functions_touched"] += 1

  return counts
