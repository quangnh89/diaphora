#!/usr/bin/python

"""
Port Hex-Rays local variable names and types from one IDA database to
another.

This is the one piece of a reverse engineer's work Diaphora does not carry
over at all. It ports function names, comments, prototypes, struct/enum
definitions and global variables, but nothing reads or writes the Hex-Rays
user lvar settings, so a ported function still decompiles to

    unsigned __int16 v4;                 instead of   unsigned __int16 status;
    HV_VP_ADDRESS_SPACE_PAGE *v6;                     ... *statePage;

and the pseudo-code diff of an unchanged function is then full of renaming
noise. Function arguments are lvars too (lvar_t.is_arg_var), so this is
also what turns `__int64 a1` back into the argument name the old database
had.

Both halves run inside IDA. The dumping side is driven by
diaphora_dump_analysis.py, the applying side by diaphora_auto_import.py.

Only what the user explicitly set is ported: the dump reads
restore_user_lvar_settings(), which returns the saved settings rather than
whatever Hex-Rays made up this time. That also makes it cheap -- it is a
netnode read, no decompilation.

Applying needs the new function's own lvars, so it decompiles, but only the
functions that actually have something to port.

A saved lvar is identified by a lvar_locator_t, which holds a location
(register or stack offset) plus `defea`, the address of the instruction that
defines it. `defea` is absolute and therefore different in every build, so
the settings cannot be copied across as-is: each one has to be matched to a
variable of the new function.

Location alone is not enough to do that. A stack slot is unique within a
function, but a register is not: several variables live in the same register
over the course of a function and only `defea` tells them apart. Matching on
the register alone left 12278 of 22285 variables unmatched on a real
database, every one of them a register with two or three candidates. So the
first key is the location plus `defea` measured from the start of the
function, which is identical in both builds as long as the function's body
is, and matching on the location alone is only the fallback for what that
misses. Where neither gives a single answer the variable is skipped and
counted, never guessed at.
"""

import json

import idc
import idautils

import ida_hexrays
import ida_name
import ida_typeinf

FORMAT_VERSION = 5


def _log(message):
  print(f"[lvars] {message}")


def _loc_key(locator):
  """
  A portable description of where a variable lives, or None when it cannot
  be matched across databases.
  """
  if locator.is_stk_var():
    return "stk:%d" % locator.get_stkoff()
  if locator.is_reg1():
    return "reg:%d" % locator.get_reg1()
  if locator.is_reg2():
    return "reg2:%d:%d" % (locator.get_reg1(), locator.get_reg2())
  # Scattered variables have no single location to match on.
  return None


def _type_string(tinfo):
  try:
    if tinfo is not None and not tinfo.empty():
      return tinfo.dstr() or ""
  except Exception: # noqa: BLE001
    pass
  return ""


def _type_decl(tinfo):
  """
  The type as a declaration of a variable called `x`, which is what IDA's
  parser takes back.

  dstr() prints an abstract declarator, and that only round-trips when the
  declarator is a plain prefix. An array variable comes out as
  "unsigned __int16[4]", and "unsigned __int16[4] x;" is not C: the brackets
  belong after the name, so every array and function-pointer local used to
  land in `types_unparsed`. print_tinfo puts the name in the right place.
  """
  try:
    if tinfo is None or tinfo.empty():
      return ""
    return ida_typeinf.print_tinfo(
      None, 0, 0, ida_typeinf.PRTYPE_1LINE | ida_typeinf.PRTYPE_SEMI,
      tinfo, "x", None,
    ) or ""
  except Exception: # noqa: BLE001
    return ""


def _locator_of(lvar):
  """
  A standalone copy of where a variable lives, still valid once the cfunc_t
  it came from is gone.
  """
  locator = ida_hexrays.lvar_locator_t()
  locator.location = lvar.location
  locator.defea = lvar.defea
  return locator


def dump_lvars(out_path):
  """
  Write every user defined local variable of the currently open database to
  @out_path.

  Returns a (functions, variables) tuple of counts.
  """
  functions = {}
  variables = 0
  unportable = 0

  for ea in idautils.Functions():
    lvinf = ida_hexrays.lvar_uservec_t()
    if not ida_hexrays.restore_user_lvar_settings(lvinf, ea):
      continue

    entries = []
    for info in lvinf.lvvec:
      key = _loc_key(info.ll)
      if key is None:
        unportable += 1
        continue

      entry = {
        "loc": key,
        "defea_off": info.ll.defea - ea,
        "name": info.name or "",
        "decl": _type_decl(info.type),
        "type_name": _type_string(info.type),
        "cmt": info.cmt or "",
      }
      if not entry["name"] and not entry["type_name"] and not entry["cmt"]:
        continue
      entries.append(entry)

    if entries:
      functions["0x%x" % ea] = entries
      variables += len(entries)

  data = {
    "format_version": FORMAT_VERSION,
    "source_idb": idc.get_idb_path(),
    "functions": functions,
  }

  with open(out_path, "w", encoding="utf8") as fh:
    json.dump(data, fh, indent=1, ensure_ascii=True)

  if unportable:
    _log(f"{unportable} scattered variable(s) cannot be ported, skipped")

  return len(functions), variables


def _plan_for(ea_new, entries, counts):
  """
  Decide what to do with one function, while its decompilation is still
  valid. Returns a list of (current_name, locator, entry).

  The plan is built before anything is applied because renaming a variable
  invalidates the cfunc_t the lvars belong to.
  """
  cfunc = ida_hexrays.decompile(ea_new)
  if cfunc is None:
    counts["decompile_failed"] += 1
    return [], {}

  by_precise = {}
  by_loc = {}
  # Every name in use in this function, and whether its owner got it from
  # the user or from Hex-Rays. Needed to resolve a name collision later.
  occupied = {}
  for lvar in cfunc.get_lvars():
    if lvar.name:
      # has_user_name is a property, not a method: IDAPython wraps it at the
      # bottom of ida_hexrays.py (`lvar_t.has_user_name = property(...)`), so
      # calling it gets you "'bool' object is not callable".
      occupied[lvar.name] = (lvar.has_user_name, _locator_of(lvar))
    key = _loc_key(lvar)
    if key is None:
      continue
    by_loc.setdefault(key, []).append(lvar)
    by_precise.setdefault((key, lvar.defea - ea_new), []).append(lvar)

  # Two passes, so that an entry that can be placed exactly never loses its
  # variable to a vaguer one. `claimed` is keyed by the pair that identifies
  # a variable uniquely within the function.
  claimed = set()
  matched = {}

  for index, entry in enumerate(entries):
    candidates = by_precise.get((entry["loc"], entry.get("defea_off")), [])
    if len(candidates) == 1:
      lvar = candidates[0]
      matched[index] = lvar
      claimed.add((entry["loc"], lvar.defea - ea_new))
      counts["matched_exactly"] += 1

  for index, entry in enumerate(entries):
    if index in matched:
      continue
    candidates = [
      lvar for lvar in by_loc.get(entry["loc"], [])
      if (entry["loc"], lvar.defea - ea_new) not in claimed
    ]
    if len(candidates) == 1:
      lvar = candidates[0]
      matched[index] = lvar
      claimed.add((entry["loc"], lvar.defea - ea_new))
      counts["matched_by_location"] += 1

  plan = []
  for index, entry in enumerate(entries):
    lvar = matched.get(index)
    if lvar is None:
      # The variable is gone, or several share its location and none of them
      # is where it used to be defined: this part of the function really is
      # different, so leave it alone.
      counts["vars_skipped"] += 1
      if len(counts["skipped_examples"]) < 20:
        counts["skipped_examples"].append(
          {
            "ea": "0x%x" % ea_new,
            "loc": entry["loc"],
            "name": entry["name"],
            "at_location": len(by_loc.get(entry["loc"], [])),
          }
        )
      continue

    plan.append({"current": lvar.name, "locator": _locator_of(lvar), "entry": entry})

  return plan, occupied


def _apply_type(ea_new, locator, entry, counts):
  """
  Deliberately by name, not by IDA's serialized form.

  Serializing the type and deserializing it here looks exact and is not: a
  tinfo_t for a named type is a typeref holding an *ordinal* in the source
  type library, and the same ordinal means something else here. Tried on a
  real pair of builds it silently retyped `HV_LP_ROOT *lpRootState` as
  `_HV_DEVICE_OBJECT *`, which is worse than failing. The name resolves
  correctly because diaphora_types.py has already brought the whole type
  library across.
  """
  decl = entry.get("decl")
  if not decl:
    # Dumps written before `decl` existed only carry the displayed form.
    text = entry.get("type_name")
    decl = f"{text} x;" if text else ""
  if not decl:
    return

  tinfo = ida_typeinf.tinfo_t()
  if ida_typeinf.parse_decl(tinfo, None, decl, ida_typeinf.PT_SIL) is None:
    counts["types_unparsed"] += 1
    if len(counts["unparsed_examples"]) < 20:
      counts["unparsed_examples"].append({"ea": "0x%x" % ea_new, "type": decl[:120]})
    return

  info = ida_hexrays.lvar_saved_info_t()
  info.ll = locator
  info.type = tinfo
  if ida_hexrays.modify_user_lvar_info(ea_new, ida_hexrays.MLI_TYPE, info):
    counts["types_applied"] += 1
  else:
    counts["types_failed"] += 1


def _free_name(base, occupied):
  for suffix in ["_"] + ["_%d" % i for i in range(1, 100)]:
    candidate = base + suffix
    if candidate not in occupied:
      return candidate
  return None


def _note(counts, key, detail):
  counts[key] += 1
  examples = counts["failures"].setdefault(key, [])
  if len(examples) < 20:
    examples.append(detail)


def _set_name(ea_new, locator, name):
  """
  Name a variable by where it lives, not by what it is called now.

  rename_lvar() takes the current name, and that is not stable: Hex-Rays
  numbers the variables it names itself on every decompilation, so renaming
  one renumbers the remaining `vN` and every name captured beforehand goes
  stale. Addressing the variable by its locator is immune to that, and the
  API documents it as the way to rename in bulk.
  """
  info = ida_hexrays.lvar_saved_info_t()
  info.ll = locator
  info.name = name
  return ida_hexrays.modify_user_lvar_info(ea_new, ida_hexrays.MLI_NAME, info)


def _rename(ea_new, item, occupied, counts):
  """
  Give one variable the name it has in the old database.

  A name already taken by another variable of this function is one reason
  this fails. When the variable in the way only carries a name Hex-Rays made
  up (`v12`, `a3`), it is moved aside so the real name can land; a name the
  user chose is never touched.
  """
  wanted = item["entry"]["name"]
  if not wanted or wanted == item["current"]:
    return False

  holder = occupied.get(wanted)
  if holder is not None:
    holder_user_named, holder_locator = holder
    if holder_user_named:
      _note(
        counts,
        "collision_user_named",
        {"ea": "0x%x" % ea_new, "name": wanted, "from": item["current"]},
      )
      return False

    spare = _free_name(wanted, occupied)
    if spare is None or not _set_name(ea_new, holder_locator, spare):
      _note(counts, "other", {"ea": "0x%x" % ea_new, "name": wanted, "why": "unblock"})
      return False
    occupied.pop(wanted, None)
    occupied[spare] = (False, holder_locator)
    counts["names_unblocked"] += 1

  if not _set_name(ea_new, item["locator"], wanted):
    # is_ident() is only consulted here, as an explanation. Using it as a
    # gate rejected 45 perfectly good lvar names -- `rip`, `Rbx`, `ch` --
    # because IDA reserves register names for *addresses*, not for locals.
    key = "invalid_name" if not ida_name.is_ident(wanted) else "other"
    _note(counts, key, {"ea": "0x%x" % ea_new, "name": wanted, "from": item["current"]})
    return False

  occupied.pop(item["current"], None)
  occupied[wanted] = (True, item["locator"])
  item["current"] = wanted
  counts["names_applied"] += 1
  return True


def _apply_comment(ea_new, locator, comment, counts):
  info = ida_hexrays.lvar_saved_info_t()
  info.ll = locator
  info.cmt = comment
  if ida_hexrays.modify_user_lvar_info(ea_new, ida_hexrays.MLI_CMT, info):
    counts["comments_applied"] += 1


def apply_lvars(in_path, pairs):
  """
  Re-create in the currently open database the local variables stored in
  @in_path by dump_lvars().

  @pairs is the list of (ea_new, ea_old) address pairs of the matched
  functions: the dump is keyed by the old database's addresses, which say
  nothing about where the same function lives now.

  Returns a dict of counts. Nothing in here raises for a single function:
  porting variables is best effort by nature.
  """
  with open(in_path, "r", encoding="utf8") as fh:
    data = json.load(fh)

  version = data.get("format_version")
  if version != FORMAT_VERSION:
    raise ValueError(
      f"Unsupported lvar dump version {version}, expected {FORMAT_VERSION}"
    )

  saved = data.get("functions", {})
  counts = {
    "functions_with_data": 0,
    "functions_touched": 0,
    "decompile_failed": 0,
    "matched_exactly": 0,
    "matched_by_location": 0,
    "names_applied": 0,
    "names_unblocked": 0,
    "collision_user_named": 0,
    "invalid_name": 0,
    "other": 0,
    "types_applied": 0,
    "types_failed": 0,
    "types_unparsed": 0,
    "unparsed_examples": [],
    "comments_applied": 0,
    "vars_skipped": 0,
    "skipped_examples": [],
    "failures": {},
  }

  for ea_new, ea_old in pairs:
    entries = saved.get("0x%x" % ea_old)
    if not entries:
      continue

    counts["functions_with_data"] += 1
    try:
      plan, occupied = _plan_for(ea_new, entries, counts)
    except Exception as exc: # noqa: BLE001
      counts["decompile_failed"] += 1
      _log(f"0x{ea_new:x}: {exc}")
      continue

    if not plan:
      continue

    touched = False
    for item in plan:
      entry = item["entry"]
      if _rename(ea_new, item, occupied, counts):
        touched = True

      if entry.get("type_name"):
        before = counts["types_applied"]
        _apply_type(ea_new, item["locator"], entry, counts)
        if counts["types_applied"] != before:
          touched = True

      if entry["cmt"]:
        _apply_comment(ea_new, item["locator"], entry["cmt"], counts)

    if touched:
      counts["functions_touched"] += 1

  counts["names_failed"] = (
    counts["collision_user_named"] + counts["invalid_name"] + counts["other"]
  )
  return counts
