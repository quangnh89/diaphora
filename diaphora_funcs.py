#!/usr/bin/python

"""
Create in the new database the functions that only exist in the old one.

Diaphora can only port what it matched, and it can only match functions that
exist on both sides. A function the analyst created by hand -- or that IDA
found in the old database and not in the new one -- is therefore invisible to
the whole pipeline: it is not matched, so its name, prototype, types, local
variables, stack frame and folder never move across.

This is not a rare corner. Diffing two databases of *one* hvax64.exe, 227 of
the old database's 4665 functions had no counterpart, every one of them named,
and 218 of those had no function in the new database at all. They are the
hypercall handlers, reached only through a dispatch table, so auto-analysis
has nothing to follow and never creates them. The same gap is why the ported
database in a two-build run always ends up with fewer functions than the one
it was ported from.

So this runs *before* the new database is exported: create the functions
first, and everything downstream -- the diff, the import, the AI export --
treats them like any other.

Addresses that fall inside a function the new database already has are left
alone. Splitting a function is a different and much riskier operation than
creating one, and the two databases disagreeing about where a function starts
is a judgement call rather than an omission. Those are counted and reported
instead.

Unlike the other dump scripts this one *writes* to the database, so whatever
drives it has to save, and the caller must have made a backup first.
"""

import json

import idc
import idautils

import ida_funcs

FORMAT_VERSION = 1


def _log(message):
  print(f"[funcs] {message}")


def dump_funcs(out_path):
  """
  Write every function of the currently open database to @out_path.

  Returns a (functions, named) tuple of counts.
  """
  functions = {}
  named = 0

  for ea in idautils.Functions():
    func = ida_funcs.get_func(ea)
    if func is None:
      continue

    name = idc.get_func_name(ea) or ""
    auto = name.startswith("sub_") or name.startswith("nullsub_") or not name
    if not auto:
      named += 1

    functions["0x%x" % ea] = {
      "end": func.end_ea,
      "name": name,
      "flags": func.flags,
      "auto_name": auto,
    }

  data = {
    "format_version": FORMAT_VERSION,
    "source_idb": idc.get_idb_path(),
    "functions": functions,
  }

  with open(out_path, "w", encoding="utf8") as fh:
    json.dump(data, fh, indent=1, ensure_ascii=True)

  return len(functions), named


def apply_funcs(in_path):
  """
  Create the functions from @in_path that the currently open database lacks.

  Returns a dict of counts. Never raises for a single address.
  """
  with open(in_path, "r", encoding="utf8") as fh:
    data = json.load(fh)

  version = data.get("format_version")
  if version != FORMAT_VERSION:
    raise ValueError(
      f"Unsupported function dump version {version}, expected {FORMAT_VERSION}"
    )

  saved = data.get("functions", {})
  counts = {
    "in_dump": len(saved),
    "already_present": 0,
    "created": 0,
    "created_with_end": 0,
    "inside_other": 0,
    "overlaps_other": 0,
    "failed": 0,
    "inside_examples": [],
    "overlap_examples": [],
    "failed_examples": [],
  }

  for key, record in sorted(saved.items(), key=lambda item: int(item[0], 16)):
    ea = int(key, 16)
    existing = ida_funcs.get_func(ea)

    if existing is not None:
      if existing.start_ea == ea:
        counts["already_present"] += 1
      else:
        # The address is in the middle of a function this database already
        # has. Creating here would mean splitting it.
        counts["inside_other"] += 1
        if len(counts["inside_examples"]) < 20:
          counts["inside_examples"].append(
            {
              "ea": key,
              "name": record.get("name", ""),
              "inside": "0x%x" % existing.start_ea,
            }
          )
      continue

    end = record.get("end")

    # The two databases can also disagree about where a function *starts*:
    # the old one has it at ...cf90 and the new one has its own function three
    # bytes in, at ...cf93. Creating here would mean moving a function the new
    # database already has, which is the same judgement call as splitting one,
    # so it is reported rather than forced.
    following = ida_funcs.get_next_func(ea)
    if following is not None and end and following.start_ea < end:
      counts["overlaps_other"] += 1
      if len(counts["overlap_examples"]) < 20:
        counts["overlap_examples"].append(
          {
            "ea": key,
            "name": record.get("name", ""),
            "overlaps": "0x%x" % following.start_ea,
          }
        )
      continue

    created = False
    try:
      # Give IDA the old database's end address first: it knows the extent
      # from a database where the function was already correct. If it refuses
      # -- the flow does not support it, say -- let IDA work the end out.
      if end and end > ea:
        created = ida_funcs.add_func(ea, end)
        if created:
          counts["created_with_end"] += 1
      if not created:
        created = ida_funcs.add_func(ea)
    except Exception as exc:  # noqa: BLE001
      _log(f"0x{ea:x}: {exc}")
      created = False

    if created:
      counts["created"] += 1
    else:
      counts["failed"] += 1
      if len(counts["failed_examples"]) < 20:
        counts["failed_examples"].append({"ea": key, "name": record.get("name", "")})

  return counts
