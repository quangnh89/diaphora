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

Nothing is created on the strength of an address alone. Two builds of one
module are not laid out alike -- 18.74% of the code section differs between
hvax64.exe 9711 and 9836 -- so the dump carries the bytes of every function
and this only creates one where the new database holds the same code. Without
that check it was creating functions over whatever had moved in, and those
then collected the wrong name: `hv_boot_iretq_probe` became
`hv_svm_stack_warm_stub`, `hv_lp_mwait` became `hv_boot_page_stub_resume64`.

Addresses that fall inside a function the new database already has are left
alone. Splitting a function is a different and much riskier operation than
creating one, and the two databases disagreeing about where a function starts
is a judgement call rather than an omission. Those are counted and reported
instead.

A function that starts a few bytes *into* one of these, however, is moved back
to the right entry point: that is the hotpatch `nop; nop` prologue, where IDA
started its own function after the padding and left the real entry belonging to
no function at all.

Unlike the other dump scripts this one *writes* to the database, so whatever
drives it has to save, and the caller must have made a backup first.
"""

import json

from hashlib import md5

import idc
import idautils

import ida_bytes
import ida_funcs
import ida_ua

FORMAT_VERSION = 2

# How many bytes of the start of a function are kept for the weaker of the two
# byte checks. Enough that two unrelated functions sharing a prologue are still
# told apart, short enough that a function whose body changed is still
# recognised at its own address.
HEAD_BYTES = 32


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

    # The bytes are what makes this dump usable at all. An address alone says
    # nothing: measured on two builds of hvax64.exe, 18.74% of the code section
    # differs, and 874 of the 889 function starts missing from the new database
    # sit at addresses where the new build holds different code. Creating a
    # function there means creating one over whatever moved in.
    length = max(0, func.end_ea - ea)
    raw = ida_bytes.get_bytes(ea, length) if length else None

    functions["0x%x" % ea] = {
      "end": func.end_ea,
      "name": name,
      "flags": func.flags,
      "auto_name": auto,
      "len": length,
      "md5": md5(raw).hexdigest() if raw else None,
      "head": raw[:HEAD_BYTES].hex() if raw else None,
    }

  data = {
    "format_version": FORMAT_VERSION,
    "source_idb": idc.get_idb_path(),
    "functions": functions,
  }

  with open(out_path, "w", encoding="utf8") as fh:
    json.dump(data, fh, indent=1, ensure_ascii=True)

  return len(functions), named


def _verify_bytes(ea, record):
  """
  Does this database hold the same code at @ea as the database the dump came
  from? Returns "exact", "prefix", "differ" or "unreadable".

  "prefix" means only the first HEAD_BYTES match: the function is still
  recognisably the one the dump describes, its body just changed between the
  two builds. That is worth creating. "differ" is a different function
  altogether and must not be.
  """
  length = record.get("len") or 0
  want_md5 = record.get("md5")
  want_head = record.get("head")
  if not length or not want_md5:
    return "unreadable"

  raw = ida_bytes.get_bytes(ea, length)
  if raw is None or len(raw) != length:
    return "unreadable"
  if md5(raw).hexdigest() == want_md5:
    return "exact"
  if want_head and raw[:HEAD_BYTES].hex() == want_head[: HEAD_BYTES * 2]:
    return "prefix"
  return "differ"


def _undefine_and_create(ea, end, counts):
  """
  Last resort: clear what is defined at @ea, make an instruction, try again.

  This is the one that matters for the hotpatch stubs. IDA's auto-analysis had
  defined their first two bytes (`66 90`, a nop) as a 2-byte *data* item named
  `byte_FFFFF8000026CF30`, and add_func() refuses to start a function on data,
  so every one of them failed silently. Two of the measured eight were worse
  still: a tail byte inside a 252-byte data blob IDA had laid over the middle
  of .text. DELIT_EXPAND clears the whole enclosing item, which is the point --
  but it reaches outside [ea, end), so it is counted separately and only ever
  runs on a range whose bytes were verified first.
  """
  size = (end - ea) if (end and end > ea) else HEAD_BYTES
  if not ida_bytes.del_items(ea, ida_bytes.DELIT_EXPAND, size):
    return False

  ida_ua.create_insn(ea)
  created = False
  if end and end > ea:
    created = ida_funcs.add_func(ea, end)
  if not created:
    created = ida_funcs.add_func(ea)
  if created:
    counts["created_after_undefine"] += 1
  return created


def _move_start_back(ea, end, record, blocking, counts):
  """
  The new database has a function that starts a few bytes into this one.

  For the hotpatch stubs that is exactly the 3 bytes of `nop; nop` prologue:
  the old database starts the function at ...cf90 and IDA started its own at
  ...cf93, so the real entry point belongs to no function and nothing can be
  ported to it. set_func_start() is the operation for this; failing that the
  function is removed and recreated with the extent the old database knows.

  A name somebody chose is never thrown away this way -- if the function in
  the way carries one, this is reported instead.
  """
  key = "0x%x" % ea
  if ida_bytes.has_user_name(ida_bytes.get_full_flags(blocking.start_ea)):
    counts["blocked_by_user_name"] += 1
    if len(counts["blocked_examples"]) < 20:
      counts["blocked_examples"].append(
        {
          "ea": key,
          "name": record.get("name", ""),
          "blocked_by": idc.get_func_name(blocking.start_ea) or "",
        }
      )
    return False

  was = blocking.start_ea
  if ida_funcs.set_func_start(was, ea) == ida_funcs.MOVE_FUNC_OK:
    counts["start_moved"] += 1
    return True

  if ida_funcs.del_func(was):
    created = False
    if end and end > ea:
      created = ida_funcs.add_func(ea, end)
    if not created:
      created = ida_funcs.add_func(ea)
    if not created:
      created = _undefine_and_create(ea, end, counts)
    if created:
      counts["recreated"] += 1
      return True

  counts["failed"] += 1
  if len(counts["failed_examples"]) < 20:
    counts["failed_examples"].append(
      {"ea": key, "name": record.get("name", ""), "why": "could not move 0x%x" % was}
    )
  return False


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
    "bytes_differ": 0,
    "bytes_unreadable": 0,
    "verified_exact": 0,
    "verified_prefix": 0,
    "created": 0,
    "created_with_end": 0,
    "created_after_undefine": 0,
    "start_moved": 0,
    "recreated": 0,
    "inside_other": 0,
    "blocked_by_user_name": 0,
    "failed": 0,
    "inside_examples": [],
    "differ_examples": [],
    "blocked_examples": [],
    "failed_examples": [],
  }

  for key, record in sorted(saved.items(), key=lambda item: int(item[0], 16)):
    ea = int(key, 16)
    end = record.get("end")

    # Before anything else: is this the same code? An address from the old
    # database means nothing on its own -- see the comment in dump_funcs().
    verdict = _verify_bytes(ea, record)
    if verdict == "exact":
      counts["verified_exact"] += 1
    elif verdict == "prefix":
      counts["verified_prefix"] += 1
    elif verdict == "unreadable":
      counts["bytes_unreadable"] += 1
      continue
    else:
      counts["bytes_differ"] += 1
      if len(counts["differ_examples"]) < 20:
        counts["differ_examples"].append({"ea": key, "name": record.get("name", "")})
      continue

    existing = ida_funcs.get_func(ea)
    if existing is not None:
      if existing.start_ea == ea:
        counts["already_present"] += 1
      else:
        # The address is in the middle of a function this database already
        # has. Creating here would mean splitting it, and with the bytes
        # verified this is a genuine disagreement about where the function
        # begins rather than an omission, so it is reported.
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

    try:
      following = ida_funcs.get_next_func(ea)
      if following is not None and end and following.start_ea < end:
        _move_start_back(ea, end, record, following, counts)
        continue

      created = False
      # Give IDA the old database's end address first: it knows the extent
      # from a database where the function was already correct. If it refuses
      # -- the flow does not support it, say -- let IDA work the end out.
      if end and end > ea:
        created = ida_funcs.add_func(ea, end)
        if created:
          counts["created_with_end"] += 1
      if not created:
        created = ida_funcs.add_func(ea)
      if not created:
        created = _undefine_and_create(ea, end, counts)
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
