#!/usr/bin/python

"""
Headless entry point that dumps everything Diaphora's own exporter leaves
behind or mangles on the way, so that diaphora_auto_import.py can put it
into another database:

    the Functions window folder layout   -> diaphora_func_folders.py
    Hex-Rays local variables and args    -> diaphora_lvars.py
    local types and function prototypes  -> diaphora_types.py

Usage (run with idat/idat64 in batch/autonomous mode):

    idat64 -A -S"diaphora_dump_analysis.py folders=<p> lvars=<p> types=<p>" \\
           -L<logfile> <source.i64>

Arguments are name=value tokens, in any order, and each one is optional --
IDA splits the -S string on whitespace, so none of these paths may contain a
space. Each half is independent: one failing does not stop the others, and
none of them failing stops the port that follows. A ".ok" / ".fail" marker
file is left next to each output so a calling shell script can check the
outcome without scraping IDA's log.

All three dumps are cheap. The folder layout is a tree walk, the local
variables are a netnode read, and the types come straight out of the type
library: none of them decompiles anything.

Nothing is written into the database: like Diaphora's own exporting step,
this ends through idaapi.qexit(), which does not save. IDA still rewrites
the .i64 container as it closes, so the file's bytes and timestamp change
even though its contents do not.
"""

import os
import traceback

import idc
import idaapi


def _write_flag(path, text):
  try:
    with open(path, "w", encoding="utf8") as fh:
      fh.write(text)
  except OSError:
    pass


def _clear_flags(path):
  for flag in (path + ".ok", path + ".fail"):
    if os.path.exists(flag):
      os.remove(flag)


def _dump_folders(out_file):
  from diaphora_func_folders import dump_folders

  functions, folders = dump_folders(out_file)
  print(f"[folders] Dumped {functions} function(s) in {folders} folder(s)")
  return f"{functions} functions, {folders} folders"


def _dump_lvars(out_file):
  from diaphora_lvars import dump_lvars

  functions, variables = dump_lvars(out_file)
  print(f"[lvars] Dumped {variables} variable(s) in {functions} function(s)")
  return f"{variables} variables, {functions} functions"


def _dump_types(out_file):
  from diaphora_types import dump_types

  local_types, functions = dump_types(out_file)
  print(f"[types] Dumped {local_types} local type(s), {functions} function type(s)")
  return f"{local_types} local types, {functions} function types"


DUMPERS = (
  ("folders", _dump_folders),
  ("lvars", _dump_lvars),
  ("types", _dump_types),
)


def _parse_args():
  """
  name=value tokens. Positional order used to matter and was getting hard to
  keep straight as the list grew.
  """
  args = {}
  for token in idc.ARGV[1:]:
    name, _, value = token.partition("=")
    if value:
      args[name.strip().lower()] = value
  return args


def _run(label, out_file, func):
  _clear_flags(out_file)
  try:
    _write_flag(out_file + ".ok", func(out_file))
  except Exception:
    traceback.print_exc()
    _write_flag(out_file + ".fail", traceback.format_exc())
    print(f"[{label}] dump failed, see the traceback above")


def main():
  try:
    args = _parse_args()
    if not args:
      print("[dump] Nothing to do: pass folders=, lvars= and/or types=")
      return

    idc.auto_wait()
    for label, func in DUMPERS:
      out_file = args.get(label)
      if out_file:
        _run(label, out_file, func)
  except Exception:
    traceback.print_exc()
  finally:
    idaapi.qexit(0)


if __name__ == "__main__":
  main()
