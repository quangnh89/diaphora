#!/usr/bin/python

"""
Headless entry point that creates the functions the new database is missing,
from the list diaphora_dump_analysis.py wrote out of the old one.

Usage (run with idat/idat64 in batch/autonomous mode):

    idat64 -A -S"diaphora_apply_funcs.py funcs=<p> report=<p>" \\
           -L<logfile> <target.i64>

Arguments are name=value tokens. IDA splits the -S string on whitespace, so
none of these paths may contain a space. `report` is optional.

This has to run BEFORE the new database is exported, so that the functions it
creates get diffed and ported like any other. That also makes it the first
step that writes to the new database, so the caller must already have taken
its backup.

Unlike the dump steps, this one ends with idc.save_database(): qexit() does
not save, and without saving the functions would be gone by the time the
export runs.
"""

import json
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


def _parse_args():
  args = {}
  for token in idc.ARGV[1:]:
    name, _, value = token.partition("=")
    if value:
      args[name.strip().lower()] = value
  return args


def main():
  args = _parse_args()
  funcs_json = args.get("funcs")
  report_json = args.get("report")

  if not funcs_json:
    print("[funcs] Nothing to do: pass funcs=<path>")
    idaapi.qexit(0)
    return

  ok_flag = funcs_json + ".applied.ok"
  fail_flag = funcs_json + ".applied.fail"
  for flag in (ok_flag, fail_flag):
    if os.path.exists(flag):
      os.remove(flag)

  try:
    idc.auto_wait()

    if not os.path.exists(funcs_json):
      raise Exception(f"{funcs_json} not found")

    from diaphora_funcs import apply_funcs

    counts = apply_funcs(funcs_json)
    print("[funcs] " + json.dumps(counts))

    if report_json:
      try:
        with open(report_json, "w", encoding="utf8") as fh:
          json.dump(counts, fh, indent=1, ensure_ascii=False)
      except OSError as exc:
        print(f"[funcs] Could not write the report: {exc}")

    if counts["created"]:
      # Only save when something was actually created: saving rewrites the
      # database, and there is no reason to do that for a no-op re-run.
      idc.save_database(idc.get_idb_path())

    _write_flag(
      ok_flag,
      "%d created, %d already present, %d inside another function, %d failed"
      % (counts["created"], counts["already_present"],
         counts["inside_other"], counts["failed"]),
    )
  except Exception:
    traceback.print_exc()
    _write_flag(fail_flag, traceback.format_exc())
  finally:
    idaapi.qexit(0)


if __name__ == "__main__":
  main()
