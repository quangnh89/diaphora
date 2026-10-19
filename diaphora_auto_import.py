#!/usr/bin/python

"""
Headless, no-dialog variant of diaphora_load_and_import.py, meant to be
driven from a shell/batch script rather than from IDA's UI.

diaphora_ida.load_and_import_all_results() (the function used by
diaphora_load_and_import.py) calls idaapi.qexit(0) right after importing,
but qexit() does NOT save the database -- so when run unattended every
name/comment/struct it just imported is silently discarded when IDA exits.
This script does the same import but explicitly saves the database first,
and leaves a ".ok" / ".fail" marker file next to the results database so a
calling shell script can check the outcome without scraping IDA's log.

Usage (run with idat/idat64 in batch/autonomous mode):

    idat64 -A -S"diaphora_auto_import.py <results.sqlite> <main.sqlite> <diff.sqlite>" \
           -L<logfile> <target.i64>

Arguments (positional, space-separated -- none of these paths may contain
spaces, since that is how IDA itself splits the -S argument list):

    results.sqlite  the diffing results produced by
                    `diaphora.py main.sqlite diff.sqlite -o results.sqlite`
    main.sqlite     the exported sqlite of the database that is currently
                    open in IDA (the "new"/target database)
    diff.sqlite     the exported sqlite of the source-of-truth database
                    (the "old" database names/comments/types are read from)
"""

import os
import traceback

import idc
import idaapi

from diaphora_ida import CIDABinDiff


def _write_flag(path, text):
  try:
    with open(path, "w", encoding="utf8") as fh:
      fh.write(text)
  except OSError:
    pass


def _save_database():
  try:
    idc.save_database(idc.get_idb_path(), 0)
  except TypeError:
    # Older/newer idc.save_database() signatures take no arguments and just
    # save in place.
    idc.save_database()


def main():
  filename = idc.ARGV[1]
  main_db = idc.ARGV[2]
  diff_db = idc.ARGV[3]

  ok_flag = filename + ".ok"
  fail_flag = filename + ".fail"
  for flag in (ok_flag, fail_flag):
    if os.path.exists(flag):
      os.remove(flag)

  try:
    idc.auto_wait()

    for path, label in ((filename, "results"), (main_db, "main"), (diff_db, "diff")):
      if not os.path.exists(path):
        raise Exception(f"{label} database not found: {path}")

    bd = CIDABinDiff(":memory:")
    imported = bd.load_and_import_all_results(filename, main_db, diff_db)
    if not imported:
      raise Exception("load_and_import_all_results() reported failure, check the log above")

    _save_database()
    _write_flag(ok_flag, "ok")
  except Exception:
    _write_flag(fail_flag, traceback.format_exc())
  finally:
    idaapi.qexit(0)


if __name__ == "__main__":
  main()
