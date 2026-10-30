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

    idat64 -A -S"diaphora_auto_import.py <results.sqlite> <main.sqlite> <diff.sqlite> [folders.json]" \
           -L<logfile> <target.i64>

Arguments (positional, space-separated -- none of these paths may contain
spaces, since that is how IDA itself splits the -S argument list):

    results.sqlite  the diffing results produced by
                    `diaphora.py main.sqlite diff.sqlite -o results.sqlite`
    main.sqlite     the exported sqlite of the database that is currently
                    open in IDA (the "new"/target database)
    diff.sqlite     the exported sqlite of the source-of-truth database
                    (the "old" database names/comments/types are read from)
    folders.json    optional, the Functions window folder layout of the old
                    database as dumped by diaphora_dump_folders.py. Applied
                    after the import, once the functions carry their final
                    names. Failing to apply it does not fail the import.
"""

import os
import sys
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


def _apply_folders(folders_json):
  """
  Port the function folder layout of the old database. Best effort: a
  failure here must not invalidate an otherwise successful import, so the
  outcome is only reported, never raised.
  """
  if folders_json is None:
    return "folders: not requested"

  if not os.path.exists(folders_json):
    return f"folders: {folders_json} not found, skipped"

  try:
    from diaphora_func_folders import apply_folders

    moved, failed, created = apply_folders(folders_json)
    return f"folders: {moved} moved, {failed} failed, {created} folders created"
  except Exception:
    traceback.print_exc()
    return f"folders: failed, {str(sys.exc_info()[1])}"


def main():
  filename = idc.ARGV[1]
  main_db = idc.ARGV[2]
  diff_db = idc.ARGV[3]
  folders_json = idc.ARGV[4] if len(idc.ARGV) > 4 else None

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

    folders_status = _apply_folders(folders_json)
    print(f"[folders] {folders_status}")

    _save_database()
    _write_flag(ok_flag, f"ok, {folders_status}")
  except Exception:
    _write_flag(fail_flag, traceback.format_exc())
  finally:
    idaapi.qexit(0)


if __name__ == "__main__":
  main()
