#!/usr/bin/python

"""
Headless entry point that dumps the Functions window folder layout of the
database it is run against, so that port_idb.bat can later re-apply it to
another database. See diaphora_func_folders.py for the actual work.

Usage (run with idat/idat64 in batch/autonomous mode):

    idat64 -A -S"diaphora_dump_folders.py <folders.json>" -L<logfile> <source.i64>

Nothing is written into the database: like Diaphora's own exporting step,
this ends through idaapi.qexit(), which does not save. IDA still rewrites
the .i64 container as it closes, so the file's bytes and timestamp change
even though its contents do not.

A ".ok" / ".fail" marker file is left next to <folders.json> so a calling
shell script can check the outcome without scraping IDA's log.
"""

import os
import traceback

import idc
import idaapi

from diaphora_func_folders import dump_folders


def _write_flag(path, text):
  try:
    with open(path, "w", encoding="utf8") as fh:
      fh.write(text)
  except OSError:
    pass


def main():
  out_file = idc.ARGV[1]

  ok_flag = out_file + ".ok"
  fail_flag = out_file + ".fail"
  for flag in (ok_flag, fail_flag):
    if os.path.exists(flag):
      os.remove(flag)

  try:
    idc.auto_wait()

    functions, folders = dump_folders(out_file)
    print(f"[folders] Dumped {functions} function(s) in {folders} folder(s)")
    _write_flag(ok_flag, f"{functions} functions, {folders} folders")
  except Exception:
    _write_flag(fail_flag, traceback.format_exc())
  finally:
    idaapi.qexit(0)


if __name__ == "__main__":
  main()
