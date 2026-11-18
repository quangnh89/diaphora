#!/usr/bin/python

"""
Headless, no-dialog variant of diaphora_load_and_import.py, meant to be
driven from a shell/batch script rather than from IDA's UI.

Four things this does that Diaphora's own headless path does not:

1. It imports EVERY match above the ratio threshold.
   diaphora_ida.load_and_import_all_results() imports through
   import_all_auto(), which keeps only the matches whose name in the NEW
   database still starts with "sub_". That is fine the first time, but once
   a database has been ported its functions have real names, so every later
   run becomes a no-op -- measured on a 4446 match session: 3 functions
   imported out of 4446. Everything Diaphora can port (prototypes, function
   and instruction comments, forced operands, pseudo-code comments, global
   variable names and types) sits behind that same filter.

2. It transfers the local types and the function prototypes in IDA's own
   serialized form rather than as C text. Diaphora prints them and parses
   them back, which on a real pair of builds lost 155 of 2181 types, and
   with them every struct member whose type was one of those -- plus the
   378 prototypes that named one. See diaphora_types.py.

3. It ports the Functions window folder layout, the Hex-Rays local variables
   and the stack frame member names and types, none of which Diaphora
   touches. The frame members are the ones that show in the disassembly as
   `[rsp+58h+flag]`, and they are a separate thing from the Hex-Rays local
   variables that show in the pseudo-code -- see diaphora_frames.py.

4. It writes a report saying what was and was not ported, instead of
   leaving the answer buried in IDA's log.

It also saves the database, which matters: load_and_import_all_results()
ends in idaapi.qexit(), and qexit() does NOT save, so unattended every
name and comment it just imported would be discarded on exit.

Usage (run with idat/idat64 in batch/autonomous mode):

    idat64 -A -S"diaphora_auto_import.py results=<p> main=<p> diff=<p> \\
                 folders=<p> lvars=<p> types=<p> frames=<p> report=<p> \\
                 typemode=all" \\
           -L<logfile> <target.i64>

Arguments are name=value tokens in any order. IDA splits the -S string on
whitespace, so none of these paths may contain a space.

    results   the diffing results produced by
              `diaphora.py main.sqlite diff.sqlite -o results.sqlite`
    main      the exported sqlite of the database that is currently open in
              IDA (the "new"/target database). It is updated in place with
              the ported state of every function that was touched, so that
              whatever reads it next sees the result of the port.
    diff      the exported sqlite of the source-of-truth database (the "old"
              database names/comments/types are read from)
    folders   the folder layout dumped by diaphora_dump_analysis.py
    lvars     the local variables dumped by the same script
    types     the local and function types dumped by the same script
    frames    the stack frame members dumped by the same script
    report    where to write the port report
    typemode  "all" to replace a type the target already has, "missing" to
              keep it and only fill in what is absent. Default "all".

Only results, main and diff are required.

A ".ok" / ".fail" marker file is left next to the results database so a
calling shell script can check the outcome without scraping IDA's log.
"""

import json
import os
import traceback

import idc
import idaapi
import ida_funcs

import diaphora
import diaphora_ida
from diaphora_ida import CIDABinDiff


def _write_flag(path, text):
  try:
    with open(path, "w", encoding="utf8") as fh:
      fh.write(text)
  except OSError:
    pass


def _parse_args():
  """
  name=value tokens. Positional order used to matter and was getting hard to
  keep straight as the list grew to eight.
  """
  args = {}
  for token in idc.ARGV[1:]:
    name, _, value = token.partition("=")
    if value:
      args[name.strip().lower()] = value
  return args


def _save_database():
  try:
    idc.save_database(idc.get_idb_path(), 0)
  except TypeError:
    # Older/newer idc.save_database() signatures take no arguments and just
    # save in place.
    idc.save_database()


class CPortObserver:
  """
  Counts what the import actually did.

  Diaphora reports none of this, and the numbers are the only way to tell a
  port that worked from one that silently skipped everything. The hooks are
  pure observers -- they always delegate and never change a result -- with
  one deliberate exception: a function whose address is in `protected` keeps
  the name the new database already gave it.
  """

  def __init__(self):
    self.protected = set()
    self.counts = {
      "functions_matched": 0,
      "functions_imported": 0,
      "names_set": 0,
      "names_kept": 0,
      "prototypes_failed": 0,
      "prototypes_missing": 0,
      "globals_renamed": 0,
      "globals_retyped": 0,
    }
    self.prototype_failures = []
    self._originals = {}

  def install(self):
    """
    Wrap the three module level helpers diaphora_ida's import path calls.
    """
    self._originals = {
      "set_name": diaphora_ida.set_name,
      "SetType": diaphora_ida.SetType,
      "log": diaphora_ida.log,
    }
    diaphora_ida.set_name = self._set_name
    diaphora_ida.SetType = self._set_type
    diaphora_ida.log = self._log

  def remove(self):
    for name, func in self._originals.items():
      setattr(diaphora_ida, name, func)
    self._originals = {}

  def _set_name(self, ea, name, flags=0):
    if ea in self.protected:
      # The new database already has a real name here and it differs from
      # the old one: a fresh symbol beats a stale guess. Reporting success
      # also stops do_import_one() from falling back to "name_0".
      self.counts["names_kept"] += 1
      return True

    ok = self._originals["set_name"](ea, name, flags)
    if ok:
      if ida_funcs.get_func(ea) is None:
        self.counts["globals_renamed"] += 1
      else:
        self.counts["names_set"] += 1
    return ok

  def _set_type(self, ea, proto):
    ok = self._originals["SetType"](ea, proto)
    if ok and ida_funcs.get_func(ea) is None:
      self.counts["globals_retyped"] += 1
    return ok

  def _log(self, message):
    # do_import_one() already reports an unusable prototype this way, it is
    # just never counted.
    text = str(message)
    if text.startswith("Could not set the type of "):
      self.counts["prototypes_failed"] += 1
      if len(self.prototype_failures) < 20:
        self.prototype_failures.append(text)
    return self._originals["log"](message)


def _pairs_of(items):
  """
  (new ea, old ea) for every chooser row. A matched chooser item is
  [line, new ea hex, new name, old ea hex, old name, ratio, ...].
  """
  return [(int(item[1], 16), int(item[3], 16)) for item in items]


def _protect_existing_names(bd, items, observer):
  """
  Mark the functions whose existing name must survive the port: the new
  database gave them a real name of their own and it is not the old one.
  """
  for item in items:
    ea_new = int(item[1], 16)
    old_name = item[4]
    current = ida_funcs.get_func_name(ea_new)
    if not current or not old_name or current == old_name:
      continue
    if bd.is_auto_generated(current):
      continue
    observer.protected.add(ea_new)


def _import_matches(bd, results_file, main_db, diff_db, observer):
  """
  What load_and_import_all_results() does, except that it imports every
  match instead of only the ones still named sub_* on the new side.
  """
  results_db = diaphora.sqlite3_connect(results_file)
  cur = results_db.cursor()
  try:
    cur.execute("select main_db, diff_db, version from config")
    rows = cur.fetchall()
    if len(rows) != 1:
      raise Exception("Malformed results database")

    version = rows[0]["version"]
    if version != diaphora.VERSION_VALUE:
      print(
        f"[port] WARNING: results were made by Diaphora {version}, this is "
        f"{diaphora.VERSION_VALUE}"
      )

    bd.reinit(main_db, diff_db)

    min_ratio = float(bd.get_value_for("MINIMUM_IMPORT_RATIO", 0.5))
    print(f"[port] Minimum import ratio {min_ratio}")
    bd.populate_choosers(cur, min_ratio=min_ratio, multimatch=False)
  finally:
    cur.close()
    results_db.close()

  items = list(bd.best_chooser.items) + list(bd.partial_chooser.items)
  observer.counts["functions_matched"] = len(items)
  _protect_existing_names(bd, items, observer)

  # import_all() is do_import_all(only_subs=False): type libraries, then the
  # struct/enum/union/typedef definitions, then every match.
  bd.import_all(items)
  observer.counts["functions_imported"] = len(items)
  return items


def _count_missing_prototypes(bd, pairs, observer):
  """
  Functions the old database had a prototype for that still have none here.

  Counting every untyped function would be meaningless: plenty never had a
  prototype on either side. The diff database is still attached at this
  point, so ask it which ones did.
  """
  cur = bd.db_cursor()
  try:
    cur.execute(
      """select address from diff.functions
           where (prototype2 is not null and prototype2 != 'int()')
              or (prototype is not null and prototype != 'int()')"""
    )
    typed_before = {str(row[0]) for row in cur.fetchall()}
  finally:
    cur.close()

  for ea_new, ea_old in pairs:
    if str(ea_old) in typed_before and idc.get_type(ea_new) is None:
      observer.counts["prototypes_missing"] += 1


def _apply_local_types(types_json, mode):
  """
  Before the import: the definitions have to be in place for the prototypes
  Diaphora applies to parse, and once they are its own import_definitions()
  finds every name complete and skips it.
  """
  if types_json is None:
    return {"status": "not requested"}
  if not os.path.exists(types_json):
    return {"status": f"{types_json} not found, skipped"}

  try:
    from diaphora_types import apply_local_types

    counts = apply_local_types(types_json, mode)
    counts["status"] = "ok"
    return counts
  except Exception:
    traceback.print_exc()
    return {"status": f"failed: {traceback.format_exc(limit=0).strip()}"}


def _apply_function_types(types_json, pairs):
  """
  After the import, so that the exact type wins over whatever Diaphora's C
  text path managed to parse.
  """
  if types_json is None:
    return {"status": "not requested"}
  if not os.path.exists(types_json):
    return {"status": f"{types_json} not found, skipped"}

  try:
    from diaphora_types import apply_function_types

    counts = apply_function_types(types_json, pairs)
    counts["status"] = "ok"
    return counts
  except Exception:
    traceback.print_exc()
    return {"status": f"failed: {traceback.format_exc(limit=0).strip()}"}


def _apply_folders(folders_json):
  if folders_json is None:
    return {"status": "not requested"}
  if not os.path.exists(folders_json):
    return {"status": f"{folders_json} not found, skipped"}

  try:
    from diaphora_func_folders import apply_folders

    moved, failed, created = apply_folders(folders_json)
    return {
      "status": "ok",
      "moved": moved,
      "failed": failed,
      "folders_created": created,
    }
  except Exception:
    traceback.print_exc()
    return {"status": f"failed: {traceback.format_exc(limit=0).strip()}"}


def _apply_frames(frames_json, pairs):
  """
  The stack frame member names and types, which show up in the disassembly.
  A different thing from the Hex-Rays local variables below, and the largest
  single source of noise in the old database vs new database comparison.
  """
  if frames_json is None:
    return {"status": "not requested"}
  if not os.path.exists(frames_json):
    return {"status": f"{frames_json} not found, skipped"}

  try:
    from diaphora_frames import apply_frames

    counts = apply_frames(frames_json, pairs)
    counts["status"] = "ok"
    return counts
  except Exception:
    traceback.print_exc()
    return {"status": f"failed: {traceback.format_exc(limit=0).strip()}"}


def _apply_lvars(lvars_json, pairs):
  if lvars_json is None:
    return {"status": "not requested"}
  if not os.path.exists(lvars_json):
    return {"status": f"{lvars_json} not found, skipped"}

  try:
    from diaphora_lvars import apply_lvars

    counts = apply_lvars(lvars_json, pairs)
    counts["status"] = "ok"
    return counts
  except Exception:
    traceback.print_exc()
    return {"status": f"failed: {traceback.format_exc(limit=0).strip()}"}


def _refresh_exported_rows(bd, pairs):
  """
  Re-read the functions we touched into the primary database.

  import_items() already does this, but it runs before the names are
  restored, before the local variables are applied and before the folders
  are moved, so its rows are a snapshot of a half finished port. Whatever
  reads main.sqlite next -- the AI export, in practice -- should see the
  finished state.
  """
  refreshed = 0
  for ea_new, _ in pairs:
    ea = str(ea_new)
    try:
      props = bd.read_function(ea)
      if not props:
        continue
      bd.delete_function(ea)
      bd.save_function(props)
      refreshed += 1
    except Exception as exc: # noqa: BLE001
      print(f"[port] Could not refresh 0x{ea_new:x}: {exc}")

  try:
    bd.db.execute("analyze")
    bd.db.commit()
  except Exception as exc: # noqa: BLE001
    print(f"[port] Could not commit the refreshed rows: {exc}")

  return refreshed


def _close_exported_db(bd):
  """
  Fold the write-ahead log back into main.sqlite and close it.

  Diaphora exports with journal_mode = WAL, and idaapi.qexit() kills the
  process without closing sqlite, so the newest rows stay in a "-wal" file
  beside the database. That is normally only untidy, because the next reader
  opens the same path and picks the -wal up. Here it is not: the import is
  handed the 8.3 form of main.sqlite, SQLite derives the -wal name from the
  path it was opened with, and whoever reads the database back under its long
  name would find no -wal and quietly see the rows as they were before the
  port -- which is exactly what the AI export does next.
  """
  for schema in ("main", "diff"):
    try:
      bd.db.execute(f"pragma {schema}.wal_checkpoint(truncate)")
    except Exception as exc: # noqa: BLE001
      print(f"[port] Could not checkpoint the {schema} database: {exc}")

  try:
    bd.db.commit()
    bd.db_close()
  except Exception as exc: # noqa: BLE001
    print(f"[port] Could not close the exported database: {exc}")


def _summary_line(report):
  counts = report["functions"]
  local_types = report["local_types"]
  func_types = report["function_types"]
  frames = report.get("frames", {})
  lvars = report["lvars"]
  folders = report["folders"]
  parts = [
    "%d/%d functions imported" % (counts["functions_imported"], counts["functions_matched"]),
    "%d names set" % counts["names_set"],
    "%d globals renamed" % counts["globals_renamed"],
  ]
  if local_types.get("status") == "ok":
    parts.append(
      "%d/%d local types complete"
      % (local_types.get("complete_after", 0), local_types.get("local_types_dumped", 0))
    )
  if func_types.get("status") == "ok":
    parts.append("%d prototypes" % func_types.get("applied", 0))
  if frames.get("status") == "ok":
    parts.append(
      "%d frame members in %d functions"
      % (frames.get("names_applied", 0), frames.get("functions_touched", 0))
    )
  if lvars.get("status") == "ok":
    parts.append(
      "%d lvars in %d functions"
      % (lvars.get("names_applied", 0), lvars.get("functions_touched", 0))
    )
  if folders.get("status") == "ok":
    parts.append("%d folders moved" % folders.get("moved", 0))
  return ", ".join(parts)


def main():
  args = _parse_args()
  filename = args.get("results")
  main_db = args.get("main")
  diff_db = args.get("diff")
  folders_json = args.get("folders")
  lvars_json = args.get("lvars")
  types_json = args.get("types")
  frames_json = args.get("frames")
  report_json = args.get("report")
  type_mode = args.get("typemode", "all")

  if not filename or not main_db or not diff_db:
    print("[port] results=, main= and diff= are all required")
    idaapi.qexit(0)
    return

  ok_flag = filename + ".ok"
  fail_flag = filename + ".fail"
  for flag in (ok_flag, fail_flag):
    if os.path.exists(flag):
      os.remove(flag)

  observer = CPortObserver()
  try:
    idc.auto_wait()

    for path, label in ((filename, "results"), (main_db, "main"), (diff_db, "diff")):
      if not os.path.exists(path):
        raise Exception(f"{label} database not found: {path}")

    bd = CIDABinDiff(":memory:")

    # Types first: the prototypes the import applies name them, and
    # Diaphora's own definition handling then finds them already in place.
    local_types = _apply_local_types(types_json, type_mode)
    print(f"[port] local types: {json.dumps(local_types)}")

    observer.install()
    try:
      items = _import_matches(bd, filename, main_db, diff_db, observer)
    finally:
      observer.remove()

    pairs = _pairs_of(items)
    func_types = _apply_function_types(types_json, pairs)
    _count_missing_prototypes(bd, pairs, observer)

    # Frames before lvars: naming a stack slot in the frame is what the
    # disassembly shows, naming the Hex-Rays variable is what the
    # pseudo-code shows, and where the two disagree the lvar setting is the
    # one the decompiler honours. So apply the weaker one first.
    frames = _apply_frames(frames_json, pairs)
    lvars = _apply_lvars(lvars_json, pairs)
    folders = _apply_folders(folders_json)
    refreshed = _refresh_exported_rows(bd, pairs)
    _close_exported_db(bd)

    report = {
      "functions": observer.counts,
      "prototype_failures": observer.prototype_failures,
      "local_types": local_types,
      "function_types": func_types,
      "frames": frames,
      "lvars": lvars,
      "folders": folders,
      "exported_rows_refreshed": refreshed,
    }

    print("[port] " + json.dumps(report["functions"]))
    print(f"[port] function types: {json.dumps(func_types)}")
    print(f"[port] frames: {json.dumps(frames)}")
    print(f"[port] lvars: {json.dumps(lvars)}")
    print(f"[port] folders: {json.dumps(folders)}")

    if report_json:
      try:
        with open(report_json, "w", encoding="utf8") as fh:
          json.dump(report, fh, indent=1, ensure_ascii=False)
      except OSError as exc:
        print(f"[port] Could not write the report: {exc}")

    _save_database()
    _write_flag(ok_flag, "ok, " + _summary_line(report))
  except Exception:
    observer.remove()
    _write_flag(fail_flag, traceback.format_exc())
  finally:
    idaapi.qexit(0)


if __name__ == "__main__":
  main()
