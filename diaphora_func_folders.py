#!/usr/bin/python

"""
Port the Functions window folder layout (IDA's "function folders") from one
IDA database to another.

Diaphora itself knows nothing about folders: it copies names, comments,
prototypes and types, but the carefully built directory tree of the old
database is lost. This module dumps that tree to a JSON file from one
database and re-applies it to another one, matching functions by name.

Both halves must run inside IDA (they use the ida_dirtree API). The dumping
side is driven by diaphora_dump_folders.py, the applying side by
diaphora_auto_import.py.

Folders live in a dirtree_t whose inodes are the functions' start addresses
(the DSF_INODE_EA flag of dirspec_t). Folder support appeared in IDA 7.5 and
was reworked in 9.3, which added the much faster dirtree_t.bulk_move(); we
use it when present and fall back to renaming entries one by one otherwise.

Note on "folded" folders: IDA renders a chain of single-child folders as one
item, joining the names with DIRTREE_FOLDED_SEP (0x1D). The path parser does
NOT split on that byte, so such a path is a single valid path component and
is dumped and recreated verbatim. Do not run it through
ida_dirtree.dirtree_restore_prefix_sep(), which is for display only.
"""

import json

import idc
import idautils

import ida_dirtree
import ida_funcs

FORMAT_VERSION = 1


def _log(message):
  print(f"[folders] {message}")


def _func_dirtree():
  return ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)


def _errstr(err):
  try:
    return ida_dirtree.dirtree_t.errstr(err)
  except (AttributeError, TypeError):
    # dirtree_t_errstr() as a free function is gone since IDA 9.0.
    return str(err)


def _abspath_of(dirtree, ea):
  """
  Absolute dirtree path of the function at @ea, name included, or None.
  """
  cursor = dirtree.find_entry(ida_dirtree.direntry_t(ea, False))
  if not cursor.valid():
    return None
  return dirtree.get_abspath(cursor) or None


def _folder_of(abspath):
  """
  The directory part of an absolute dirtree path. "/" for the root.
  """
  folder = abspath.rsplit("/", 1)[0]
  return folder if folder != "" else "/"


class _FolderCollector(ida_dirtree.dirtree_visitor_t):
  """
  Collect every directory of a dirtree, including the empty ones.
  """

  def __init__(self, dirtree):
    super().__init__()
    self.dirtree = dirtree
    self.folders = []

  def visit(self, cursor, de):
    if de.isdir:
      path = self.dirtree.get_abspath(cursor)
      if path and path != "/":
        self.folders.append(path)
    return 0


def dump_folders(out_path):
  """
  Write the folder layout of the currently open database to @out_path.

  Returns a (functions, folders) tuple of counts.
  """
  dirtree = _func_dirtree()
  dirtree.chdir("/")

  # Only reading here: modifying the tree during traverse() is undefined
  # behaviour.
  collector = _FolderCollector(dirtree)
  dirtree.traverse(collector)
  folders = sorted(set(collector.folders))

  functions = []
  for ea in idautils.Functions():
    abspath = _abspath_of(dirtree, ea)
    if abspath is None:
      continue

    folder = _folder_of(abspath)
    if folder == "/":
      # Functions at the root carry no information worth porting.
      continue

    functions.append(
      {
        "name": ida_funcs.get_func_name(ea),
        "ea": "0x%x" % ea,
        "folder": folder,
      }
    )

  data = {
    "format_version": FORMAT_VERSION,
    "source_idb": idc.get_idb_path(),
    "folders": folders,
    "functions": functions,
  }

  with open(out_path, "w", encoding="utf8") as fh:
    json.dump(data, fh, indent=1, ensure_ascii=True)

  return len(functions), len(folders)


def _strip_dup_suffix(name):
  """
  Undo the "_0".."_9" suffix Diaphora appends when the imported name is
  already taken, or None if @name does not look suffixed.
  """
  if len(name) > 2 and name[-2] == "_" and name[-1].isdigit():
    return name[:-2]
  return None


def _create_folders(dirtree, folders):
  created = 0
  # Shallowest first, so that a parent always exists before its children.
  for folder in sorted(folders, key=lambda path: path.count("/")):
    if folder == "/":
      continue

    err = dirtree.mkdir(folder)
    if err == ida_dirtree.DTE_OK:
      created += 1
    elif err != ida_dirtree.DTE_ALREADY_EXISTS:
      _log(f"mkdir({folder!r}) failed: {_errstr(err)}")
  return created


def _move_one_by_one(dirtree, folder, eas):
  moved = 0
  failed = 0
  base = "" if folder == "/" else folder

  for ea in eas:
    abspath = _abspath_of(dirtree, ea)
    if abspath is None:
      failed += 1
      continue

    leaf = abspath.rsplit("/", 1)[1]
    dst = f"{base}/{leaf}"
    if dst == abspath:
      continue

    err = dirtree.rename(abspath, dst)
    if err == ida_dirtree.DTE_OK:
      moved += 1
    else:
      failed += 1
      _log(f"rename({abspath!r}, {dst!r}) failed: {_errstr(err)}")

  return moved, failed


def _move_group(dirtree, folder, eas):
  """
  Move every function of @eas into @folder. Cursors are resolved here rather
  than by the caller because an earlier move invalidates them.
  """
  if not hasattr(dirtree, "bulk_move"):
    # IDA < 9.3.
    return _move_one_by_one(dirtree, folder, eas)

  cursors = ida_dirtree.dirtree_cursor_vec_t()
  for ea in eas:
    cursor = dirtree.find_entry(ida_dirtree.direntry_t(ea, False))
    if cursor.valid():
      cursors.push_back(cursor)

  if len(cursors) == 0:
    return 0, len(eas)

  moved_items = ida_dirtree.dirtree_cursor_vec_t()
  err = dirtree.bulk_move(cursors, folder, -1, moved_items)
  if err == ida_dirtree.DTE_OK:
    return len(moved_items), len(eas) - len(moved_items)

  _log(f"bulk_move() into {folder!r} failed: {_errstr(err)}, moving one by one")
  return _move_one_by_one(dirtree, folder, eas)


def apply_folders(in_path):
  """
  Re-create in the currently open database the folder layout stored in
  @in_path by dump_folders(), moving every function whose name matches.

  Returns a (moved, failed, folders_created) tuple of counts.
  """
  with open(in_path, "r", encoding="utf8") as fh:
    data = json.load(fh)

  version = data.get("format_version")
  if version != FORMAT_VERSION:
    raise ValueError(
      f"Unsupported folder dump version {version}, expected {FORMAT_VERSION}"
    )

  dirtree = _func_dirtree()
  dirtree.chdir("/")

  created = _create_folders(dirtree, data.get("folders", []))

  wanted = {}
  for entry in data.get("functions", []):
    wanted[entry["name"]] = entry["folder"]

  groups = {}
  for ea in idautils.Functions():
    name = ida_funcs.get_func_name(ea)
    folder = wanted.get(name)
    if folder is None:
      stripped = _strip_dup_suffix(name)
      if stripped is not None:
        folder = wanted.get(stripped)
    if folder is None:
      continue

    abspath = _abspath_of(dirtree, ea)
    if abspath is None or _folder_of(abspath) == folder:
      continue

    groups.setdefault(folder, []).append(ea)

  moved = 0
  failed = 0
  for folder, eas in groups.items():
    group_moved, group_failed = _move_group(dirtree, folder, eas)
    moved += group_moved
    failed += group_failed

  # No dirtree.save() here on purpose. A standard dirtree is persisted with
  # the database, and calling save() on one leaves IDA 9.4 unable to reopen
  # that database at all ("Database initialization failed with error 4"),
  # even though the layout itself was written correctly. Saving the database
  # is enough and is the caller's job.
  return moved, failed, created
