#!/usr/bin/python3

"""
Turn a Diaphora diffing session into a folder of plain text that an AI agent
can read directly, without IDA and without knowing anything about Diaphora's
internals.

This runs on the sqlite files only -- the two exported databases and the
diffing results -- so it needs no IDA license and no IDA installation. It is
normally driven by ai_diff.bat, but it can be run by hand on any set of files
produced by:

    diaphora.py new.sqlite old.sqlite -o results.sqlite

Usage:

    python diaphora_ai_export.py --results results.sqlite \
                                 --new new.sqlite --old old.sqlite \
                                 --outdir out

Orientation matters and is easy to get backwards: Diaphora calls the first
database "main"/"primary" and the second one "diff"/"secondary". We always
pass the NEW database first, so throughout the output "primary" is the NEW
binary and "secondary" is the OLD one. Every record names the two sides
explicitly, as "new" and "old", so nothing downstream has to remember this.
"""

import argparse
import difflib
import json
import os
import re
import sqlite3
import time

# The order the matches are listed in, most trustworthy first.
TYPE_ORDER = ["best", "partial", "unreliable", "multimatch"]

# How many rows the human-readable summary shows before pointing at the
# .jsonl files for the rest.
SUMMARY_ROWS = 40

_UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9_.-]")


def connect(path):
  db = sqlite3.connect(path)
  db.row_factory = sqlite3.Row
  # Exported databases occasionally hold text that is not valid UTF-8 (string
  # literals lifted straight out of the binary). Never fail an export over a
  # stray byte.
  db.text_factory = lambda raw: raw.decode("utf8", "replace")
  return db


def safe_name(name):
  """
  A file name component that survives every filesystem we care about.
  """
  cleaned = _UNSAFE_CHARS.sub("_", name or "")
  return cleaned[:80] if cleaned else "unnamed"


def hex_to_decimal(address):
  """
  Diaphora stores addresses as "%08x" in the results database but as decimal
  strings in the functions tables of the exported databases.
  """
  return str(int(address, 16))


def hex_ea(address):
  """
  The zero-padded "%08x" of the results database as a plain 0x address.
  """
  return "0x%x" % int(address, 16)


def as_text(value):
  """
  Diaphora stores the md5 as the raw 16-byte digest, which is not JSON. Turn
  any blob into something printable, leaving real text alone.
  """
  if isinstance(value, (bytes, bytearray)):
    return value.hex()
  return value


def program_info(db):
  """
  The md5/processor row Diaphora writes for every exported database.
  """
  info = {"md5sum": None, "processor": None, "functions": None}
  try:
    row = db.execute("select md5sum, processor from program").fetchone()
    if row is not None:
      info["md5sum"] = as_text(row["md5sum"])
      info["processor"] = as_text(row["processor"])
  except sqlite3.Error:
    pass

  try:
    row = db.execute("select count(*) as total from functions").fetchone()
    info["functions"] = row["total"]
  except sqlite3.Error:
    pass

  return info


def function_body(db, address):
  """
  The text a function is diffed as: its prototype followed by its
  pseudo-code, or by its assembly when the database was exported without a
  decompiler.

  Returns a (text, kind) tuple, both None when the function is unknown.
  """
  row = db.execute(
    "select prototype, pseudocode, assembly from functions where address = ?",
    (hex_to_decimal(address),),
  ).fetchone()
  if row is None:
    return None, None

  for kind in ("pseudocode", "assembly"):
    code = row[kind]
    if code:
      parts = [part for part in (row["prototype"], code) if part]
      return "\n".join(parts), kind

  return None, None


def read_matches(results, min_ratio):
  """
  Every row of the results table, normalised and oriented as new vs old.
  """
  matches = []
  for row in results.execute("select * from results"):
    ratio = float(row["ratio"])
    if ratio < min_ratio:
      continue

    matches.append(
      {
        "type": row["type"],
        "ratio": ratio,
        "heuristic": row["description"],
        "identical": ratio >= 1.0,
        "new": {
          "ea": hex_ea(row["address"]),
          "name": row["name"],
          "nodes": int(row["nodes1"]),
        },
        "old": {
          "ea": hex_ea(row["address2"]),
          "name": row["name2"],
          "nodes": int(row["nodes2"]),
        },
        "_address": row["address"],
        "_address2": row["address2"],
        "diff_file": None,
      }
    )

  matches.sort(
    key=lambda m: (
      TYPE_ORDER.index(m["type"]) if m["type"] in TYPE_ORDER else len(TYPE_ORDER),
      -m["ratio"],
      m["new"]["name"] or "",
    )
  )
  return matches


def read_unmatched(results):
  """
  Functions present on one side only, split by side.
  """
  only_new = []
  only_old = []
  for row in results.execute("select * from unmatched"):
    entry = {"ea": hex_ea(row["address"]), "name": row["name"]}
    if row["type"] == "primary":
      only_new.append(entry)
    else:
      only_old.append(entry)

  only_new.sort(key=lambda e: e["name"] or "")
  only_old.sort(key=lambda e: e["name"] or "")
  return only_new, only_old


def write_diffs(matches, new_db, old_db, outdir, max_diffs, context):
  """
  Write a unified diff per changed function, most changed first so that the
  --max-diffs budget is spent where it matters.

  Mutates the matches in place to record the diff file each one got, and
  returns a dict of counts.
  """
  changed_dir = os.path.join(outdir, "changed")
  os.makedirs(changed_dir, exist_ok=True)

  # Re-running with other options yields a different set of files, and the
  # numbering shifts. Drop the previous ones, so that nothing is left in
  # changed/ that index.jsonl does not account for.
  for stale in os.listdir(changed_dir):
    if stale.endswith(".diff"):
      os.remove(os.path.join(changed_dir, stale))

  candidates = sorted(
    (m for m in matches if not m["identical"]),
    key=lambda m: (m["ratio"], m["new"]["name"] or ""),
  )

  written = 0
  unchanged_body = 0
  no_body = 0
  budget_reached = False
  index_path = os.path.join(changed_dir, "index.jsonl")
  with open(index_path, "w", encoding="utf8", newline="\n") as index:
    for match in candidates:
      if written >= max_diffs:
        budget_reached = True
        break

      new_text, new_kind = function_body(new_db, match["_address"])
      old_text, old_kind = function_body(old_db, match["_address2"])
      if new_text is None or old_text is None:
        no_body += 1
        continue

      lines = list(
        difflib.unified_diff(
          old_text.splitlines(),
          new_text.splitlines(),
          fromfile="old/%s" % match["old"]["name"],
          tofile="new/%s" % match["new"]["name"],
          n=context,
          lineterm="",
        )
      )
      if not lines:
        # The ratio also accounts for features that are not part of the text
        # we diff here, so a changed function can still have an identical
        # body.
        match["body_identical"] = True
        unchanged_body += 1
        continue

      relative = "changed/%05d_%s.diff" % (written + 1, safe_name(match["new"]["name"]))
      with open(os.path.join(outdir, relative), "w", encoding="utf8", newline="\n") as fh:
        fh.write("\n".join(lines))
        fh.write("\n")

      match["diff_file"] = relative
      match["body"] = new_kind if new_kind == old_kind else f"{old_kind} -> {new_kind}"
      written += 1

      index.write(
        json.dumps(
          {
            "diff_file": relative,
            "type": match["type"],
            "ratio": match["ratio"],
            "heuristic": match["heuristic"],
            "new_name": match["new"]["name"],
            "old_name": match["old"]["name"],
          },
          ensure_ascii=False,
        )
      )
      index.write("\n")

  skipped = len(candidates) - written - unchanged_body - no_body if budget_reached else 0
  return {
    "diffs_written": written,
    "diffs_skipped": max(0, skipped),
    "body_identical": unchanged_body,
    "body_missing": no_body,
  }


def write_jsonl(path, records):
  with open(path, "w", encoding="utf8", newline="\n") as fh:
    for record in records:
      fh.write(json.dumps(record, ensure_ascii=False))
      fh.write("\n")


def reference(path, outdir):
  """
  Paths are nicer to follow when they stay inside the output folder.
  """
  absolute = os.path.abspath(path)
  try:
    relative = os.path.relpath(absolute, os.path.abspath(outdir))
  except ValueError:
    return absolute
  return relative.replace(os.sep, "/") if not relative.startswith("..") else absolute


def write_summary(path, ctx):
  counts = ctx["counts"]
  lines = [
    "# Diaphora diff: %s vs %s" % (ctx["new_label"], ctx["old_label"]),
    "",
    "Generated %s by `diaphora_ai_export.py`." % ctx["generated_at"],
    "",
    "## Orientation",
    "",
    "- **new** = `%s` (md5 `%s`) -- the binary being analysed." % (ctx["new_label"], ctx["new_info"]["md5sum"]),
    "- **old** = `%s` (md5 `%s`) -- the reference binary." % (ctx["old_label"], ctx["old_info"]["md5sum"]),
    "",
    "Every diff reads old -> new: `-` lines were removed, `+` lines were added.",
    "",
    "## Counts",
    "",
    "| | |",
    "|---|---|",
    "| Functions in new | %s |" % ctx["new_info"]["functions"],
    "| Functions in old | %s |" % ctx["old_info"]["functions"],
    "| Matches | %d |" % counts["matches"],
  ]
  for name in TYPE_ORDER:
    if counts["by_type"].get(name):
      lines.append("| &nbsp;&nbsp;%s | %d |" % (name, counts["by_type"][name]))
  lines += [
    "| Identical (ratio 1.0) | %d |" % counts["identical"],
    "| Added (only in new) | %d |" % counts["only_new"],
    "| Removed (only in old) | %d |" % counts["only_old"],
    "| Diff files written | %d |" % counts["diffs_written"],
  ]
  if counts["diffs_skipped"]:
    lines.append("| Diffs skipped (--max-diffs) | %d |" % counts["diffs_skipped"])
  if counts["body_identical"]:
    lines.append("| Changed but same body | %d |" % counts["body_identical"])
  if counts["body_missing"]:
    lines.append("| No body exported | %d |" % counts["body_missing"])

  lines += [
    "",
    "## Files",
    "",
    "- `matches.jsonl` -- one JSON object per match: type, ratio, heuristic, and the",
    "  `new`/`old` address, name and basic-block count. `diff_file` points at the diff",
    "  when there is one.",
    "- `unmatched_primary.jsonl` -- functions that exist only in the **new** binary.",
    "- `unmatched_secondary.jsonl` -- functions that exist only in the **old** binary.",
    "- `changed/index.jsonl` -- the catalogue of diff files.",
    "- `changed/*.diff` -- unified diff of the decompiled (or disassembled) function.",
    "- `manifest.json` -- machine-readable version of everything on this page.",
    "- `db/*.sqlite` -- the raw Diaphora databases, for SQL queries the files above",
    "  do not answer. `results.results(type, address, name, address2, name2, ratio,",
    "  description)` holds the matches, where `address`/`name` is the new side and",
    "  `address2`/`name2` the old one; `{new,old}.functions` holds everything that was",
    "  exported per function, with `address` stored as a **decimal** string there and",
    "  as **hex** in `results`.",
    "",
    "## Most changed functions",
    "",
  ]

  changed = [m for m in ctx["matches"] if m.get("diff_file")]
  changed.sort(key=lambda m: m["ratio"])
  if not changed:
    lines.append("None: every match is identical.")
  else:
    lines += [
      "| Ratio | New | Old | Heuristic | Diff |",
      "|---|---|---|---|---|",
    ]
    for match in changed[:SUMMARY_ROWS]:
      lines.append(
        "| %.4f | `%s` | `%s` | %s | [%s](%s) |"
        % (
          match["ratio"],
          match["new"]["name"],
          match["old"]["name"],
          match["heuristic"],
          os.path.basename(match["diff_file"]),
          match["diff_file"],
        )
      )
    if len(changed) > SUMMARY_ROWS:
      lines.append("")
      lines.append(
        "%d more in `changed/index.jsonl`." % (len(changed) - SUMMARY_ROWS)
      )

  for title, key, filename in (
    ("Added (only in new)", "only_new", "unmatched_primary.jsonl"),
    ("Removed (only in old)", "only_old", "unmatched_secondary.jsonl"),
  ):
    entries = ctx[key]
    lines += ["", "## %s" % title, ""]
    if not entries:
      lines.append("None.")
      continue
    for entry in entries[:SUMMARY_ROWS]:
      lines.append("- `%s` at %s" % (entry["name"], entry["ea"]))
    if len(entries) > SUMMARY_ROWS:
      lines.append("")
      lines.append("%d more in `%s`." % (len(entries) - SUMMARY_ROWS, filename))

  with open(path, "w", encoding="utf8", newline="\n") as fh:
    fh.write("\n".join(lines))
    fh.write("\n")


def main():
  parser = argparse.ArgumentParser(
    description="Export a Diaphora diffing session as AI-readable text."
  )
  parser.add_argument("--results", required=True, help="results sqlite from diaphora.py")
  parser.add_argument("--new", required=True, help="exported sqlite of the new binary")
  parser.add_argument("--old", required=True, help="exported sqlite of the old binary")
  parser.add_argument("--outdir", required=True, help="directory to write into")
  parser.add_argument(
    "--max-diffs", type=int, default=2000,
    help="stop after this many diff files, lowest ratio first (default: 2000)"
  )
  parser.add_argument(
    "--context", type=int, default=3, help="diff context lines (default: 3)"
  )
  parser.add_argument(
    "--min-ratio", type=float, default=0.0,
    help="drop matches below this ratio entirely (default: keep everything)"
  )
  parser.add_argument("--new-label", default=None, help="display name of the new binary")
  parser.add_argument("--old-label", default=None, help="display name of the old binary")
  args = parser.parse_args()

  os.makedirs(args.outdir, exist_ok=True)

  results = connect(args.results)
  new_db = connect(args.new)
  old_db = connect(args.old)

  try:
    matches = read_matches(results, args.min_ratio)
    only_new, only_old = read_unmatched(results)

    diff_counts = write_diffs(
      matches, new_db, old_db, args.outdir, args.max_diffs, args.context
    )

    new_info = program_info(new_db)
    old_info = program_info(old_db)
  finally:
    results.close()
    new_db.close()
    old_db.close()

  for match in matches:
    del match["_address"]
    del match["_address2"]

  write_jsonl(os.path.join(args.outdir, "matches.jsonl"), matches)
  write_jsonl(os.path.join(args.outdir, "unmatched_primary.jsonl"), only_new)
  write_jsonl(os.path.join(args.outdir, "unmatched_secondary.jsonl"), only_old)

  by_type = {}
  for match in matches:
    by_type[match["type"]] = by_type.get(match["type"], 0) + 1

  counts = {
    "matches": len(matches),
    "by_type": by_type,
    "identical": sum(1 for m in matches if m["identical"]),
    "only_new": len(only_new),
    "only_old": len(only_old),
  }
  counts.update(diff_counts)

  ctx = {
    "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    "new_label": args.new_label or os.path.basename(args.new),
    "old_label": args.old_label or os.path.basename(args.old),
    "new_info": new_info,
    "old_info": old_info,
    "counts": counts,
    "matches": matches,
    "only_new": only_new,
    "only_old": only_old,
  }

  manifest = {
    "generated_at": ctx["generated_at"],
    "orientation": {
      "new": "primary side of the results table (address, name, nodes1)",
      "old": "secondary side of the results table (address2, name2, nodes2)",
      "diff_direction": "old -> new",
    },
    "new": dict(new_info, label=ctx["new_label"], sqlite=reference(args.new, args.outdir)),
    "old": dict(old_info, label=ctx["old_label"], sqlite=reference(args.old, args.outdir)),
    "results_sqlite": reference(args.results, args.outdir),
    "counts": counts,
    "options": {
      "max_diffs": args.max_diffs,
      "context": args.context,
      "min_ratio": args.min_ratio,
    },
  }
  with open(os.path.join(args.outdir, "manifest.json"), "w", encoding="utf8") as fh:
    json.dump(manifest, fh, indent=1, ensure_ascii=False)
    fh.write("\n")

  write_summary(os.path.join(args.outdir, "summary.md"), ctx)

  print(
    "[ai-export] %d matches (%d identical), %d added, %d removed, %d diff file(s)"
    % (counts["matches"], counts["identical"], counts["only_new"],
       counts["only_old"], counts["diffs_written"])
  )
  if counts["diffs_skipped"]:
    print(
      "[ai-export] %d diff(s) skipped, raise --max-diffs to get them"
      % counts["diffs_skipped"]
    )


if __name__ == "__main__":
  main()
