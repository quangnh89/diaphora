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


def function_row(db, address):
  """
  Everything this exporter needs about one function, or None.
  """
  return db.execute(
    "select prototype, pseudocode, assembly, clean_assembly, bytes_hash"
    " from functions where address = ?",
    (hex_to_decimal(address),),
  ).fetchone()


def function_body(row):
  """
  The text a function is diffed as: its prototype followed by its
  pseudo-code, or by its assembly when the database was exported without a
  decompiler.

  Returns a (text, kind) tuple, both None when there is nothing to diff.
  """
  if row is None:
    return None, None

  for kind in ("pseudocode", "assembly"):
    code = row[kind]
    if code:
      parts = [part for part in (row["prototype"], code) if part]
      return "\n".join(parts), kind

  return None, None


def code_row(db, address):
  """
  Just the two columns the machine level verdict needs.
  """
  return db.execute(
    "select clean_assembly, bytes_hash from functions where address = ?",
    (hex_to_decimal(address),),
  ).fetchone()


# A stack operand that survived Diaphora's normaliser as "[rsp+XXXX+name]".
_STACK_MEMBER = re.compile(r"\+[A-Za-z_][A-Za-z0-9_]*\]")

# Verdicts that mean the instructions are the same, strongest first.
SAME_CODE = ("same-bytes", "same-asm", "same-asm-renamed-stack")


def code_verdict(new_row, old_row):
  """
  Did the machine code change, independently of how it is rendered? One of:

    same-bytes   identical instruction bytes. Proof.
    same-asm     identical normalised disassembly. `clean_assembly` is
                 Diaphora's own (CBinDiff.get_cmp_asm): comments gone,
                 sub_/qword_/loc_/... names and addresses replaced by
                 placeholders, registers and immediate values kept.
    same-asm-renamed-stack
                 identical once the names of the stack frame members are
                 masked too. Those are not ported -- a slot the old database
                 calls `gpaOut` is still `arg_18` here -- so without this
                 an unchanged function reads as changed. Weaker than
                 same-asm: it cannot tell two different stack slots apart.
                 Note that get_cmp_asm has already replaced the numeric part
                 of the operand ("+48h+" -> "+XXXX+"), so the name was the
                 only thing left distinguishing them in the first place.
    changed      the instructions differ.
    unknown      one side was not exported.

  Deliberately NOT based on the `mnemonics` column: that one is the list of
  mnemonics alone, with the operands dropped, so it cannot tell `mov eax`
  from `mov ecx` and would hide a real change.
  """
  if new_row is None or old_row is None:
    return "unknown"

  if new_row["bytes_hash"] and new_row["bytes_hash"] == old_row["bytes_hash"]:
    return "same-bytes"

  new_asm = new_row["clean_assembly"]
  old_asm = old_row["clean_assembly"]
  if not new_asm or not old_asm:
    return "unknown"
  if new_asm == old_asm:
    return "same-asm"
  if _STACK_MEMBER.sub("+VAR]", new_asm) == _STACK_MEMBER.sub("+VAR]", old_asm):
    return "same-asm-renamed-stack"
  return "changed"


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


def classify_matches(matches, new_db, old_db):
  """
  Answer "did the machine code change" for every match, including the ones
  that need no diff, so that a consumer can filter on it without having to
  reason about ratios.
  """
  for match in matches:
    verdict = code_verdict(
      code_row(new_db, match["_address"]),
      code_row(old_db, match["_address2"]),
    )
    match["code"] = verdict
    match["code_changed"] = verdict not in SAME_CODE


def _unified(old_text, new_text, old_label, new_label, context):
  return list(
    difflib.unified_diff(
      old_text.splitlines(),
      new_text.splitlines(),
      fromfile="old/%s" % old_label,
      tofile="new/%s" % new_label,
      n=context,
      lineterm="",
    )
  )


def _write_text(path, lines):
  with open(path, "w", encoding="utf8", newline="\n") as fh:
    fh.write("\n".join(lines))
    fh.write("\n")


def _clear_diffs(directory):
  # Re-running with other options yields a different set of files, and the
  # numbering shifts. Drop the previous ones, so that nothing is left behind
  # that index.jsonl does not account for.
  if not os.path.isdir(directory):
    return
  for stale in os.listdir(directory):
    if stale.endswith(".diff"):
      os.remove(os.path.join(directory, stale))


def write_diffs(matches, new_db, old_db, outdir, max_diffs, context):
  """
  Write a unified diff per changed function, most changed first so that the
  --max-diffs budget is spent where it matters.

  Functions whose instructions are unchanged go to cosmetic/ instead of
  changed/, so that changed/ means what it says. The ones that did change
  also get a diff of the normalised assembly next to the pseudo-code one:
  the question is always "did the code change" before "how does it read".

  Mutates the matches in place to record the verdict and the diff file each
  one got, and returns a dict of counts.
  """
  changed_dir = os.path.join(outdir, "changed")
  cosmetic_dir = os.path.join(outdir, "cosmetic")
  os.makedirs(changed_dir, exist_ok=True)
  os.makedirs(cosmetic_dir, exist_ok=True)
  _clear_diffs(changed_dir)
  _clear_diffs(cosmetic_dir)

  candidates = sorted(
    (m for m in matches if not m["identical"]),
    key=lambda m: (m["ratio"], m["new"]["name"] or ""),
  )

  written = 0
  cosmetic = 0
  unchanged_body = 0
  no_body = 0
  budget_reached = False
  index_path = os.path.join(changed_dir, "index.jsonl")
  cosmetic_index_path = os.path.join(cosmetic_dir, "index.jsonl")

  with open(index_path, "w", encoding="utf8", newline="\n") as index, \
       open(cosmetic_index_path, "w", encoding="utf8", newline="\n") as cosmetic_index:
    for match in candidates:
      if written + cosmetic >= max_diffs:
        budget_reached = True
        break

      new_row = function_row(new_db, match["_address"])
      old_row = function_row(old_db, match["_address2"])
      new_text, new_kind = function_body(new_row)
      old_text, old_kind = function_body(old_row)
      if new_text is None or old_text is None:
        no_body += 1
        continue

      old_label = match["old"]["name"]
      new_label = match["new"]["name"]
      lines = _unified(old_text, new_text, old_label, new_label, context)
      if not lines:
        # The ratio also accounts for features that are not part of the text
        # we diff here, so a changed function can still have an identical
        # body.
        match["body_identical"] = True
        unchanged_body += 1
        continue

      if match["code_changed"]:
        bucket, number = "changed", written + 1
      else:
        bucket, number = "cosmetic", cosmetic + 1

      relative = "%s/%05d_%s.diff" % (bucket, number, safe_name(new_label))
      _write_text(os.path.join(outdir, relative), lines)
      match["diff_file"] = relative
      match["body"] = new_kind if new_kind == old_kind else f"{old_kind} -> {new_kind}"

      record = {
        "diff_file": relative,
        "type": match["type"],
        "ratio": match["ratio"],
        "heuristic": match["heuristic"],
        "new_name": new_label,
        "old_name": old_label,
        "code": match["code"],
      }

      if not match["code_changed"]:
        cosmetic += 1
        cosmetic_index.write(json.dumps(record, ensure_ascii=False))
        cosmetic_index.write("\n")
      else:
        # The instructions really differ: show them too, so the reader does
        # not have to infer the machine level change from the pseudo-code.
        asm_lines = _unified(
          old_row["clean_assembly"] or "",
          new_row["clean_assembly"] or "",
          old_label,
          new_label,
          context,
        )
        if asm_lines:
          asm_relative = relative[: -len(".diff")] + ".asm.diff"
          _write_text(os.path.join(outdir, asm_relative), asm_lines)
          record["asm_diff_file"] = asm_relative
          match["asm_diff_file"] = asm_relative

        written += 1
        index.write(json.dumps(record, ensure_ascii=False))
        index.write("\n")

  accounted = written + cosmetic + unchanged_body + no_body
  skipped = len(candidates) - accounted if budget_reached else 0
  return {
    "diffs_written": written,
    "cosmetic": cosmetic,
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
    "## Did the code change, or only the way it reads?",
    "",
    "Every match carries `code_changed` and the `code` verdict behind it:",
    "",
    "| `code` | Means |",
    "|---|---|",
    "| `same-bytes` | Identical instruction bytes. Proof. |",
    "| `same-asm` | Identical normalised disassembly: symbol names and addresses replaced by placeholders, registers and immediates kept. |",
    "| `same-asm-renamed-stack` | Identical once the stack frame member names are masked too. Those are never ported, so a slot the old database calls `gpaOut` is still `arg_18` here. Weaker: it cannot tell two different stack slots apart. |",
    "| `changed` | The instructions differ. |",
    "",
    "The per-function diffs are split on it:",
    "",
    "- `changed/` -- the instructions differ. Each one also has a `.asm.diff`",
    "  next to it, so you can read the machine level change before the C.",
    "- `cosmetic/` -- same instructions, different rendering: a name, a type, a",
    "  local variable or a struct field that exists on one side only.",
    "  **Start with `changed/`.**",
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
    "| Same instructions | %d |" % counts["same_code"],
    "| Diff files written (code changed) | %d |" % counts["diffs_written"],
    "| Cosmetic only | %d |" % counts["cosmetic"],
  ]
  for verdict in SAME_CODE + ("changed", "unknown"):
    if counts["by_code"].get(verdict):
      lines.append("| &nbsp;&nbsp;`%s` | %d |" % (verdict, counts["by_code"][verdict]))
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
    "- `matches.jsonl` -- one JSON object per match: type, ratio, heuristic,",
    "  `code`/`code_changed`, and the `new`/`old` address, name and",
    "  basic-block count. `diff_file` points at the diff when there is one.",
    "- `unmatched_primary.jsonl` -- functions that exist only in the **new** binary.",
    "- `unmatched_secondary.jsonl` -- functions that exist only in the **old** binary.",
    "- `changed/index.jsonl`, `cosmetic/index.jsonl` -- the catalogue of each bucket.",
    "- `changed/*.diff` -- unified diff of the decompiled (or disassembled) function.",
    "- `changed/*.asm.diff` -- the same function's normalised disassembly.",
    "- `cosmetic/*.diff` -- functions whose instructions did not change.",
    "- `port_report.json` -- what the porting step managed to carry over, when it ran.",
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
    "Only the ones whose instructions actually differ. The ratio was measured on",
    "the databases as they were diffed; if the porting step ran afterwards, the",
    "diff bodies below read with the ported names and types while the ratio does",
    "not reflect that.",
    "",
  ]

  changed = [
    m for m in ctx["matches"]
    if m.get("diff_file") and m.get("code_changed")
  ]
  changed.sort(key=lambda m: m["ratio"])
  if not changed:
    lines.append("None: no match differs at instruction level.")
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

    classify_matches(matches, new_db, old_db)
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
  by_code = {}
  for match in matches:
    by_type[match["type"]] = by_type.get(match["type"], 0) + 1
    verdict = match.get("code", "unknown")
    by_code[verdict] = by_code.get(verdict, 0) + 1

  counts = {
    "matches": len(matches),
    "by_type": by_type,
    "identical": sum(1 for m in matches if m["identical"]),
    "same_code": sum(1 for m in matches if not m.get("code_changed")),
    "by_code": by_code,
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
