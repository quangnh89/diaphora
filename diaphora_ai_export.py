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


# ---------------------------------------------------------------------------
# Comparing disassembly without comparing names
#
# Diaphora's `clean_assembly` replaces IDA's *auto-generated* names (sub_,
# dword_, loc_, ...) with a placeholder but leaves names a human gave alone.
# That is fine when both databases are annotated to the same degree, and
# useless here: the old database has names, types and struct fields everywhere
# and the new one mostly does not, so every annotated operand reads as a
# change. Measured on hvax64 9711 -> 9836, of the 1157 matches whose bytes
# differ, 1054 (91%) differed only in annotation:
#
#   frame member names + size prefixes      692
#   named global vs placeholder             121
#   same family one level deeper            239
#   genuinely different code                103
#
# So canonicalise both sides the same way first, then align the two line lists
# and only call a difference cosmetic when it really is one-sided annotation.
# ---------------------------------------------------------------------------

try:
  import diaphora_config as _config
  _AUTO_PREFIXES = tuple(_config.CLEANING_CMP_REPS)
except ImportError:
  # This exporter is documented as runnable on nothing but the sqlite files,
  # so it must not hard-depend on the rest of the checkout.
  _AUTO_PREFIXES = ("loc_", "j_nullsub_", "nullsub_", "j_sub_", "sub_", "qword_",
                    "dword_", "byte_", "word_", "off_", "def_", "unk_", "asc_",
                    "stru_", "dbl_", "locret_", "flt_", "jpt_")

# What get_cmp_asm leaves where an auto-generated name used to be.
_PLACEHOLDER = re.compile(r"\bXXXX\b", re.I)

# A size prefix. get_cmp_asm is supposed to drop these; it only manages it for
# databases exported after the fix to its CLEANING_CMP_REMS loop, which used to
# require hexadecimal digits right after the prefix. Handle them here too so
# that an older export still classifies correctly.
_SIZE_PREFIX = re.compile(
  r"\b(?:byte|word|dword|qword|oword|tbyte|xmmword|ymmword|zmmword|fword)\s+ptr\s+",
  re.I,
)

# A whole stack frame reference: "[rsp+XXXX+var_38]", "[rsp+XXXX+a2+4]",
# "[rbp+flag]". The member name and any sub-offset inside it say nothing about
# the instruction -- get_cmp_asm has already blanked the frame size, so the
# name was all that distinguished them.
_FRAME_REF = re.compile(r"\[(r[sb]p|e[sb]p)\+[^\]]*\]", re.I)

# An operand IDA renders through a struct field, "(_HV_VP.Field-14h)", because
# a type was applied to it. The other side shows a plain number.
_STRUCT_OFF = re.compile(r"\(\s*[A-Za-z_][\w:]*\.[\w.]*\s*[-+]\s*[0-9A-Fa-f]+h\s*\)")

# The "_0", "_1", ... IDA appends to a ported name that was already taken.
#
# This also strips a numeric suffix that was always part of the name, so in
# principle `g_Table_2` and `g_Table_3` compare equal. It is safe in this
# pipeline because the new database's names come from porting the old one's:
# a name that differs only by such a suffix is the collision artifact, not two
# different symbols. Numbered string literals, the other case where this could
# bite, get folded to `aXXX` by get_cmp_asm long before we see them.
_DUP_SUFFIX = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*?)_\d+\b")

# "cs:name", "gs:name.Field+100h".
_SEG_SYMBOL = re.compile(r"\b([a-z]s):([A-Za-z_][\w.]*)(\+[0-9A-Fa-f]+h)?", re.I)

# A bare symbol as the operand right after the mnemonic, as in
# "lea rdx, g_HvXsaveFieldRegions.Offset+18h" -- except that only the first
# operand is reached, so `mov rax, g_Foo` is left alone. That makes the
# comparison give up and report `changed` rather than forgive something it
# should not, which is the right way round to be wrong here.
_SYMBOL_OPERAND = re.compile(
  r"\b(call|jmp|lea|mov|push|cmp|test|add|sub|and|or|xor)(\s+)([A-Za-z_][\w.]{3,})\b",
  re.I,
)

_SPACES = re.compile(r"\s+")

# Verdicts that mean the instructions are the same, strongest first.
SAME_CODE = ("same-bytes", "same-asm", "same-asm-annotated")

# A match this weak is more likely a wrong pairing than a rewritten function.
SUSPECT_SIMILARITY = 0.50


def canon_line(line):
  """
  One disassembly line reduced to what it says about the machine, dropping
  what it says about how the database is annotated.
  """
  text = _SIZE_PREFIX.sub("", line)
  text = _STRUCT_OFF.sub("+OFF", text)
  text = _FRAME_REF.sub(lambda m: "[%s+FRAME]" % m.group(1).lower(), text)
  text = _DUP_SUFFIX.sub(r"\1", text)
  return _SPACES.sub(" ", text).strip().lower()


def _abstract_line(line):
  """
  canon_line with every symbol reference flattened to one token, so that two
  lines referring to *a* symbol compare equal whatever it is called.
  """
  text = _SEG_SYMBOL.sub(lambda m: "%s:SYM" % m.group(1).lower(), canon_line(line))
  text = _PLACEHOLDER.sub("SYM", text)
  return _SYMBOL_OPERAND.sub(r"\1\2SYM", text)


def _annotation_only(old_line, new_line):
  """
  Do these two lines differ *only* because one side names something the other
  left auto-generated?

  Both conditions have to hold: the lines must be equal once every symbol is
  flattened, and exactly one side must be the annotated one. So `g_A` against
  `g_B` -- both named -- is still a change, and only the one-sided case is
  forgiven.
  """
  if _abstract_line(old_line) != _abstract_line(new_line):
    return False

  old_canon = canon_line(old_line)
  new_canon = canon_line(new_line)
  old_auto = bool(_PLACEHOLDER.search(old_canon))
  new_auto = bool(_PLACEHOLDER.search(new_canon))
  if old_auto != new_auto:
    return True

  old_named = old_auto or bool(_SEG_SYMBOL.search(old_canon))
  new_named = new_auto or bool(_SEG_SYMBOL.search(new_canon))
  return old_named != new_named


def asm_verdict(old_asm, new_asm):
  """
  Compare two normalised disassembly texts. Returns (verdict, similarity),
  where similarity is measured on the canonical form and is what decides
  whether a match looks wrong rather than changed.
  """
  old_lines = old_asm.split("\n")
  new_lines = new_asm.split("\n")
  old_canon = [canon_line(line) for line in old_lines]
  new_canon = [canon_line(line) for line in new_lines]
  if old_canon == new_canon:
    return "same-asm", 1.0

  matcher = difflib.SequenceMatcher(None, old_canon, new_canon)
  for op, i1, i2, j1, j2 in matcher.get_opcodes():
    if op == "equal":
      continue
    # An inserted or deleted instruction is a real change, and so is a
    # replacement that does not line up one for one.
    if op != "replace" or (i2 - i1) != (j2 - j1):
      return "changed", matcher.ratio()
    for old_line, new_line in zip(old_lines[i1:i2], new_lines[j1:j2]):
      if not _annotation_only(old_line, new_line):
        return "changed", matcher.ratio()

  return "same-asm-annotated", matcher.ratio()


def code_verdict(new_row, old_row):
  """
  Did the machine code change, independently of how it is rendered? Returns
  (verdict, similarity) where the verdict is one of:

    same-bytes   identical instruction bytes. Proof.
    same-asm     identical disassembly once both sides are canonicalised:
                 comments, symbol names, addresses, size prefixes, stack frame
                 member names and struct-field operands removed; registers and
                 immediate values kept.
    same-asm-annotated
                 identical except where one database names something the other
                 does not. This is the asymmetry the porting step exists to
                 remove, and it cannot be avoided entirely: a name only reaches
                 the new database for a function Diaphora matched.
    changed      the instructions differ.
    unknown      one side was not exported.

  Deliberately NOT based on the `mnemonics` column: that one is the list of
  mnemonics alone, with the operands dropped, so it cannot tell `mov eax`
  from `mov ecx` and would hide a real change.
  """
  if new_row is None or old_row is None:
    return "unknown", 0.0

  if new_row["bytes_hash"] and new_row["bytes_hash"] == old_row["bytes_hash"]:
    return "same-bytes", 1.0

  new_asm = new_row["clean_assembly"]
  old_asm = old_row["clean_assembly"]
  if not new_asm or not old_asm:
    return "unknown", 0.0
  return asm_verdict(old_asm, new_asm)


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


def read_unmatched(results, new_db, old_db):
  """
  Functions present on one side only, split by side.

  Derived from the function tables minus the matched addresses rather than
  read out of the results database's `unmatched` table, because that table's
  `type` column is inverted. `find_unmatched()` in diaphora.py fills a chooser
  from `functions` (main, the NEW side) and assigns it to
  `self.unmatched_second`, and one from `diff.functions` (OLD) assigned to
  `self.unmatched_primary`; `save_results` then writes `type` from those
  attribute names. Measured on a real pair of builds: all 221 rows marked
  `primary` existed in OLD, and all 11 marked `secondary` existed in NEW.

  Working from the tables is also stricter than Diaphora's own name-based
  matching, and it stays correct whatever the `type` column ends up saying.
  """
  matched_new = set()
  matched_old = set()
  # Every row, not just the ones read_matches kept: a match dropped by
  # --min-ratio is still a match, and must not be reported as added/removed.
  for row in results.execute("select address, address2 from results"):
    matched_new.add(int(row["address"], 16))
    matched_old.add(int(row["address2"], 16))

  def only_in(db, matched):
    entries = []
    for row in db.execute("select address, name from functions"):
      # `functions.address` is a decimal string, `results.address` is hex.
      address = int(row["address"])
      if address not in matched:
        entries.append({"ea": "0x%x" % address, "name": row["name"]})
    entries.sort(key=lambda entry: entry["name"] or "")
    return entries

  return only_in(new_db, matched_new), only_in(old_db, matched_old)


def classify_matches(matches, new_db, old_db):
  """
  Answer "did the machine code change" for every match, including the ones
  that need no diff, so that a consumer can filter on it without having to
  reason about ratios.

  Also flags the matches that look like a wrong pairing rather than a changed
  function: a different number of basic blocks *and* a canonical similarity
  below SUSPECT_SIMILARITY. Both conditions together, so that a function which
  really was rewritten is not dismissed as a bad match.
  """
  for match in matches:
    verdict, similarity = code_verdict(
      code_row(new_db, match["_address"]),
      code_row(old_db, match["_address2"]),
    )
    match["code"] = verdict
    match["code_changed"] = verdict not in SAME_CODE
    match["asm_similarity"] = round(similarity, 4)
    match["suspect"] = bool(
      match["code_changed"]
      and match["new"]["nodes"] != match["old"]["nodes"]
      and similarity < SUSPECT_SIMILARITY
    )


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
  changed/, so that changed/ means what it says, and the ones that look like a
  wrong pairing go to suspect/ so they do not drown the real changes. The ones
  that did change also get a diff of the normalised assembly next to the
  pseudo-code one: the question is always "did the code change" before "how
  does it read".

  Mutates the matches in place to record the verdict and the diff file each
  one got, and returns a dict of counts.
  """
  buckets = {
    "changed": os.path.join(outdir, "changed"),
    "cosmetic": os.path.join(outdir, "cosmetic"),
    "suspect": os.path.join(outdir, "suspect"),
  }
  for directory in buckets.values():
    os.makedirs(directory, exist_ok=True)
    _clear_diffs(directory)

  # A ratio of 1.0 normally means there is nothing to show. It is not a
  # guarantee though: check_ratio() rounds, and takes the best of several
  # representations, so a function whose instructions really did change can
  # still come back as 1.0 -- patching six immediates in a test binary
  # produced five such matches, every one of them reported as `changed` and
  # none of them getting a diff. So the machine level verdict overrides the
  # ratio here: if the code changed, it gets written.
  candidates = sorted(
    (m for m in matches if not m["identical"] or m["code_changed"]),
    key=lambda m: (m["ratio"], m["new"]["name"] or ""),
  )

  counters = {"changed": 0, "cosmetic": 0, "suspect": 0}
  unchanged_body = 0
  no_body = 0
  budget_reached = False

  indexes = {}
  try:
    for name, directory in buckets.items():
      indexes[name] = open(
        os.path.join(directory, "index.jsonl"), "w", encoding="utf8", newline="\n"
      )

    for match in candidates:
      if sum(counters.values()) >= max_diffs:
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

      if not match["code_changed"]:
        bucket = "cosmetic"
      elif match["suspect"]:
        bucket = "suspect"
      else:
        bucket = "changed"
      counters[bucket] += 1

      relative = "%s/%05d_%s.diff" % (bucket, counters[bucket], safe_name(new_label))
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
        "asm_similarity": match["asm_similarity"],
      }
      if match["suspect"]:
        record["suspect"] = True
        record["nodes"] = {"new": match["new"]["nodes"], "old": match["old"]["nodes"]}

      if match["code_changed"]:
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

      indexes[bucket].write(json.dumps(record, ensure_ascii=False))
      indexes[bucket].write("\n")
  finally:
    for handle in indexes.values():
      handle.close()

  accounted = sum(counters.values()) + unchanged_body + no_body
  skipped = len(candidates) - accounted if budget_reached else 0
  return {
    "diffs_written": counters["changed"],
    "cosmetic": counters["cosmetic"],
    "suspect": counters["suspect"],
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
  ]
  if ctx.get("baseline"):
    lines += [
      "## Baseline run",
      "",
      "Nothing was ported. These are plain Diaphora's own numbers on the two",
      "databases as they were, which makes them the reference to compare a",
      "ported run against. Expect more `changed` here than after a port: the",
      "old database is annotated and the new one is not, and that asymmetry is",
      "exactly what porting removes.",
      "",
    ]
  lines += [
    "## Did the code change, or only the way it reads?",
    "",
    "Every match carries `code_changed` and the `code` verdict behind it:",
    "",
    "| `code` | Means |",
    "|---|---|",
    "| `same-bytes` | Identical instruction bytes. Proof. |",
    "| `same-asm` | Identical disassembly once both sides are canonicalised: comments, symbol names, addresses, size prefixes, stack frame member names and struct-field operands removed; registers and immediates kept. |",
    "| `same-asm-annotated` | Identical except where one database names something the other left auto-generated. A name only reaches the new database for a function Diaphora matched, so some of this asymmetry is unavoidable. A rename from one *named* symbol to another is still `changed`. |",
    "| `changed` | The instructions differ. |",
    "",
    "`asm_similarity` on each match is how alike the two canonical forms are.",
    "",
    "The per-function diffs are split on it:",
    "",
    "- `changed/` -- the instructions differ. Each one also has a `.asm.diff`",
    "  next to it, so you can read the machine level change before the C.",
    "  **Start here.**",
    "- `cosmetic/` -- same instructions, different rendering: a name, a type, a",
    "  local variable or a struct field that exists on one side only.",
    "- `suspect/` -- the instructions differ, but the two sides also have a",
    "  different number of basic blocks and an `asm_similarity` below %.2f."
    % SUSPECT_SIMILARITY,
    "  Much more likely a function Diaphora paired wrongly than one that was",
    "  rewritten. These were still imported by the porting step, so a name or",
    "  type in the new database that looks wrong is worth checking against this",
    "  list.",
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
    "| Suspect (probably a wrong pairing) | %d |" % counts["suspect"],
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
    "  `code`/`code_changed`/`asm_similarity`/`suspect`, and the `new`/`old`",
    "  address, name and basic-block count. `diff_file` points at the diff when",
    "  there is one.",
    "- `unmatched_primary.jsonl` -- functions that exist only in the **new** binary.",
    "- `unmatched_secondary.jsonl` -- functions that exist only in the **old** binary.",
    "  Both are derived from the two function tables minus the matched addresses,",
    "  not from the `unmatched` table of `results.sqlite`, whose `type` column is",
    "  inverted (`primary` there is in fact the old side).",
    "- `changed/index.jsonl`, `cosmetic/index.jsonl`, `suspect/index.jsonl` -- the",
    "  catalogue of each bucket.",
    "- `changed/*.diff` -- unified diff of the decompiled (or disassembled) function.",
    "- `changed/*.asm.diff` -- the same function's normalised disassembly.",
    "- `cosmetic/*.diff` -- functions whose instructions did not change.",
    "- `suspect/*.diff` -- matches that look like a wrong pairing.",
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
    if m.get("diff_file") and m.get("code_changed") and not m.get("suspect")
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

  suspect = [m for m in ctx["matches"] if m.get("suspect")]
  if suspect:
    suspect.sort(key=lambda m: m["asm_similarity"])
    lines += [
      "",
      "## Suspect matches",
      "",
      "Different number of basic blocks *and* an `asm_similarity` below %.2f."
      % SUSPECT_SIMILARITY,
      "Probably paired wrongly by Diaphora. They were imported anyway, so check",
      "these before trusting a name or type in the new database that looks off.",
      "",
      "| Similarity | Ratio | New | Old | Nodes new/old | Heuristic |",
      "|---|---|---|---|---|---|",
    ]
    for match in suspect[:SUMMARY_ROWS]:
      lines.append(
        "| %.4f | %.4f | `%s` | `%s` | %d/%d | %s |"
        % (
          match["asm_similarity"],
          match["ratio"],
          match["new"]["name"],
          match["old"]["name"],
          match["new"]["nodes"],
          match["old"]["nodes"],
          match["heuristic"],
        )
      )
    if len(suspect) > SUMMARY_ROWS:
      lines.append("")
      lines.append("%d more in `suspect/index.jsonl`." % (len(suspect) - SUMMARY_ROWS))

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
  parser.add_argument(
    "--baseline", action="store_true",
    help="record that nothing was ported, so these numbers are plain Diaphora's"
  )
  args = parser.parse_args()

  os.makedirs(args.outdir, exist_ok=True)

  results = connect(args.results)
  new_db = connect(args.new)
  old_db = connect(args.old)

  try:
    matches = read_matches(results, args.min_ratio)
    only_new, only_old = read_unmatched(results, new_db, old_db)

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
    "suspect_matches": sum(1 for m in matches if m.get("suspect")),
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
    "baseline": args.baseline,
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
      "baseline": args.baseline,
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
  print(
    "[ai-export] code: %s"
    % ", ".join(
      "%s %d" % (verdict, counts["by_code"][verdict])
      for verdict in SAME_CODE + ("changed", "unknown")
      if counts["by_code"].get(verdict)
    )
  )
  if counts["suspect"]:
    print(
      "[ai-export] %d match(es) look like a wrong pairing, see suspect/"
      % counts["suspect"]
    )
  if counts["diffs_skipped"]:
    print(
      "[ai-export] %d diff(s) skipped, raise --max-diffs to get them"
      % counts["diffs_skipped"]
    )


if __name__ == "__main__":
  main()
