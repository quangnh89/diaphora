# δiaphora

<p align='center'>
<img src="https://github.com/joxeankoret/diaphora/assets/2945834/3f1e9cf4-98d7-4d9a-b7d3-0a7354053b4e" width="10%">
</p>

## Installation

Install with the [Hex-Rays plugin manager](https://hcli.docs.hex-rays.com/user-guide/plugin-manager/):

    hcli plugin install https://github.com/joxeankoret/diaphora/archive/refs/tags/3.5.0.zip
    
Manual install: download the code and place it into your `plugins/` directory.

Diaphora (διαφορά, Greek for 'difference') version 3.5 is the most advanced program diffing tool (working as an IDA plugin) available as of today (2026). It was released in 2015 and has been actively maintained ever since: Diaphora has been ported for 11 years already to every single minor version of IDA since 6.8 to 9.5.

Diaphora supports versions of IDA >= 7.4 because the code only runs in Python 3.X (Python 3.11 was the last version being tested).

## Unique Features

Diaphora has many of the most common program diffing (bindiffing) features you might expect, like:

 * Diffing assembler.
 * Diffing control flow graphs.
 * Porting symbol names and comments.
 * Adding manual matches.
 * Similarity ratio calculation.
 * Batch automation.
 * Call graph matching calculation.
 * Dozens of heuristics based on graph theory, assembler, bytes, functions' features, etc...

However, Diaphora has also many features that are unique, not available in any other public tool. The following is a non extensive list of unique features:

 * Ability to port structs, enums, unions and typedefs.
 * Potentially fixed vulnerabilities detection for patch diffing sessions.
 * Support for compilation units (finding and diffing compilation units).
 * Microcode support.
 * Parallel diffing.
 * Pseudo-code based heuristics.
 * Pseudo-code patches generation.
 * Diffing pseudo-codes (with syntax highlighting!).
 * Scripting support (for both the exporting and diffing processes).
 * ...

## Donations

You can help (or thank) the author of Diaphora by making a donation. If you feel like doing so you can use one of the following links:

 * [![Liberapay](https://img.shields.io/liberapay/receives/diaphora.svg?logo=liberapay)](https://liberapay.com/Diaphora/donate)
 * [![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&amp;hosted_button_id=68Z4H8SE7N64L)

## Support

Feel free to open issues in Github if you have any problem or need help. If you prefer to chat interactively, you can use the following Discord channel: https://discord.gg/atg34w2xjV

## Licensing problems

If your company does not allow using the AGPL license you can get commercial licenses of Diaphora to use it in your company or to use it as a particular in any company you work (similar concept as IDA's named licenses). For more details, please contact me at admin@joxeankoret.com.

Please remember that it isn't me preventing you from using Diaphora: it's your company. Thank you for your understanding.

## Wiki

If you are looking how to automate the export or diffing process, or you want to speed operations, etc... You might want to take a look to the [wiki](https://github.com/joxeankoret/diaphora/wiki) where such questions are answered.

## Screenshots

Diaphora finding the exact function where a vulnerability was patched in CVE-2020-1350:

![CVE-2020-1350](https://files.mastodon.social/media_attachments/files/110/313/141/968/158/099/original/607189c509ec1cc4.png)

Diaphora, again, finding the exact function where CVE-2023-28231 was fixed:

![CVE-2023-28231](https://files.mastodon.social/media_attachments/files/110/313/148/945/529/051/original/28e032f21be414a3.png)

CVE-2023-28231. As explained in a blog from ZDI, the vulnerability was fixed by checking that the number of relay forward messages in "ProcessRelayForwardMessage()" is not bigger or equal than 32 (0x20), as shown in the following pseudo-code diffing:

![CVE-2023-28231](https://files.mastodon.social/media_attachments/files/110/300/368/934/189/808/original/fe3392db2b8234e9.png)

Diaphora doing Hex-Ray's microcode diffing:

![Diffing microcode in a graph](https://files.mastodon.social/media_attachments/files/110/157/157/910/926/533/original/6c5975e15c378cb5.png)

Diffing assembly, pseudo-code and microcode:

![Assembly, pseudo-code and microcode](https://files.mastodon.social/media_attachments/files/110/102/237/646/074/440/original/4a816df5069691c3.png)

Diffing CVE-2023-21768 with Diaphora 3.0:

![Diffing CVE-2023-21768 with #Diaphora 3.0](https://files.mastodon.social/media_attachments/files/110/066/930/153/215/408/original/86b06ae90d57d5a1.png)

This is a screenshot of Diaphora diffing the PEGASUS iOS kernel Vulnerability fixed in iOS 9.3.5:

![Diffing iOS 9.3.5 diff](http://sektioneins.de/images/diaphora1.png)

And this is an old screenshot of Diaphora diffing the [Microsoft bulletin MS15-034](https://technet.microsoft.com/en-us/library/security/ms15-034.aspx):

![Diaphora diffing MS15-034](https://pbs.twimg.com/media/CCnruP_W0AA8ksc.png:large)

These are some screenshots of Diaphora diffing the [Microsoft bulletin MS15-050]( https://technet.microsoft.com/en-us/library/security/ms15-050.aspx), extracted from the blog post [Analyzing MS15-050 With Diaphora](http://www.alex-ionescu.com/?p=271) from Alex Ionescu.

![Diaphora diffing MS15-050, best matches](http://www.alex-ionescu.com/wp-content/uploads/diaphora2.png)
![Diaphora diffing MS15-050, partial matches](http://www.alex-ionescu.com/wp-content/uploads/diaphora3.png)
![Diaphora diffing MS15-050, diffing pseudo-code](http://www.alex-ionescu.com/wp-content/uploads/diaphora1.png)

![Diaphora diffing a LuaBot, matches and pseudo-code](https://1.bp.blogspot.com/-O5UjSOyjCgg/V5byA-ozXVI/AAAAAAAABaY/yRTMDTSD9zI0mSy4AsHN21ZYf_YvctnkwCLcB/s1600/evs-compile.png)


Here is a screenshot of Diaphora diffing [iBoot from iOS 10.3.3 against iOS 11.0](https://blog.matteyeux.com/hacking/2018/04/04/diaphora-diff-and-ida.html):

![Diaphora diffing iBoot from iOS 10.3.3 against iOS 11.0](https://blog.matteyeux.com/images/newgraph.PNG)

---

# Windows automation script

This fork adds `diaphora_run.bat`, an unattended Diaphora pass over two IDA
databases. It drives IDA in batch mode and needs no interaction.

    diaphora_run.bat <old.i64|old.idb> <new.i64|new.idb> [outdir] [options]

It produces two things, and does both by default:

**Porting** copies function names, prototypes, function and instruction
comments, pseudo-code comments, struct/enum/union/typedef definitions, global
variable names and types, the Hex-Rays local variables (function arguments
included) and the Functions window folder layout from the old database into
the new one. The new database is modified in place, after a backup of it is
made and kept. `port_report.json` says how much of each actually went across.

Types — the local type definitions and the function prototypes — are
transferred in IDA's own serialized form rather than printed as C and parsed
back. That round trip is lossy: on a real pair of builds it dropped 155 of
2181 types, truncated every struct that had one of those as a member, and
took 378 prototypes down with it. Some of it cannot work at all that way,
since IDA prints a shifted pointer as `X *__shifted(Y,0x80)` and its own
parser will not read that back.

**The AI export** writes the diffing result as plain text an AI agent can read
directly: the matched and unmatched tables as JSONL, a unified diff of the
pseudo-code per changed function, a `summary.md`, and the raw `.sqlite`
databases for SQL queries.

| Option | Effect |
|---|---|
| *(none)* | Both: port into the new database and write the AI export |
| `--port` | Port only |
| `--ai` | AI export only |
| `--outdir DIR` | Where the AI export goes. Default: `<new>_vs_<old>.aidiff` next to the new database |
| `--no-folders` | Do not port the function folder layout |
| `--no-lvars` | Do not port the Hex-Rays local variables |
| `--no-frames` | Do not port the stack frame member names and types |
| `--no-create-funcs` | Do not create the functions that exist only in the old database |
| `--types all` \| `missing` | Replace a type the new database already has, or only fill in what is absent. Default `all` |
| `--no-types` | Leave the types to Diaphora's own C text path |
| `--no-protect-old` | Read the old database directly instead of a scratch copy |
| `--baseline` | Export, diff and write the AI export, but port nothing. Plain Diaphora's own numbers, for use as a reference. Cannot be combined with `--port` |
| `--force` | Export again even when a previous export is there |
| `-h`, `--help` | Usage |

## Two builds of the same module

The common case: the same binary one version apart, say `10.0.26100.9711` and
`10.0.26100.9838`, with the older one already analysed and named.

    diaphora_run.bat D:\work\old\module.i64 D:\work\new\module.i64

Both deliverables need the same expensive groundwork — export the old database,
export the new one, diff them — so the script does that once and feeds both
halves from it. Running the two halves as separate commands would export four
times and diff twice. Do not run two copies in parallel against the same
database either: IDA locks it.

The AI export is written **after** the porting step, and reads the ported
state. That matters more than it sounds: without it, an unchanged function
still diffs as `status` against `v4` and `HV_VP_CONTEXT *ctx` against
`__int64 a1`, purely because the analysis lives in the old database only. Once
the names, prototypes, types and local variables are across, both sides of the
pseudo-code read the same and what is left in the diff is the change itself.

The ratio in `matches.jsonl` is still the one measured while diffing, before
the port, so it is not inflated by the porting itself. The diff bodies are the
ported ones. `summary.md` repeats this where it matters.

## Did the code change, or only the way it reads?

Every match carries `code_changed` and the `code` verdict behind it:

| `code` | Means |
|---|---|
| `same-bytes` | Identical instruction bytes. Proof. |
| `same-asm` | Identical disassembly once both sides are canonicalised: comments, symbol names, addresses, size prefixes, stack frame member names and struct-field operands removed; registers and immediate values kept. |
| `same-asm-annotated` | Identical except where one database names something the other left auto-generated. See below. |
| `same-asm-boundary` | One side's instruction list is a strict prefix of the other's: the same code, with the two databases disagreeing about where the function ends. Only possible when both describe the same binary. |
| `changed` | The instructions differ. |

`same-bytes` means Diaphora's `bytes_hash` matched. The name oversells it:
`get_decoded_instruction()` subtracts `ins.ops[n].offb` from each instruction's
length before reading its bytes, so part of every operand is left out of the
hash. It is a strong signal, not proof of byte equality, and it is not
invariant to annotation either — two databases holding identical bytes can
hash differently when an operand is typed in one of them.

Each match also carries `asm_similarity`, how alike the two canonical forms
are, and `suspect`.

The per-function diffs are split on the verdict:

- `changed/` — the instructions differ. Each diff has an `.asm.diff` beside it
  showing the machine level change, down to a single `add rdi, 8` becoming
  `add rdi, 9`. **Start here.**
- `cosmetic/` — same instructions, different rendering: a name, a type, a local
  variable or a struct field that exists on one side only.
- `suspect/` — the instructions differ, but the two sides also have a different
  number of basic blocks *and* an `asm_similarity` below `0.50`. Far more
  likely a pair Diaphora matched wrongly than a function that was rewritten.
  These are still imported by the porting step, so if a name or type in the
  new database looks wrong, check this list first.
- `boundary/` — same code, the two databases disagree about where the function
  ends.

### Two databases of the same binary

When both databases record the same input md5 they are two analyses of one
file, so **no match can be a code change** and every difference is a database
artefact. The comparison detects this and relaxes accordingly: it forgives
operand rendering it would otherwise have to treat as real (an applied offset
base turns `[rdi+rdx*8+0]` into `ds:rva dword_FFFFF8000000EC60[rdi+rdx*8]`),
and it reports a differing function extent as `same-asm-boundary`.

If a function's bytes *still* differ after that, one of the two databases has a
byte image that no longer matches the binary — bytes were patched in it. That
is reported in a `## Database integrity` section of `summary.md` and in
`byte_divergence` in `manifest.json`, with the exact address and the
instruction each side reports. On a real pair of databases of one hvax64.exe
this found seven such functions, for example:

| At | Database A | Database B |
|---|---|---|
| `0x321f2c` | `mov r8, r9` | `and r8, r9` |
| `0x351fc2` | `mov edi, 10000h` | `mov r11d, 10000h` |

Pass `--old-binary` / `--new-binary` (`diaphora_run.bat` fills these in when
the binary sits next to the database) and it will also say *which* side
diverges, by decoding the file's own bytes at that address. That needs
`capstone`; without it the divergence is still reported, just unattributed.

### Why the comparison is not just a text diff

Diaphora's `clean_assembly` replaces IDA's *auto-generated* names (`sub_`,
`dword_`, `loc_`, …) with a placeholder and leaves names a human gave alone.
That is fine when both databases are annotated to the same degree, and this is
the one case where they never are: the old database has names, types and struct
fields everywhere, the new one has whatever the port reached. Compared as plain
text, every annotated operand reads as a change.

Measured on hvax64 `9711` → `9836`, of the 1157 matches whose bytes differ:

| Cause | Matches |
|---|---|
| Stack frame member names and size prefixes | 692 |
| Named global vs placeholder | 121 |
| Same family one level deeper (struct-field operands) | 239 |
| Genuinely different code | 103 |

So 91% of the differences were annotation, not code. The verdict therefore
canonicalises both sides first, then aligns the two line lists and only calls a
difference cosmetic when it really is one-sided annotation — a rename from one
*named* symbol to another stays `changed`. On that pair this took `changed`
from 881 down to the ~350 that are real, and of the 1253 matches it reclassified
as unchanged, zero had a differing mnemonic sequence or instruction count.

Deliberately not based on the `mnemonics` column: that one drops the operands,
so it cannot tell `mov eax` from `mov ecx` and would hide a real change.

## Things to watch out for

Porting imports every match at or above `DIAPHORA_MINIMUM_IMPORT_RATIO`
(`0.5`), so a bad match can put a wrong name into the new database. Two builds
off the same branch are close enough for the default; raise it to `0.7` or so
when the builds are further apart, for instance built with a different
compiler.

A function the new database already named itself keeps that name when it
differs from the old one — a fresh symbol beats a stale guess. Everything else
about it is still ported. `names_kept` in the report counts those.

Local variables cannot be copied across as they are: Hex-Rays identifies a
saved variable by its location plus `defea`, the address of the instruction
that defines it, and that address is different in every build. They are
matched instead on the location plus `defea` measured from the start of the
function, which is the same in both builds for as long as the body is, and on
the location alone as a fallback. The location alone is not enough on its own:
a stack slot is unique within a function but a register is not, and several
variables sharing one register is the common case — on a real database that
distinction was the difference between 10007 and 22285 variables carried over.
Where neither key gives a single answer the variable is left alone and counted
in `lvars.vars_skipped`, never guessed at.

A name already taken by another variable of the same function is the other
reason a rename fails. When the variable in the way only carries a name
Hex-Rays made up (`v12`, `a3`) it is moved aside so the real name can land
(`lvars.names_unblocked`); a name you chose yourself is never touched, and
those cases are counted in `lvars.collision_user_named` with examples.

Porting local variables means decompiling the functions that have any, and the
step that writes the ported state back into `db/new.sqlite` decompiles the
matched functions once more, so a big database spends real time there.
`--no-lvars` skips it.

### Stack frame members

A separate thing from the local variables above, and easy to confuse with
them. Hex-Rays local variables live in a netnode and show in the pseudo-code;
stack frame members live in the function's frame type and show in the
*disassembly*, as `[rsp+58h+flag]` rather than `[rsp+58h+var_40]`. Nothing in
Diaphora carries them over and neither did anything here until
`diaphora_frames.py`. On hvax64 they were the single largest difference between
the two databases, 692 of the 1157 functions whose disassembly did not match.

Members are matched on their offset in the frame, which the emitted code fixes
and which is therefore the same in both builds as long as the body is. The
whole function is skipped when its frame size differs, since a frame that grew
or shrank means every offset in it would be a guess
(`frames.skipped_layout`). Auto-generated names (`var_38`, `arg_8`, the
saved-register and return-address slots) are not dumped at all.

Reading and writing a frame is a type library operation, so this decompiles
nothing and costs very little. `--no-frames` skips it. Note that it does not
make the diff smaller — the AI export masks frame member names on both sides
before comparing — it makes the new database readable.

### Functions that exist only in the old database

Diaphora can only port what it matched, and it can only match a function that
exists on both sides. A function auto-analysis never found in the new database
is therefore invisible to the entire pipeline: not matched, so its name,
prototype, types, local variables, stack frame and folder never move across.

This is not a corner case. Diffing two databases of *one* hvax64.exe, 227 of
the old side's 4665 functions had no counterpart — every one of them named —
and 218 of those had no function in the new database at all. They are the
hypercall handlers, reached only through a dispatch table, so auto-analysis has
nothing to follow. It is also why a ported database ends up with fewer
functions than the one it was ported from.

So the functions are created first, before the new database is exported, and
everything downstream treats them like any other. Two cases are reported
rather than forced, because both are a judgement call rather than an omission:

- `inside_other` — the address falls inside a function the new database already
  has, so creating it would mean splitting that one.
- `overlaps_other` — the two databases disagree about where the function
  *starts*; the old one has it at `…cf30` and the new one has its own function
  at `…cf39`.

This is the one porting step that writes to the new database before exporting
it, which is why it is its own step and why the backup is taken before it.
`--no-create-funcs` skips it.

The old database is copied into the scratch directory and the original is
never opened, so it comes out of a run byte for byte identical. That is not
paranoia: IDA rewrites the `.i64` container whenever it closes one, and the
exporting step decompiles every function, which Hex-Rays caches *inside* the
database — a small sample grew from 842 KB to 1.6 MB on its first export.
Since the old database is usually the one holding analysis that cannot be
reproduced, it is left alone by default. `--no-protect-old` skips the copy.

If a step cannot open a database, the run stops there rather than carrying on
to the next one. Opening a database that just failed to open is how IDA ends
up creating an empty one over it.

## Configuration

The script reads its settings from a `.env` file next to it. Copy the template
once and fill in at least `IDA_DIR`:

    copy .env.example .env

The script refuses to run without that file. `.env.example` documents every
key; this is the full list:

| Variable | Applies to | Default | Purpose |
|---|---|---|---|
| `IDA_DIR` | both halves | **required** | Folder holding `idat.exe` (and `idat64.exe` on IDA < 9.0) |
| `DIAPHORA_DIR` | both halves | folder of the script | The diaphora checkout. Must not contain spaces, IDA splits its `-S` argument on whitespace |
| `PYTHON_EXE` | both halves | `python` | Python 3 for the diffing and exporting steps, which need no IDA |
| `USE_DECOMPILER` | both halves | `1` | `0` exports without Hex-Rays: much faster, but the diffs then show assembly instead of pseudo-code |
| `PORT_FOLDERS` | `--port` | `1` | `0` skips porting the function folder layout, same as `--no-folders` |
| `PORT_LVARS` | `--port` | `1` | `0` skips porting the Hex-Rays local variables, same as `--no-lvars` |
| `PORT_FRAMES` | `--port` | `1` | `0` skips porting the stack frame member names and types, same as `--no-frames` |
| `CREATE_FUNCS` | `--port` | `1` | `0` skips creating the functions that exist only in the old database, same as `--no-create-funcs` |
| `PORT_TYPES` | `--port` | `all` | `missing` only fills in absent types, `0` leaves them to Diaphora's C text path |
| `PROTECT_OLD` | both halves | `1` | `0` reads the old database directly instead of a scratch copy |
| `DIAPHORA_MINIMUM_IMPORT_RATIO` | `--port` | `0.5` | Similarity a match needs before it is imported |
| `AI_DIFF_MAX_DIFFS` | `--ai` | `2000` | Cap on the number of per-function `.diff` files, lowest ratio first |
| `AI_DIFF_CONTEXT` | `--ai` | `3` | Context lines in those diffs |
| `AI_DIFF_MIN_RATIO` | `--ai` | `0.0` | Drops matches below this ratio from the export |
| `AI_DIFF_FORCE` | `--ai` | unset | `1` re-exports even when `db\*.sqlite` is already there, same as `--force` |

An existing export in `<outdir>\db` is reused rather than redone, since
exporting is the slow part. The new database is the exception: whenever porting
is involved it is always exported afresh, because a cached export may be one
that a previous import has already rewritten.

A variable that is already set in the environment wins over `.env`, so a one-off
change needs no edit:

    set USE_DECOMPILER=0&& diaphora_run.bat old.i64 new.i64

Any other `DIAPHORA_*` variable Diaphora itself reads (see
`CBinDiff.get_value_for()` in `diaphora.py`) can go in `.env` too: the script
passes its whole environment down to IDA and to `diaphora.py`.

`.env` holds machine-specific paths and is deliberately not tracked by git.
