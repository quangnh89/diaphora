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

**Porting** copies function names, function and instruction comments,
prototypes, struct/enum/union/typedef definitions, and the Functions window
folder layout from the old database into the new one. The new database is
modified in place, after a backup of it is made and kept.

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

The AI export is written **before** the porting step, so it describes the two
databases exactly as they were diffed: honest similarity ratios, and the names
each side had at diff time. That means the new side of a diff still reads
`sub_140012340`; `matches.jsonl` pairs it with the old name, so nothing is
lost. As a side effect the export survives a failing import.

If you would rather have the diffs themselves labelled with the ported names —
`old/CheckAccessToken` against `new/CheckAccessToken`, with both sides of the
pseudo-code using the same variable and struct names, leaving only the real
change in the diff — port first and then export against the ported database:

    diaphora_run.bat D:\work\old\module.i64 D:\work\new\module.i64 --port
    diaphora_run.bat D:\work\old\module.i64 D:\work\new\module.i64 --ai --force

That costs one extra export of the new database, and the ratios it reports are
inflated, because porting the symbols is itself what made the two sides look
alike.

One thing to watch out for either way: porting imports every match at or above
`DIAPHORA_MINIMUM_IMPORT_RATIO` (`0.5`), so a bad match can put a wrong name
into the new database. Two builds off the same branch are close enough for the
default; raise it to `0.7` or so when the builds are further apart, for
instance built with a different compiler.

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
