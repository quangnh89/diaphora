@echo off
setlocal EnableDelayedExpansion

rem =============================================================================
rem  diaphora_run.bat
rem
rem  One unattended Diaphora pass over two IDA databases that produces both
rem  deliverables at once:
rem
rem    porting    copies function names, function and instruction comments,
rem               prototypes, struct/enum/union/typedef definitions and the
rem               Functions window folder layout from the OLD database into
rem               the NEW one, in place.
rem    AI export  writes the matched and unmatched tables as JSONL, a unified
rem               diff of the pseudo-code per changed function and a
rem               summary.md, for an AI agent to read directly.
rem
rem  Usage:
rem      diaphora_run.bat <old.i64|old.idb> <new.i64|new.idb> [outdir] [options]
rem
rem      (no option)    do both
rem      --port         port into the NEW database only
rem      --ai           write the AI export only
rem      --outdir DIR   where the AI export goes. Defaults to
rem                     <new>_vs_<old>.aidiff next to the new database.
rem      --no-folders   do not port the function folder layout
rem      --no-frames    do not port the stack frame member names/types
rem      --baseline     diff with plain Diaphora and port nothing, to get
rem                     a reference set of numbers
rem      --force        export again even when a previous export is there
rem      -h, --help     this text
rem
rem  Exporting both databases and diffing them is by far the most expensive
rem  part, and both deliverables need exactly that. Doing it once is the whole
rem  point of this script: running the two halves separately would export
rem  twice and diff twice.
rem
rem  The AI export is written BEFORE the porting step, so that it describes the
rem  databases exactly as they were diffed -- honest similarity ratios, and the
rem  names both sides had at diff time. As a welcome side effect it survives a
rem  failing import. Diaphora's import rewrites the rows of every function it
rem  touches in the primary database, so the import runs against copies in the
rem  scratch directory and db\new.sqlite is left as it was diffed.
rem
rem  Nothing is written into the OLD database. The NEW one is modified in place
rem  by the porting step, which first makes a backup copy next to it and keeps
rem  it. Everything else lives in the scratch directory and is deleted on the
rem  way out; with --ai the exported .sqlite files are deliverables and stay in
rem  <outdir>\db.
rem =============================================================================

rem shift walks %0 along with the rest of the arguments, so anything derived
rem from it has to be captured before the parsing loop below runs.
set "SELF=%~nx0"
set "SELF_DIR=%~dp0"

rem ---- configuration ---------------------------------------------------------
rem Everything configurable lives in .env next to this script, see .env.example.
rem A variable already set in the environment wins over that file, so
rem     set USE_DECOMPILER=0&& diaphora_run.bat old.i64 new.i64
rem still works as a one-off override. Mind the missing space before &&: cmd
rem would otherwise put it inside the value.
call "%SELF_DIR%load_env.bat" "%SELF_DIR%.env"
if errorlevel 1 exit /b 1

rem Defaults for everything .env may legitimately leave out.
if not defined DIAPHORA_DIR set "DIAPHORA_DIR=%SELF_DIR%"
if not defined PYTHON_EXE set "PYTHON_EXE=python"
if not defined PORT_FOLDERS set "PORT_FOLDERS=1"
if not defined PORT_LVARS set "PORT_LVARS=1"
if not defined PORT_FRAMES set "PORT_FRAMES=1"
if not defined PORT_TYPES set "PORT_TYPES=all"
if not defined PROTECT_OLD set "PROTECT_OLD=1"
if not defined USE_DECOMPILER set "USE_DECOMPILER=1"
if not defined AI_DIFF_MAX_DIFFS set "AI_DIFF_MAX_DIFFS=2000"
if not defined AI_DIFF_CONTEXT set "AI_DIFF_CONTEXT=3"
if not defined AI_DIFF_MIN_RATIO set "AI_DIFF_MIN_RATIO=0.0"

rem %~dp0 keeps a trailing backslash, the rest of the script does not want one.
if "%DIAPHORA_DIR:~-1%"=="\" set "DIAPHORA_DIR=%DIAPHORA_DIR:~0,-1%"

rem ---- command line ----------------------------------------------------------
set "OLD_IDB="
set "NEW_IDB="
set "OLD_LABEL="
set "NEW_LABEL="
set "OUTDIR="
set "DO_PORT="
set "DO_AI="
set "WANT_OUTDIR="
set "WANT_TYPEMODE="

:parse_args
if "%~1"=="" goto :args_done
if defined WANT_OUTDIR (
  set "OUTDIR=%~f1"
  set "WANT_OUTDIR="
) else if defined WANT_TYPEMODE (
  set "PORT_TYPES=%~1"
  set "WANT_TYPEMODE="
) else if /I "%~1"=="--help" (
  goto :usage
) else if /I "%~1"=="-h" (
  goto :usage
) else if "%~1"=="/?" (
  goto :usage
) else if /I "%~1"=="--port" (
  set "DO_PORT=1"
) else if /I "%~1"=="--ai" (
  set "DO_AI=1"
) else if /I "%~1"=="--no-folders" (
  set "PORT_FOLDERS=0"
) else if /I "%~1"=="--no-lvars" (
  set "PORT_LVARS=0"
) else if /I "%~1"=="--no-frames" (
  set "PORT_FRAMES=0"
) else if /I "%~1"=="--baseline" (
  set "DO_BASELINE=1"
) else if /I "%~1"=="--no-types" (
  set "PORT_TYPES=0"
) else if /I "%~1"=="--no-protect-old" (
  set "PROTECT_OLD=0"
) else if /I "%~1"=="--types" (
  set "WANT_TYPEMODE=1"
) else if /I "%~1"=="--force" (
  set "AI_DIFF_FORCE=1"
) else if /I "%~1"=="--outdir" (
  set "WANT_OUTDIR=1"
) else (
  call :positional "%~1"
  if errorlevel 1 goto :usage
)
shift
goto :parse_args

:args_done
if defined WANT_OUTDIR (
  echo [ERROR] --outdir needs a directory after it.
  goto :usage
)
if defined WANT_TYPEMODE (
  echo [ERROR] --types needs "all" or "missing" after it.
  goto :usage
)
if /I not "%PORT_TYPES%"=="all" if /I not "%PORT_TYPES%"=="missing" if not "%PORT_TYPES%"=="0" (
  echo [ERROR] PORT_TYPES must be "all", "missing" or "0", not "%PORT_TYPES%".
  exit /b 1
)
if not defined NEW_IDB goto :usage

rem --baseline answers "is the diff itself right": export, diff and write
rem the AI export, but port nothing at all, so the numbers come from plain
rem Diaphora and nothing has been written into the new database.
if defined DO_BASELINE (
  if defined DO_PORT (
    echo [ERROR] --baseline ports nothing, so it cannot be combined with --port.
    exit /b 1
  )
  set "DO_AI=1"
)

rem No feature selected means both of them, which is the reason this script
rem exists in the first place.
if not defined DO_PORT if not defined DO_AI (
  set "DO_PORT=1"
  set "DO_AI=1"
)

rem ---- validation ------------------------------------------------------------
if not defined IDA_DIR (
  echo [ERROR] IDA_DIR is not set, add it to %SELF_DIR%.env ^(see .env.example^).
  exit /b 1
)
if not exist "%OLD_IDB%" (
  echo [ERROR] Old database not found: %OLD_IDB%
  exit /b 1
)
if not exist "%NEW_IDB%" (
  echo [ERROR] New database not found: %NEW_IDB%
  exit /b 1
)
if not exist "%DIAPHORA_DIR%\diaphora_ida.py" (
  echo [ERROR] DIAPHORA_DIR does not point to a diaphora checkout: %DIAPHORA_DIR%
  exit /b 1
)

rem IDA splits its -S script+args string on whitespace, so the diaphora
rem checkout itself must not live under a path containing spaces. The output
rem directory may: everything written there goes through an environment
rem variable or a quoted python argument, and the import step works on copies
rem in the space free scratch directory.
if not "%DIAPHORA_DIR%"=="%DIAPHORA_DIR: =%" (
  echo [ERROR] DIAPHORA_DIR contains a space, IDA's -S switch cannot handle that:
  echo         %DIAPHORA_DIR%
  echo         Move the diaphora checkout to a path without spaces.
  exit /b 1
)

if not exist "%IDA_DIR%\idat64.exe" if not exist "%IDA_DIR%\idat.exe" (
  echo [ERROR] No idat64.exe/idat.exe found under IDA_DIR: %IDA_DIR%
  exit /b 1
)

rem Diaphora only checks whether DIAPHORA_USE_DECOMPILER exists, never its
rem value, so "0" would still switch the decompiler on: it has to be cleared.
if "%USE_DECOMPILER%"=="1" (
  set "DIAPHORA_USE_DECOMPILER=1"
) else (
  set "DIAPHORA_USE_DECOMPILER="
)

call :pick_idat "%OLD_IDB%" IDAT_OLD
call :pick_idat "%NEW_IDB%" IDAT_NEW

rem ---- scratch directory, guaranteed free of spaces --------------------------
set "TS=%RANDOM%%RANDOM%"
set "TMPDIR=%TEMP%\diaphora_run_%TS%"
mkdir "%TMPDIR%" 2>nul
for %%A in ("%TMPDIR%") do set "TMPDIR=%%~sA"
rem A substitution test, not `echo | findstr`: cmd counts the space before the
rem pipe as part of what is echoed, so that test always reports a space.
if not "%TMPDIR%"=="%TMPDIR: =%" (
  rd /s /q "%TMPDIR%" 2>nul
  set "TMPDIR=%SystemDrive%\diaphora_run_%TS%"
  mkdir "!TMPDIR!" 2>nul
)
if not exist "%TMPDIR%" (
  echo [ERROR] Could not create a scratch directory.
  exit /b 1
)

rem ---- work on a copy of the OLD database ------------------------------------
rem Nothing here means to change the old database, but opening one is not free:
rem IDA rewrites the .i64 container every time it closes one, and the exporting
rem step decompiles every function, which Hex-Rays caches inside the database
rem (measured: 842 KB grew to 1.6 MB on the first export). The old database is
rem usually the one holding analysis that cannot be reproduced, so by default
rem it is copied into the scratch directory and never opened at all.
set "OLD_ORIG=%OLD_IDB%"
if "%PROTECT_OLD%"=="1" (
  for %%A in ("%OLD_IDB%") do set "OLD_COPY=%TMPDIR%\old_source%%~xA"
  echo [INFO] Copying the OLD database so it is never opened:
  echo        !OLD_COPY!
  copy /y "%OLD_IDB%" "!OLD_COPY!" >nul
  if errorlevel 1 (
    echo [ERROR] Could not copy the OLD database. Pass --no-protect-old to
    echo         work on it directly, or free up space in %TEMP%.
    rd /s /q "%TMPDIR%" 2>nul
    exit /b 1
  )
  set "OLD_IDB=!OLD_COPY!"
)

rem ---- where the exports live ------------------------------------------------
rem With --ai they are deliverables the summary points at, so they go next to
rem the export and stay. Otherwise they are throwaway intermediates.
rem Named after the original old database, not the working copy.
if defined DO_AI (
  for %%A in ("%NEW_IDB%") do set "NEW_DIR=%%~dpA"
  for %%A in ("%NEW_IDB%") do set "NEW_STEM=%%~nA"
  for %%A in ("%OLD_ORIG%") do set "OLD_STEM=%%~nA"
)
if defined DO_AI if not defined OUTDIR (
  set "OUTDIR=!NEW_DIR!!NEW_STEM!_vs_!OLD_STEM!.aidiff"
)
if defined DO_AI (
  mkdir "!OUTDIR!" 2>nul
  mkdir "!OUTDIR!\db" 2>nul
  mkdir "!OUTDIR!\logs" 2>nul
  if not exist "!OUTDIR!\db" (
    echo [ERROR] Could not create the output directory: !OUTDIR!
    rd /s /q "%TMPDIR%" 2>nul
    exit /b 1
  )
  set "DBDIR=!OUTDIR!\db"
  set "LOGDIR=!OUTDIR!\logs"
)
if not defined DO_AI (
  set "DBDIR=%TMPDIR%"
  set "LOGDIR=%TMPDIR%"
)

set "OLD_SQLITE=%DBDIR%\old.sqlite"
set "NEW_SQLITE=%DBDIR%\new.sqlite"
set "RESULTS_SQLITE=%DBDIR%\results.sqlite"
rem These four go through IDA's -S switch, which splits on whitespace, so they
rem live in the space free scratch directory. The report is copied out at the end.
set "FOLDERS_JSON=%TMPDIR%\folders.json"
set "LVARS_JSON=%TMPDIR%\lvars.json"
set "TYPES_JSON=%TMPDIR%\types.json"
set "FRAMES_JSON=%TMPDIR%\frames.json"
set "PORT_REPORT=%TMPDIR%\port_report.json"
set "LOG_DUMP=%LOGDIR%\dump_old.log"
set "LOG_EXPORT_OLD=%LOGDIR%\export_old.log"
set "LOG_EXPORT_NEW=%LOGDIR%\export_new.log"
set "LOG_DIFF=%LOGDIR%\diff.log"
set "LOG_IMPORT=%LOGDIR%\import.log"

rem ---- step budget -----------------------------------------------------------
rem Exporting both sides and diffing them is always needed; the rest depends
rem on which halves were asked for.
rem Porting adds two: the dump from the OLD database, and the import itself.
set /a TOTAL=3
if defined DO_PORT set /a TOTAL+=2
if defined DO_AI set /a TOTAL+=1
set "STEP_NO=0"
set "FAIL_AI="
set "FAIL_PORT="
set "ABORT="

echo [INFO] Old database: %OLD_ORIG%
echo [INFO] New database: %NEW_IDB%
if defined DO_PORT echo [INFO] Porting:      names / prototypes / comments / types ^(%PORT_TYPES%^) / globals / frames / lvars / folders
if defined DO_AI echo [INFO] AI export:    %OUTDIR%
if defined DO_BASELINE echo [INFO] Baseline:     plain Diaphora, nothing is ported
echo [INFO] Scratch:      %TMPDIR%

rem ---- backup of the new IDB (kept on purpose, not cleaned up) ---------------
set "BACKUP="
if defined DO_PORT (
  set "BACKUP=%NEW_IDB%.%TS%.bak"
  echo [INFO] Backing up new database to:
  echo        !BACKUP!
  copy /y "%NEW_IDB%" "!BACKUP!" >nul
  if errorlevel 1 (
    echo [ERROR] Could not create backup, aborting before touching anything.
    rd /s /q "%TMPDIR%" 2>nul
    exit /b 1
  )
)

rem ---- dump what Diaphora's exporter leaves behind, from the OLD database ----
rem The folder layout, the Hex-Rays local variables, and the types. All three
rem are cheap -- a tree walk, a netnode read and a type library read, none of
rem them decompiles -- so all three are always dumped and PORT_FOLDERS /
rem PORT_LVARS / PORT_TYPES only decide what gets applied.
rem
rem This only reads the OLD database: the dump script ends with qexit(), which
rem does not save, exactly like the export steps below. (IDA does rewrite the
rem .i64 container on close, so its timestamp changes, but its contents do
rem not.) A failure here is not fatal, we simply port everything else.
set "FOLDERS_ARG="
set "LVARS_ARG="
set "TYPES_ARG="
set "FRAMES_ARG="
set "BASELINE_ARG="
if defined DO_BASELINE set "BASELINE_ARG=--baseline"
if defined DO_PORT call :dump_old
if defined ABORT goto :abort

rem ---- export OLD ------------------------------------------------------------
rem The OLD database is never modified by us, so a previous export of it is
rem always safe to reuse.
set "DO_EXPORT=1"
set "IDA_RC=0"
if defined DO_AI call :needs_export "%OLD_SQLITE%" DO_EXPORT
if "%DO_EXPORT%"=="0" (
  call :skipstep "Reusing db\old.sqlite, pass --force to export it again"
) else (
  call :step "Exporting OLD database..."
  del /q "%OLD_SQLITE%" >nul 2>&1
  set "DIAPHORA_AUTO=1"
  set "DIAPHORA_EXPORT_FILE=%OLD_SQLITE%"
  "%IDAT_OLD%" -A -S"%DIAPHORA_DIR%\diaphora_ida.py" -L"%LOG_EXPORT_OLD%" "%OLD_IDB%"
  set "IDA_RC=!errorlevel!"
)
if not exist "%OLD_SQLITE%" (
  echo [ERROR] Export of OLD database failed, IDA exit code %IDA_RC%. Log follows:
  if exist "%LOG_EXPORT_OLD%" type "%LOG_EXPORT_OLD%"
  goto :abort
)

rem ---- export NEW ------------------------------------------------------------
rem Never reused when porting: a cached new.sqlite may be one a previous import
rem rewrote, which would both inflate the ratios and make import_all_auto skip
rem the functions it is supposed to rename (it only takes sub_* ones).
set "DO_EXPORT=1"
set "IDA_RC=0"
if defined DO_AI if not defined DO_PORT call :needs_export "%NEW_SQLITE%" DO_EXPORT
if "%DO_EXPORT%"=="0" (
  call :skipstep "Reusing db\new.sqlite, pass --force to export it again"
) else (
  call :step "Exporting NEW database..."
  del /q "%NEW_SQLITE%" >nul 2>&1
  set "DIAPHORA_AUTO=1"
  set "DIAPHORA_EXPORT_FILE=%NEW_SQLITE%"
  "%IDAT_NEW%" -A -S"%DIAPHORA_DIR%\diaphora_ida.py" -L"%LOG_EXPORT_NEW%" "%NEW_IDB%"
  set "IDA_RC=!errorlevel!"
)
rem diaphora_ida.py runs its exporting branch whenever DIAPHORA_AUTO is set, and
rem diaphora_auto_import.py imports it, so these must be gone before the import.
set "DIAPHORA_AUTO="
set "DIAPHORA_EXPORT_FILE="
set "DIAPHORA_USE_DECOMPILER="
if not exist "%NEW_SQLITE%" (
  echo [ERROR] Export of NEW database failed, IDA exit code %IDA_RC%. Log follows:
  if exist "%LOG_EXPORT_NEW%" type "%LOG_EXPORT_NEW%"
  goto :abort
)

rem ---- diff (plain python, no IDA license needed here) -----------------------
rem NEW goes first, so "primary" is the new binary all the way through.
call :step "Diffing NEW against OLD..."
del /q "%RESULTS_SQLITE%" >nul 2>&1
"%PYTHON_EXE%" "%DIAPHORA_DIR%\diaphora.py" "%NEW_SQLITE%" "%OLD_SQLITE%" -o "%RESULTS_SQLITE%" > "%LOG_DIFF%" 2>&1
if not exist "%RESULTS_SQLITE%" (
  echo [ERROR] Diffing failed, log follows:
  type "%LOG_DIFF%"
  goto :abort
)

rem ---- import everything into the NEW idb, in place --------------------------
rem Before the AI export on purpose: the import updates db\new.sqlite with the
rem ported state of every function it touched, so the export that follows reads
rem pseudo-code whose names and types match the old database. Without that, an
rem unchanged function still diffs as "status" against "v4".
if defined DO_PORT call :do_import

rem ---- render the results for an AI agent ------------------------------------
rem Runs even when the import failed: the analysis is the expensive part and is
rem worth keeping, it just describes the un-ported database in that case.
if defined DO_AI (
  call :step "Writing the AI-readable export..."
  "%PYTHON_EXE%" "%DIAPHORA_DIR%\diaphora_ai_export.py" ^
    --results "%RESULTS_SQLITE%" --new "%NEW_SQLITE%" --old "%OLD_SQLITE%" ^
    --outdir "%OUTDIR%" --max-diffs %AI_DIFF_MAX_DIFFS% ^
    --context %AI_DIFF_CONTEXT% --min-ratio %AI_DIFF_MIN_RATIO% ^
    --new-label "%NEW_LABEL%" --old-label "%OLD_LABEL%" %BASELINE_ARG%
  if errorlevel 1 (
    echo [ERROR] Could not write the AI export.
    set "FAIL_AI=1"
  )
)

rem The report is written in the scratch directory, which goes away: keep it
rem with the rest of the output, or beside the database it describes when there
rem is no output directory.
set "REPORT_KEPT="
if defined DO_PORT if exist "%PORT_REPORT%" (
  if defined DO_AI (
    set "REPORT_KEPT=!OUTDIR!\port_report.json"
  ) else (
    set "REPORT_KEPT=!NEW_IDB!.port_report.json"
  )
  copy /y "%PORT_REPORT%" "!REPORT_KEPT!" >nul 2>&1
)

rem ---- report ----------------------------------------------------------------
echo.
if defined DO_AI if not defined FAIL_AI echo [OK] AI export written, start from %OUTDIR%\summary.md
if defined DO_AI if not defined FAIL_AI if defined FAIL_PORT echo [WARN] That export describes the database as it was BEFORE the port, which failed.
if defined DO_AI if defined FAIL_AI echo [FAIL] The AI export could not be written.
if defined DO_PORT if not defined FAIL_PORT echo [OK] %NEW_IDB% has been updated in place.
if defined DO_PORT if not defined FAIL_PORT echo [OK] Backup of the pre-import state kept at %BACKUP%
if defined REPORT_KEPT echo [OK] What the port carried over: %REPORT_KEPT%
if defined DO_PORT if defined FAIL_PORT echo [FAIL] Porting failed, %NEW_IDB% is unchanged beyond its backup at %BACKUP%

call :cleanup
if defined FAIL_AI exit /b 1
if defined FAIL_PORT exit /b 1
echo [DONE]
exit /b 0

:abort
rem Reached only when a step every half depends on failed, so nothing has been
rem modified yet beyond the backup.
call :cleanup
if defined BACKUP (
  echo [INFO] %NEW_IDB% was NOT modified, its backup is at %BACKUP%
)
exit /b 1

rem =============================================================================
:dump_old
call :step "Dumping folders, local variables and types from OLD database..."
"%IDAT_OLD%" -A -S"%DIAPHORA_DIR%\diaphora_dump_analysis.py folders=%FOLDERS_JSON% lvars=%LVARS_JSON% types=%TYPES_JSON% frames=%FRAMES_JSON%" -L"%LOG_DUMP%" "%OLD_IDB%"
rem The dump script swallows its own errors and still exits 0, so a non-zero
rem code here means IDA itself could not open the database. Stop now instead of
rem carrying on to the export: opening a database that just failed to open is
rem how IDA ends up creating an empty one over it.
if not "%errorlevel%"=="0" (
  echo [ERROR] IDA could not open the OLD database ^(exit code %errorlevel%^).
  echo         Not touching it again. Log:
  if exist "%LOG_DUMP%" type "%LOG_DUMP%"
  set "ABORT=1"
  exit /b 0
)

if "%PORT_FOLDERS%"=="1" (
  if exist "%FOLDERS_JSON%.ok" (
    set "FOLDERS_ARG= folders=%FOLDERS_JSON%"
    for /f "usebackq delims=" %%L in ("%FOLDERS_JSON%.ok") do echo        folders: %%L
  ) else (
    echo [WARN] Could not dump the function folders, continuing without them.
    if exist "%FOLDERS_JSON%.fail" type "%FOLDERS_JSON%.fail"
  )
) else (
  echo        folders: skipped ^(PORT_FOLDERS=%PORT_FOLDERS%^)
)

if "%PORT_LVARS%"=="1" (
  if exist "%LVARS_JSON%.ok" (
    set "LVARS_ARG= lvars=%LVARS_JSON%"
    for /f "usebackq delims=" %%L in ("%LVARS_JSON%.ok") do echo        lvars:   %%L
  ) else (
    echo [WARN] Could not dump the local variables, continuing without them.
    if exist "%LVARS_JSON%.fail" type "%LVARS_JSON%.fail"
  )
) else (
  echo        lvars:   skipped ^(PORT_LVARS=%PORT_LVARS%^)
)

if "%PORT_FRAMES%"=="1" (
  if exist "%FRAMES_JSON%.ok" (
    set "FRAMES_ARG= frames=%FRAMES_JSON%"
    for /f "usebackq delims=" %%L in ("%FRAMES_JSON%.ok") do echo        frames:  %%L
  ) else (
    echo        frames:  NOT dumped, the stack frame members will not be ported
    if exist "%FRAMES_JSON%.fail" type "%FRAMES_JSON%.fail"
  )
) else (
  echo        frames:  skipped ^(PORT_FRAMES=%PORT_FRAMES%^)
)

if not "%PORT_TYPES%"=="0" (
  if exist "%TYPES_JSON%.ok" (
    set "TYPES_ARG= types=%TYPES_JSON% typemode=%PORT_TYPES%"
    for /f "usebackq delims=" %%L in ("%TYPES_JSON%.ok") do echo        types:   %%L ^(mode %PORT_TYPES%^)
  ) else (
    echo [WARN] Could not dump the types, falling back to Diaphora's own C text path.
    if exist "%TYPES_JSON%.fail" type "%TYPES_JSON%.fail"
  )
) else (
  echo        types:   skipped, Diaphora's own C text path will be used
)
exit /b 0

rem =============================================================================
:do_import
rem IDA splits -S on whitespace, so the three database paths handed to the
rem import script must be space free. They must also be the real files, not
rem copies: the import updates main.sqlite with the ported state of every
rem function it touched, and the AI export reads that afterwards. So instead
rem of copying, pass the 8.3 short form of each path, which names the same
rem file without spaces.
call :short_path "%RESULTS_SQLITE%" S_RESULTS
call :short_path "%NEW_SQLITE%" S_NEW
call :short_path "%OLD_SQLITE%" S_OLD
rem One substitution test over all three: it is a no-op unless one has a space.
set "_PATHS=!S_RESULTS!;!S_NEW!;!S_OLD!"
if not "!_PATHS!"=="!_PATHS: =!" (
  echo [ERROR] These paths still contain a space in their 8.3 form, so IDA cannot
  echo         be told about them:
  echo         !_PATHS!
  echo         8.3 names are probably disabled on that volume. Re-run with
  echo         --outdir pointing somewhere without spaces.
  set "_PATHS="
  set "FAIL_PORT=1"
  exit /b 0
)
set "_PATHS="

call :step "Importing names / prototypes / comments / types / globals / frames / lvars / folders into NEW database..."
"%IDAT_NEW%" -A -S"%DIAPHORA_DIR%\diaphora_auto_import.py results=!S_RESULTS! main=!S_NEW! diff=!S_OLD! report=%PORT_REPORT%%FOLDERS_ARG%%LVARS_ARG%%TYPES_ARG%%FRAMES_ARG%" -L"%LOG_IMPORT%" "%NEW_IDB%"

rem The marker files land next to the path the script was given, which is the
rem 8.3 one -- and "results.sqlite" does not survive 8.3 unchanged, so looking
rem for them under the long name would never find them.
if exist "!S_RESULTS!.ok" (
  for /f "usebackq delims=" %%L in ("!S_RESULTS!.ok") do echo        %%L
  del /q "!S_RESULTS!.ok" >nul 2>&1
  exit /b 0
)

echo [ERROR] Import failed:
if exist "!S_RESULTS!.fail" type "!S_RESULTS!.fail"
echo [ERROR] IDA log follows:
if exist "%LOG_IMPORT%" type "%LOG_IMPORT%"
del /q "!S_RESULTS!.fail" >nul 2>&1
set "FAIL_PORT=1"
exit /b 0

rem =============================================================================
:short_path
rem %1 = an existing path, %2 = variable receiving its 8.3 short form.
rem %%~s only resolves for a file that exists, which is the case for all three
rem databases by the time the import runs.
for %%A in ("%~1") do set "%2=%%~sA"
exit /b 0

rem =============================================================================
:cleanup
rem Only the scratch directory is ever removed. With --ai the exports and logs
rem under <outdir> are deliverables, and the backup of the new database is kept
rem on purpose in every mode.
rd /s /q "%TMPDIR%" >nul 2>&1
exit /b 0

rem =============================================================================
:step
set /a STEP_NO+=1
echo [STEP %STEP_NO%/%TOTAL%] %~1
exit /b 0

rem =============================================================================
:skipstep
set /a STEP_NO+=1
echo [SKIP %STEP_NO%/%TOTAL%] %~1
exit /b 0

rem =============================================================================
:needs_export
rem %1 = .sqlite path, %2 = variable receiving 0 (reuse) or 1 (export)
rem Exporting takes minutes, so an export already sitting in the output
rem directory is reused. There is deliberately no freshness check against the
rem database: IDA rewrites the .i64 every time it opens one, even read-only, so
rem neither its timestamp nor its contents survive an export unchanged.
rem --force (AI_DIFF_FORCE=1) is the way to redo one.
set "%2=1"
if "%AI_DIFF_FORCE%"=="1" exit /b 0
if not exist "%~1" exit /b 0
rem A leftover crash file means the export was interrupted half way.
if exist "%~1-crash" exit /b 0
set "%2=0"
exit /b 0

rem =============================================================================
:positional
rem %1 = a bare argument: the old database, then the new one, then the outdir.
set "_p=%~1"
if "%_p:~0,1%"=="-" (
  echo [ERROR] Unknown option: %~1
  exit /b 1
)
if not defined OLD_IDB (
  set "OLD_IDB=%~f1"
  set "OLD_LABEL=%~nx1"
  exit /b 0
)
if not defined NEW_IDB (
  set "NEW_IDB=%~f1"
  set "NEW_LABEL=%~nx1"
  exit /b 0
)
if not defined OUTDIR (
  set "OUTDIR=%~f1"
  exit /b 0
)
echo [ERROR] Unexpected argument: %~1
exit /b 1

rem =============================================================================
:pick_idat
rem %1 = idb/i64 path, %2 = name of the variable to receive the idat exe path
rem IDA >= 9.0 ships a single idat.exe; older versions need idat64.exe for .i64.
rem The existence test needs the variable's value, hence the !...! indirection.
if /I "%~x1"==".i64" (
  set "_IDAT=%IDA_DIR%\idat64.exe"
  if not exist "!_IDAT!" set "_IDAT=%IDA_DIR%\idat.exe"
) else (
  set "_IDAT=%IDA_DIR%\idat.exe"
)
set "%2=!_IDAT!"
set "_IDAT="
exit /b 0

rem =============================================================================
:usage
echo Usage: %SELF% ^<old.i64^|old.idb^> ^<new.i64^|new.idb^> [outdir] [options]
echo.
echo   (no option)    port into the NEW database AND write the AI export
echo   --port         port into the NEW database only
echo   --ai           write the AI export only
echo   --outdir DIR   where the AI export goes
echo                  ^(default: ^<new^>_vs_^<old^>.aidiff next to the new database^)
echo   --no-folders   do not port the function folder layout
echo   --no-lvars     do not port the Hex-Rays local variables
echo   --no-frames    do not port the stack frame member names and types
echo   --types MODE   "all" to replace a type the new database already has,
echo                  "missing" to only fill in what is absent ^(default: all^)
echo   --no-types     leave the types to Diaphora's own C text path
echo   --no-protect-old  read the OLD database directly instead of a copy
echo                  ^(the copy exists because opening a database rewrites it^)
echo   --force        export again even when a previous export is there
echo   -h, --help     this text
echo.
echo Settings live in .env next to this script, see .env.example.
exit /b 1
