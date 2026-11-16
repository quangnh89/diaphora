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

:parse_args
if "%~1"=="" goto :args_done
if defined WANT_OUTDIR (
  set "OUTDIR=%~f1"
  set "WANT_OUTDIR="
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
if not defined NEW_IDB goto :usage

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
echo "%TMPDIR%" | findstr /c:" " >nul
if not errorlevel 1 (
  rd /s /q "%TMPDIR%" 2>nul
  set "TMPDIR=%SystemDrive%\diaphora_run_%TS%"
  mkdir "!TMPDIR!" 2>nul
)
if not exist "%TMPDIR%" (
  echo [ERROR] Could not create a scratch directory.
  exit /b 1
)

rem ---- where the exports live ------------------------------------------------
rem With --ai they are deliverables the summary points at, so they go next to
rem the export and stay. Otherwise they are throwaway intermediates.
if defined DO_AI (
  for %%A in ("%NEW_IDB%") do set "NEW_DIR=%%~dpA"
  for %%A in ("%NEW_IDB%") do set "NEW_STEM=%%~nA"
  for %%A in ("%OLD_IDB%") do set "OLD_STEM=%%~nA"
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
set "FOLDERS_JSON=%TMPDIR%\folders.json"
set "LOG_FOLDERS=%LOGDIR%\folders.log"
set "LOG_EXPORT_OLD=%LOGDIR%\export_old.log"
set "LOG_EXPORT_NEW=%LOGDIR%\export_new.log"
set "LOG_DIFF=%LOGDIR%\diff.log"
set "LOG_IMPORT=%LOGDIR%\import.log"

rem ---- step budget -----------------------------------------------------------
rem Exporting both sides and diffing them is always needed; the rest depends
rem on which halves were asked for.
set /a TOTAL=3
if defined DO_PORT set /a TOTAL+=1
if defined DO_PORT if "%PORT_FOLDERS%"=="1" set /a TOTAL+=1
if defined DO_AI set /a TOTAL+=1
set "STEP_NO=0"
set "FAIL_AI="
set "FAIL_PORT="

echo [INFO] Old database: %OLD_IDB%
echo [INFO] New database: %NEW_IDB%
if defined DO_PORT echo [INFO] Porting:      names / comments / prototypes / types / folders
if defined DO_AI echo [INFO] AI export:    %OUTDIR%
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

rem ---- dump the function folder layout of the OLD database -------------------
rem This only reads the OLD database: the dump script ends with qexit(), which
rem does not save, exactly like the export steps below. (IDA does rewrite the
rem .i64 container on close, so its timestamp changes, but its contents do
rem not.) A failure here is not fatal, we simply port everything but the
rem folders.
set "FOLDERS_ARG="
if defined DO_PORT if "%PORT_FOLDERS%"=="1" (
  call :step "Dumping function folders from OLD database..."
  "%IDAT_OLD%" -A -S"%DIAPHORA_DIR%\diaphora_dump_folders.py %FOLDERS_JSON%" -L"%LOG_FOLDERS%" "%OLD_IDB%"
  if exist "%FOLDERS_JSON%.ok" (
    set "FOLDERS_ARG= %FOLDERS_JSON%"
    for /f "usebackq delims=" %%L in ("%FOLDERS_JSON%.ok") do echo        %%L
  ) else (
    echo [WARN] Could not dump the function folders, continuing without them.
    if exist "%FOLDERS_JSON%.fail" type "%FOLDERS_JSON%.fail"
  )
)

rem ---- export OLD ------------------------------------------------------------
rem The OLD database is never modified by us, so a previous export of it is
rem always safe to reuse.
set "DO_EXPORT=1"
if defined DO_AI call :needs_export "%OLD_SQLITE%" DO_EXPORT
if "%DO_EXPORT%"=="0" (
  call :skipstep "Reusing db\old.sqlite, pass --force to export it again"
) else (
  call :step "Exporting OLD database..."
  del /q "%OLD_SQLITE%" >nul 2>&1
  set "DIAPHORA_AUTO=1"
  set "DIAPHORA_EXPORT_FILE=%OLD_SQLITE%"
  "%IDAT_OLD%" -A -S"%DIAPHORA_DIR%\diaphora_ida.py" -L"%LOG_EXPORT_OLD%" "%OLD_IDB%"
)
if not exist "%OLD_SQLITE%" (
  echo [ERROR] Export of OLD database failed, log follows:
  if exist "%LOG_EXPORT_OLD%" type "%LOG_EXPORT_OLD%"
  goto :abort
)

rem ---- export NEW ------------------------------------------------------------
rem Never reused when porting: a cached new.sqlite may be one a previous import
rem rewrote, which would both inflate the ratios and make import_all_auto skip
rem the functions it is supposed to rename (it only takes sub_* ones).
set "DO_EXPORT=1"
if defined DO_AI if not defined DO_PORT call :needs_export "%NEW_SQLITE%" DO_EXPORT
if "%DO_EXPORT%"=="0" (
  call :skipstep "Reusing db\new.sqlite, pass --force to export it again"
) else (
  call :step "Exporting NEW database..."
  del /q "%NEW_SQLITE%" >nul 2>&1
  set "DIAPHORA_AUTO=1"
  set "DIAPHORA_EXPORT_FILE=%NEW_SQLITE%"
  "%IDAT_NEW%" -A -S"%DIAPHORA_DIR%\diaphora_ida.py" -L"%LOG_EXPORT_NEW%" "%NEW_IDB%"
)
rem diaphora_ida.py runs its exporting branch whenever DIAPHORA_AUTO is set, and
rem diaphora_auto_import.py imports it, so these must be gone before the import.
set "DIAPHORA_AUTO="
set "DIAPHORA_EXPORT_FILE="
set "DIAPHORA_USE_DECOMPILER="
if not exist "%NEW_SQLITE%" (
  echo [ERROR] Export of NEW database failed, log follows:
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

rem ---- render the results for an AI agent ------------------------------------
rem Deliberately before the porting step, see the header.
if defined DO_AI (
  call :step "Writing the AI-readable export..."
  "%PYTHON_EXE%" "%DIAPHORA_DIR%\diaphora_ai_export.py" ^
    --results "%RESULTS_SQLITE%" --new "%NEW_SQLITE%" --old "%OLD_SQLITE%" ^
    --outdir "%OUTDIR%" --max-diffs %AI_DIFF_MAX_DIFFS% ^
    --context %AI_DIFF_CONTEXT% --min-ratio %AI_DIFF_MIN_RATIO% ^
    --new-label "%NEW_LABEL%" --old-label "%OLD_LABEL%"
  if errorlevel 1 (
    echo [ERROR] Could not write the AI export.
    set "FAIL_AI=1"
  )
)

rem ---- import everything into the NEW idb, in place --------------------------
if defined DO_PORT call :do_import

rem ---- report ----------------------------------------------------------------
echo.
if defined DO_AI if not defined FAIL_AI echo [OK] AI export written, start from %OUTDIR%\summary.md
if defined DO_AI if defined FAIL_AI echo [FAIL] The AI export could not be written.
if defined DO_PORT if not defined FAIL_PORT echo [OK] %NEW_IDB% has been updated in place.
if defined DO_PORT if not defined FAIL_PORT echo [OK] Backup of the pre-import state kept at %BACKUP%
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
:do_import
rem IDA splits -S on whitespace, so the paths handed to the import script must
rem be space free -- and they must not be the deliverables either, because
rem Diaphora's import rewrites the rows of every function it touches in the
rem primary database (reinit() makes main_db the primary, and import_items()
rem re-reads and re-saves each one). Copies in the scratch directory solve both
rem at once and leave db\new.sqlite exactly as it was diffed.
set "IMP_OLD=%OLD_SQLITE%"
set "IMP_NEW=%NEW_SQLITE%"
set "IMP_RESULTS=%RESULTS_SQLITE%"
if defined DO_AI (
  set "IMP_OLD=%TMPDIR%\imp_old.sqlite"
  set "IMP_NEW=%TMPDIR%\imp_new.sqlite"
  set "IMP_RESULTS=%TMPDIR%\imp_results.sqlite"
  copy /y "%OLD_SQLITE%" "!IMP_OLD!" >nul
  copy /y "%NEW_SQLITE%" "!IMP_NEW!" >nul
  copy /y "%RESULTS_SQLITE%" "!IMP_RESULTS!" >nul
  if errorlevel 1 (
    echo [ERROR] Could not copy the exports into the scratch directory.
    set "FAIL_PORT=1"
    exit /b 0
  )
)

call :step "Importing names / comments / prototypes / structs / enums / unions / typedefs / folders into NEW database..."
"%IDAT_NEW%" -A -S"%DIAPHORA_DIR%\diaphora_auto_import.py %IMP_RESULTS% %IMP_NEW% %IMP_OLD%%FOLDERS_ARG%" -L"%LOG_IMPORT%" "%NEW_IDB%"

if exist "%IMP_RESULTS%.ok" (
  for /f "usebackq delims=" %%L in ("%IMP_RESULTS%.ok") do echo        %%L
  exit /b 0
)

echo [ERROR] Import failed:
if exist "%IMP_RESULTS%.fail" type "%IMP_RESULTS%.fail"
echo [ERROR] IDA log follows:
if exist "%LOG_IMPORT%" type "%LOG_IMPORT%"
set "FAIL_PORT=1"
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
echo   --force        export again even when a previous export is there
echo   -h, --help     this text
echo.
echo Settings live in .env next to this script, see .env.example.
exit /b 1
