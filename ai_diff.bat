@echo off
setlocal EnableDelayedExpansion

rem =============================================================================
rem  ai_diff.bat
rem
rem  Unattended Diaphora diffing session, exported as plain text an AI agent
rem  can read: export both databases, diff them, then write the matched /
rem  unmatched tables as JSONL plus a unified diff per changed function.
rem
rem  Usage:
rem      ai_diff.bat <old.i64|old.idb> <new.i64|new.idb> [outdir]
rem
rem  Nothing is written into either database: IDA is only used to export, and
rem  it exits through qexit(), which does not save. (IDA does rewrite the
rem  .i64 container on close, so timestamps change, but contents do not.)
rem  Nothing is cleaned up either -- the whole point is the output directory,
rem  which defaults to <new>_vs_<old>.aidiff next to the new database.
rem
rem  Exporting is by far the slowest step, so an export already sitting in
rem  the output directory is reused as is -- re-run with AI_DIFF_FORCE=1
rem  after changing a database, otherwise the old export is diffed again.
rem =============================================================================

rem ---- configuration ---------------------------------------------------------
rem Everything configurable lives in .env next to this script, see .env.example.
rem A variable already set in the environment wins over that file, so
rem     set AI_DIFF_FORCE=1&& ai_diff.bat old.i64 new.i64
rem still works as a one-off override. Mind the missing space before &&: cmd
rem would otherwise put it inside the value.
call "%~dp0load_env.bat" "%~dp0.env"
if errorlevel 1 exit /b 1

rem Defaults for everything .env may legitimately leave out.
if not defined DIAPHORA_DIR set "DIAPHORA_DIR=%~dp0"
if not defined PYTHON_EXE set "PYTHON_EXE=python"
if not defined USE_DECOMPILER set "USE_DECOMPILER=1"
if not defined AI_DIFF_MAX_DIFFS set "AI_DIFF_MAX_DIFFS=2000"
if not defined AI_DIFF_CONTEXT set "AI_DIFF_CONTEXT=3"
if not defined AI_DIFF_MIN_RATIO set "AI_DIFF_MIN_RATIO=0.0"

rem Diaphora only checks whether DIAPHORA_USE_DECOMPILER exists, never its
rem value, so "0" would still switch the decompiler on: it has to be cleared.
if "%USE_DECOMPILER%"=="1" (
  set "DIAPHORA_USE_DECOMPILER=1"
) else (
  set "DIAPHORA_USE_DECOMPILER="
)

rem %~dp0 keeps a trailing backslash, the rest of the script does not want one.
if "%DIAPHORA_DIR:~-1%"=="\" set "DIAPHORA_DIR=%DIAPHORA_DIR:~0,-1%"

if not defined IDA_DIR (
  echo [ERROR] IDA_DIR is not set, add it to %~dp0.env ^(see .env.example^).
  exit /b 1
)
rem -----------------------------------------------------------------------------

if "%~2"=="" (
  echo Usage: %~nx0 ^<old.i64^|old.idb^> ^<new.i64^|new.idb^> [outdir]
  exit /b 1
)

set "OLD_IDB=%~f1"
set "NEW_IDB=%~f2"

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
rem directory may: everything written there is passed either through an
rem environment variable or as a quoted python argument.
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

call :pick_idat "%OLD_IDB%" IDAT_OLD
call :pick_idat "%NEW_IDB%" IDAT_NEW

rem ---- output layout ---------------------------------------------------------
if "%~3"=="" (
  set "OUTDIR=%~dp2%~n2_vs_%~n1.aidiff"
) else (
  set "OUTDIR=%~f3"
)

mkdir "%OUTDIR%" 2>nul
mkdir "%OUTDIR%\db" 2>nul
mkdir "%OUTDIR%\logs" 2>nul
if not exist "%OUTDIR%\db" (
  echo [ERROR] Could not create the output directory: %OUTDIR%
  exit /b 1
)

set "OLD_SQLITE=%OUTDIR%\db\old.sqlite"
set "NEW_SQLITE=%OUTDIR%\db\new.sqlite"
set "RESULTS_SQLITE=%OUTDIR%\db\results.sqlite"
set "LOG_EXPORT_OLD=%OUTDIR%\logs\export_old.log"
set "LOG_EXPORT_NEW=%OUTDIR%\logs\export_new.log"
set "LOG_DIFF=%OUTDIR%\logs\diff.log"

echo [INFO] Old database: %OLD_IDB%
echo [INFO] New database: %NEW_IDB%
echo [INFO] Output:       %OUTDIR%

rem ---- 1/4: export OLD --------------------------------------------------------
call :needs_export "%OLD_SQLITE%" "%OLD_IDB%" DO_EXPORT
if "!DO_EXPORT!"=="0" (
  echo [SKIP] 1/4 reusing db\old.sqlite, set AI_DIFF_FORCE=1 to export again
) else (
  echo [STEP 1/4] Exporting OLD database...
  del /q "%OLD_SQLITE%" >nul 2>&1
  set "DIAPHORA_AUTO=1"
  set "DIAPHORA_EXPORT_FILE=%OLD_SQLITE%"
  "%IDAT_OLD%" -A -S"%DIAPHORA_DIR%\diaphora_ida.py" -L"%LOG_EXPORT_OLD%" "%OLD_IDB%"
)
if not exist "%OLD_SQLITE%" (
  echo [ERROR] Export of OLD database failed, log follows:
  if exist "%LOG_EXPORT_OLD%" type "%LOG_EXPORT_OLD%"
  exit /b 1
)

rem ---- 2/4: export NEW --------------------------------------------------------
call :needs_export "%NEW_SQLITE%" "%NEW_IDB%" DO_EXPORT
if "!DO_EXPORT!"=="0" (
  echo [SKIP] 2/4 reusing db\new.sqlite, set AI_DIFF_FORCE=1 to export again
) else (
  echo [STEP 2/4] Exporting NEW database...
  del /q "%NEW_SQLITE%" >nul 2>&1
  set "DIAPHORA_AUTO=1"
  set "DIAPHORA_EXPORT_FILE=%NEW_SQLITE%"
  "%IDAT_NEW%" -A -S"%DIAPHORA_DIR%\diaphora_ida.py" -L"%LOG_EXPORT_NEW%" "%NEW_IDB%"
)
set "DIAPHORA_AUTO="
set "DIAPHORA_EXPORT_FILE="
set "DIAPHORA_USE_DECOMPILER="
if not exist "%NEW_SQLITE%" (
  echo [ERROR] Export of NEW database failed, log follows:
  if exist "%LOG_EXPORT_NEW%" type "%LOG_EXPORT_NEW%"
  exit /b 1
)

rem ---- 3/4: diff (plain python, no IDA license needed here) ------------------
rem NEW goes first, so "primary" is the new binary all the way through.
echo [STEP 3/4] Diffing NEW against OLD...
del /q "%RESULTS_SQLITE%" >nul 2>&1
"%PYTHON_EXE%" "%DIAPHORA_DIR%\diaphora.py" "%NEW_SQLITE%" "%OLD_SQLITE%" -o "%RESULTS_SQLITE%" > "%LOG_DIFF%" 2>&1
if not exist "%RESULTS_SQLITE%" (
  echo [ERROR] Diffing failed, log follows:
  type "%LOG_DIFF%"
  exit /b 1
)

rem ---- 4/4: render the results for an AI agent -------------------------------
echo [STEP 4/4] Writing the AI-readable export...
"%PYTHON_EXE%" "%DIAPHORA_DIR%\diaphora_ai_export.py" ^
  --results "%RESULTS_SQLITE%" --new "%NEW_SQLITE%" --old "%OLD_SQLITE%" ^
  --outdir "%OUTDIR%" --max-diffs %AI_DIFF_MAX_DIFFS% ^
  --context %AI_DIFF_CONTEXT% --min-ratio %AI_DIFF_MIN_RATIO% ^
  --new-label "%~nx2" --old-label "%~nx1"
if errorlevel 1 (
  echo [ERROR] Could not write the AI export.
  exit /b 1
)

echo.
echo [OK] Start from %OUTDIR%\summary.md
echo [DONE]
exit /b 0

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
:needs_export
rem %1 = .sqlite path, %2 = database path, %3 = variable receiving 0 or 1
rem Exporting takes minutes, so an export at least as new as its database is
rem reused unless AI_DIFF_FORCE says otherwise.
set "%3=1"
if "%AI_DIFF_FORCE%"=="1" exit /b 0
if not exist "%~1" exit /b 0
rem A leftover crash file means the export was interrupted half way.
if exist "%~1-crash" exit /b 0
rem Deliberately no freshness check against the database: IDA rewrites the
rem .i64 every time it opens one, even read-only, so neither its timestamp
rem nor its contents survive an export unchanged. Any existing export is
rem therefore reused, and AI_DIFF_FORCE=1 is the way to redo one.
set "%3=0"
exit /b 0
