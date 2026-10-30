@echo off
setlocal EnableDelayedExpansion

rem =============================================================================
rem  port_idb.bat
rem
rem  Export + diff + auto-import with Diaphora: copies function names, function
rem  and instruction comments, prototypes, struct/enum/union/typedef
rem  definitions, and the Functions window folder layout from an OLD IDA
rem  database into a NEW one, fully unattended.
rem
rem  Usage:
rem      port_idb.bat <old.i64|old.idb> <new.i64|new.idb>
rem
rem  The NEW database is modified IN PLACE (that is the whole point: it ends
rem  up with the old database's names/comments/types). A backup copy of it is
rem  made before anything else happens and is kept on disk afterwards -- it is
rem  the one file this script deliberately does NOT clean up.
rem
rem  Everything else (exported .sqlite files, diff results, logs) lives in a
rem  scratch directory and is deleted when the script finishes, whether it
rem  succeeded or failed.
rem =============================================================================

rem ---- configuration ---------------------------------------------------------
rem Everything configurable lives in .env next to this script, see .env.example.
rem A variable already set in the environment wins over that file, so
rem     set PORT_FOLDERS=0&& port_idb.bat old.i64 new.i64
rem still works as a one-off override. Mind the missing space before &&: cmd
rem would otherwise put it inside the value.
call "%~dp0load_env.bat" "%~dp0.env"
if errorlevel 1 exit /b 1

rem Defaults for everything .env may legitimately leave out.
if not defined DIAPHORA_DIR set "DIAPHORA_DIR=%~dp0"
if not defined PYTHON_EXE set "PYTHON_EXE=python"
if not defined PORT_FOLDERS set "PORT_FOLDERS=1"
if not defined USE_DECOMPILER set "USE_DECOMPILER=1"

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
  echo Usage: %~nx0 ^<old.i64^|old.idb^> ^<new.i64^|new.idb^>
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
rem checkout itself must not live under a path containing spaces.
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

rem ---- scratch directory, guaranteed free of spaces --------------------------
set "TS=%RANDOM%%RANDOM%"
set "TMPDIR=%TEMP%\diaphora_port_%TS%"
mkdir "%TMPDIR%" 2>nul
for %%A in ("%TMPDIR%") do set "TMPDIR=%%~sA"
echo "%TMPDIR%" | findstr /c:" " >nul
if not errorlevel 1 (
  rd /s /q "%TMPDIR%" 2>nul
  set "TMPDIR=%SystemDrive%\diaphora_port_%TS%"
  mkdir "!TMPDIR!" 2>nul
)
echo [INFO] Scratch directory: %TMPDIR%

set "OLD_SQLITE=%TMPDIR%\old.sqlite"
set "NEW_SQLITE=%TMPDIR%\new.sqlite"
set "RESULTS_SQLITE=%TMPDIR%\results.sqlite"
set "FOLDERS_JSON=%TMPDIR%\folders.json"
set "LOG_FOLDERS=%TMPDIR%\folders.log"
set "LOG_EXPORT_OLD=%TMPDIR%\export_old.log"
set "LOG_EXPORT_NEW=%TMPDIR%\export_new.log"
set "LOG_DIFF=%TMPDIR%\diff.log"
set "LOG_IMPORT=%TMPDIR%\import.log"

rem ---- backup of the new IDB (kept on purpose, not cleaned up) ---------------
set "BACKUP=%NEW_IDB%.%TS%.bak"
echo [INFO] Backing up new database to:
echo        %BACKUP%
copy /y "%NEW_IDB%" "%BACKUP%" >nul
if errorlevel 1 (
  echo [ERROR] Could not create backup, aborting before touching anything.
  rd /s /q "%TMPDIR%" 2>nul
  exit /b 1
)

rem ---- 1/5: dump the function folder layout of the OLD database --------------
rem This only reads the OLD database: the dump script ends with qexit(), which
rem does not save, exactly like the export step below. (IDA does rewrite the
rem .i64 container on close, so its timestamp changes, but its contents do
rem not.) A failure here is not fatal, we simply port everything but the
rem folders.
set "FOLDERS_ARG="
if "%PORT_FOLDERS%"=="1" (
  echo [STEP 1/5] Dumping function folders from OLD database...
  "%IDAT_OLD%" -A -S"%DIAPHORA_DIR%\diaphora_dump_folders.py %FOLDERS_JSON%" -L"%LOG_FOLDERS%" "%OLD_IDB%"
  if exist "%FOLDERS_JSON%.ok" (
    set "FOLDERS_ARG= %FOLDERS_JSON%"
    for /f "usebackq delims=" %%L in ("%FOLDERS_JSON%.ok") do echo        %%L
  ) else (
    echo [WARN] Could not dump the function folders, continuing without them.
    if exist "%FOLDERS_JSON%.fail" type "%FOLDERS_JSON%.fail"
  )
) else (
  echo [STEP 1/5] Skipping function folders ^(PORT_FOLDERS=%PORT_FOLDERS%^)
)

rem ---- 2/5: export OLD --------------------------------------------------------
echo [STEP 2/5] Exporting OLD database: %OLD_IDB%
rem DIAPHORA_USE_DECOMPILER was already set (or cleared) from USE_DECOMPILER
rem at the top of the script.
set "DIAPHORA_AUTO=1"
set "DIAPHORA_EXPORT_FILE=%OLD_SQLITE%"
"%IDAT_OLD%" -A -S"%DIAPHORA_DIR%\diaphora_ida.py" -L"%LOG_EXPORT_OLD%" "%OLD_IDB%"
if not exist "%OLD_SQLITE%" (
  echo [ERROR] Export of OLD database failed, log follows:
  type "%LOG_EXPORT_OLD%"
  goto :cleanup_fail
)

rem ---- 3/5: export NEW --------------------------------------------------------
echo [STEP 3/5] Exporting NEW database: %NEW_IDB%
set "DIAPHORA_EXPORT_FILE=%NEW_SQLITE%"
"%IDAT_NEW%" -A -S"%DIAPHORA_DIR%\diaphora_ida.py" -L"%LOG_EXPORT_NEW%" "%NEW_IDB%"
if not exist "%NEW_SQLITE%" (
  echo [ERROR] Export of NEW database failed, log follows:
  type "%LOG_EXPORT_NEW%"
  goto :cleanup_fail
)
set "DIAPHORA_AUTO="
set "DIAPHORA_EXPORT_FILE="
set "DIAPHORA_USE_DECOMPILER="

rem ---- 4/5: diff (plain python, no IDA license needed here) ------------------
echo [STEP 4/5] Diffing NEW against OLD...
"%PYTHON_EXE%" "%DIAPHORA_DIR%\diaphora.py" "%NEW_SQLITE%" "%OLD_SQLITE%" -o "%RESULTS_SQLITE%" > "%LOG_DIFF%" 2>&1
if not exist "%RESULTS_SQLITE%" (
  echo [ERROR] Diffing failed, log follows:
  type "%LOG_DIFF%"
  goto :cleanup_fail
)

rem ---- 5/5: import everything into the NEW idb, in place ---------------------
echo [STEP 5/5] Importing names / comments / prototypes / structs / enums / unions / typedefs / folders into NEW database...
"%IDAT_NEW%" -A -S"%DIAPHORA_DIR%\diaphora_auto_import.py %RESULTS_SQLITE% %NEW_SQLITE% %OLD_SQLITE%%FOLDERS_ARG%" -L"%LOG_IMPORT%" "%NEW_IDB%"

if exist "%RESULTS_SQLITE%.ok" (
  echo [OK] Import finished successfully.
  for /f "usebackq delims=" %%L in ("%RESULTS_SQLITE%.ok") do echo [OK] %%L
  echo [OK] %NEW_IDB% has been updated in place.
  echo [OK] Backup of the pre-import state kept at %BACKUP%
  goto :cleanup_ok
)

echo [ERROR] Import failed:
if exist "%RESULTS_SQLITE%.fail" type "%RESULTS_SQLITE%.fail"
echo [ERROR] IDA log follows:
type "%LOG_IMPORT%"
goto :cleanup_fail

:cleanup_ok
echo [INFO] Cleaning up temporary files...
del /q "%OLD_SQLITE%" "%NEW_SQLITE%" "%RESULTS_SQLITE%" "%RESULTS_SQLITE%.ok" "%RESULTS_SQLITE%.fail" >nul 2>&1
del /q "%FOLDERS_JSON%" "%FOLDERS_JSON%.ok" "%FOLDERS_JSON%.fail" >nul 2>&1
del /q "%LOG_FOLDERS%" "%LOG_EXPORT_OLD%" "%LOG_EXPORT_NEW%" "%LOG_DIFF%" "%LOG_IMPORT%" >nul 2>&1
rd /s /q "%TMPDIR%" >nul 2>&1
echo [DONE]
exit /b 0

:cleanup_fail
echo [INFO] Cleaning up temporary files (failure path)...
del /q "%OLD_SQLITE%" "%NEW_SQLITE%" "%RESULTS_SQLITE%" "%RESULTS_SQLITE%.ok" "%RESULTS_SQLITE%.fail" >nul 2>&1
del /q "%FOLDERS_JSON%" "%FOLDERS_JSON%.ok" "%FOLDERS_JSON%.fail" >nul 2>&1
del /q "%LOG_FOLDERS%" "%LOG_EXPORT_OLD%" "%LOG_EXPORT_NEW%" "%LOG_DIFF%" "%LOG_IMPORT%" >nul 2>&1
rd /s /q "%TMPDIR%" >nul 2>&1
echo [INFO] %NEW_IDB% was NOT modified beyond its backed-up state at %BACKUP%
echo        ^(the import step only overwrites it after a successful diff^).
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
