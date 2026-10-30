@echo off
rem =============================================================================
rem  load_env.bat
rem
rem  Load KEY=VALUE pairs from a .env file into the environment of the caller.
rem
rem  Usage (from another batch script):
rem      call "%~dp0load_env.bat" "%~dp0.env"
rem      if errorlevel 1 exit /b 1
rem
rem  There is deliberately no setlocal here: the whole point is that the
rem  variables land in the caller's scope.
rem
rem  A variable that is already set is NOT overwritten, so a one-off override
rem  from the command line still wins over the file:
rem      set IDA_DIR=D:\ida-9.1 && port_idb.bat old.i64 new.i64
rem
rem  File format:
rem    KEY=VALUE        one pair per line; VALUE may itself contain "="
rem    # comment        a line whose first character is # is ignored
rem    KEY=             an empty value leaves KEY unset, so that the caller's
rem                     own default applies
rem    KEY="VALUE"      one pair of surrounding double quotes is removed
rem
rem  Do not indent KEY and do not leave trailing spaces after VALUE: both end
rem  up inside the name or the value. Avoid % and ! in values, cmd eats them.
rem =============================================================================

if "%~1"=="" (
  echo [ERROR] load_env.bat: no configuration file given
  exit /b 1
)

if not exist "%~1" (
  echo [ERROR] Configuration file not found:
  echo         %~1
  echo         Copy .env.example to .env and fill in at least IDA_DIR.
  exit /b 1
)

rem eol=# drops the comment lines, delims== splits off the key, and tokens=1,*
rem keeps the whole remainder as the value so that values containing "=" survive.
for /f "usebackq eol=# delims== tokens=1,*" %%K in ("%~1") do call :set_one "%%~K" "%%~L"
exit /b 0

rem =============================================================================
:set_one
rem %1 = key, %2 = value. Both already stripped of surrounding quotes by %%~.
if "%~1"=="" exit /b 0
rem An empty value means "not configured", leave the caller's default alone.
if "%~2"=="" exit /b 0
if defined %~1 exit /b 0
set "%~1=%~2"
exit /b 0
