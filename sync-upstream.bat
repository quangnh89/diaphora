@echo off
setlocal enabledelayedexpansion

set "MAIN_BRANCH=master"
set "UPSTREAM_REMOTE=upstream"
set "ORIGIN_REMOTE=origin"
set "TEMP_BRANCH=temp-merge-fix"
set "HAS_TEMP=false"

echo  1. Kiem tra trang thai Git...
for /f "tokens=*" %%i in ('git rev-parse --abbrev-ref HEAD') do set "CURRENT_HEAD=%%i"

:: Kiem tra neu dang o trang thai detached HEAD (HEAD)
if "%CURRENT_HEAD%"=="HEAD" (
    echo  Phat hien trang thai ^(no branch^) / Detached HEAD.
    echo  Tao nhanh tam '%TEMP_BRANCH%' de giu lai commit hien tai...
    git branch -D %TEMP_BRANCH% >nul 2>&1
    git branch %TEMP_BRANCH%
    if errorlevel 1 goto :error
    set "HAS_TEMP=true"
)

echo  2. Chuyen ve nhanh %MAIN_BRANCH%...
git checkout %MAIN_BRANCH%
if errorlevel 1 goto :error

echo  3. Lay du lieu moi nhat tu %UPSTREAM_REMOTE%...
git fetch %UPSTREAM_REMOTE%
if errorlevel 1 goto :error

if "%HAS_TEMP%"=="true" (
    echo  4. Gop commit tu nhanh tam ^(%TEMP_BRANCH%^) vao %MAIN_BRANCH%...
    git merge %TEMP_BRANCH% --no-edit
    if errorlevel 1 goto :error

    echo  5. Don dep nhanh tam...
    git branch -D %TEMP_BRANCH%
    if errorlevel 1 goto :error
)

echo  6. Gop %UPSTREAM_REMOTE%/%MAIN_BRANCH% vao %MAIN_BRANCH% local...
git merge %UPSTREAM_REMOTE%/%MAIN_BRANCH% --no-edit
if errorlevel 1 goto :error

echo  7. Day ket qua len %ORIGIN_REMOTE%/%MAIN_BRANCH%...
git push %ORIGIN_REMOTE% %MAIN_BRANCH%
if errorlevel 1 goto :error

echo.
echo  Hoan tat dong bo tu upstream vao %MAIN_BRANCH% thanh cong!
exit /b 0

:error
echo.
echo [ERROR] Co loi xay ra trong qua trinh thuc thi! Vui long kiem tra xung dot (conflict) hoac trang thai git.
exit /b 1