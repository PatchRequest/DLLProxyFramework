@echo off
REM DLL Proxy Framework - End-to-end test suite
REM Run from a Visual Studio Developer Command Prompt
REM Usage: cd test && run_tests.bat

setlocal enabledelayedexpansion

set PASS=0
set FAIL=0
set ROOT=%~dp0..
set TARGET=C:\Windows\System32\version.dll

echo ============================================================
echo  DLL Proxy Framework - Test Suite
echo ============================================================
echo.

REM --- Setup ---
if not exist "%ROOT%\test\out" mkdir "%ROOT%\test\out"

echo [*] Compiling test host...
cl /nologo /Fe:"%ROOT%\test\out\test_host.exe" "%ROOT%\test\test_host.c" >nul
if errorlevel 1 (
    echo [-] FAIL: Could not compile test_host.c
    exit /b 1
)
echo [+] test_host.exe ready
echo.

REM ============================================================
REM  Test 1: embed, no block
REM ============================================================
echo [TEST 1] --embed --payload
echo ------------------------------------------------------------

python "%ROOT%\generate.py" %TARGET% --payload --embed -o "%ROOT%\test\out\t1" >nul 2>&1
cd /d "%ROOT%\test\out\t1"
call .\build_msvc.bat >nul 2>&1
if errorlevel 1 (
    echo [-] FAIL: Build failed
    set /a FAIL+=1
    goto :test2
)
copy "%ROOT%\test\out\test_host.exe" . >nul

.\test_host.exe > output.txt 2>&1
findstr /C:"GetFileVersionInfoSizeA" output.txt >nul 2>&1
if errorlevel 1 (
    echo [-] FAIL: Export forwarding did not work
    set /a FAIL+=1
) else (
    echo [+] PASS: Embed forwarding works, host exited normally
    set /a PASS+=1
)

:test2
echo.

REM ============================================================
REM  Test 2: embed + block
REM ============================================================
echo [TEST 2] --embed --payload --block
echo ------------------------------------------------------------

python "%ROOT%\generate.py" %TARGET% --payload --embed --block -o "%ROOT%\test\out\t2" >nul 2>&1
cd /d "%ROOT%\test\out\t2"
copy /Y "%ROOT%\test\test_payload_block.c" payload.c >nul

call .\build_msvc.bat >nul 2>&1
if errorlevel 1 (
    echo [-] FAIL: Build failed
    set /a FAIL+=1
    goto :test3
)
copy "%ROOT%\test\out\test_host.exe" . >nul
if exist proof.txt del proof.txt

.\test_host.exe >nul 2>&1

if exist proof.txt (
    echo [+] PASS: Embed + block kept process alive, payload completed
    set /a PASS+=1
) else (
    echo [-] FAIL: Proof file missing - payload did not complete
    set /a FAIL+=1
)

:test3
echo.

REM ============================================================
REM  Test 3: no embed, no block
REM ============================================================
echo [TEST 3] --payload (no embed, no block)
echo ------------------------------------------------------------

python "%ROOT%\generate.py" %TARGET% --payload -o "%ROOT%\test\out\t3" >nul 2>&1
cd /d "%ROOT%\test\out\t3"
call .\build_msvc.bat >nul 2>&1
if errorlevel 1 (
    echo [-] FAIL: Build failed
    set /a FAIL+=1
    goto :test4
)
copy "%ROOT%\test\out\test_host.exe" . >nul
copy %TARGET% original_version.dll >nul

.\test_host.exe > output.txt 2>&1
findstr /C:"GetFileVersionInfoSizeA" output.txt >nul 2>&1
if errorlevel 1 (
    echo [-] FAIL: Export forwarding did not work
    set /a FAIL+=1
) else (
    echo [+] PASS: Non-embed forwarding works, host exited normally
    set /a PASS+=1
)

:test4
echo.

REM ============================================================
REM  Test 4: no embed + block
REM ============================================================
echo [TEST 4] --payload --block (no embed)
echo ------------------------------------------------------------

python "%ROOT%\generate.py" %TARGET% --payload --block -o "%ROOT%\test\out\t4" >nul 2>&1
cd /d "%ROOT%\test\out\t4"
copy /Y "%ROOT%\test\test_payload_block.c" payload.c >nul

call .\build_msvc.bat >nul 2>&1
if errorlevel 1 (
    echo [-] FAIL: Build failed
    set /a FAIL+=1
    goto :summary
)
copy "%ROOT%\test\out\test_host.exe" . >nul
copy %TARGET% original_version.dll >nul
if exist proof.txt del proof.txt

.\test_host.exe >nul 2>&1

if exist proof.txt (
    echo [+] PASS: Non-embed + block works, payload completed
    set /a PASS+=1
) else (
    echo [-] FAIL: Proof file missing - payload did not complete
    set /a FAIL+=1
)

:summary
echo.
echo ============================================================
echo  Results: !PASS! passed, !FAIL! failed
echo ============================================================

if !FAIL! GTR 0 exit /b 1
exit /b 0
