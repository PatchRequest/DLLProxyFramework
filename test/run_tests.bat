@echo off
REM DLL Proxy Framework - End-to-end test suite
REM Run from a Visual Studio Developer Command Prompt (MSVC tests)
REM MinGW tests require gcc and mingw32-make on PATH
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

echo [*] Compiling test payload DLL...
cl /nologo /LD /Fe:"%ROOT%\test\out\test_payload.dll" "%ROOT%\test\test_payload_dll.c" >nul
if errorlevel 1 (
    echo [-] FAIL: Could not compile test_payload_dll.c
    exit /b 1
)
echo [+] test_payload.dll ready
echo.

REM --- Detect MinGW ---
set HAS_GCC=0
where gcc >nul 2>&1
if not errorlevel 1 (
    where mingw32-make >nul 2>&1
    if not errorlevel 1 (
        set HAS_GCC=1
        echo [*] MinGW detected - GCC tests enabled
    )
)
if "!HAS_GCC!"=="0" echo [*] MinGW not found - skipping GCC tests
echo.

REM ============================================================
REM  MSVC Tests
REM ============================================================

echo [TEST 1/MSVC] --embed --payload
echo ------------------------------------------------------------

python "%ROOT%\generate.py" %TARGET% --payload --embed --compiler msvc -o "%ROOT%\test\out\t1" >nul 2>&1
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
    echo [+] PASS: MSVC embed forwarding works
    set /a PASS+=1
)

:test2
echo.
echo [TEST 2/MSVC] --embed --payload --block
echo ------------------------------------------------------------

python "%ROOT%\generate.py" %TARGET% --payload --embed --block --compiler msvc -o "%ROOT%\test\out\t2" >nul 2>&1
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
    echo [+] PASS: MSVC embed + block works
    set /a PASS+=1
) else (
    echo [-] FAIL: Proof file missing
    set /a FAIL+=1
)

:test3
echo.
echo [TEST 3/MSVC] --payload (no embed, no block)
echo ------------------------------------------------------------

python "%ROOT%\generate.py" %TARGET% --payload --compiler msvc -o "%ROOT%\test\out\t3" >nul 2>&1
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
    echo [+] PASS: MSVC non-embed forwarding works
    set /a PASS+=1
)

:test4
echo.
echo [TEST 4/MSVC] --payload --block (no embed)
echo ------------------------------------------------------------

python "%ROOT%\generate.py" %TARGET% --payload --block --compiler msvc -o "%ROOT%\test\out\t4" >nul 2>&1
cd /d "%ROOT%\test\out\t4"
copy /Y "%ROOT%\test\test_payload_block.c" payload.c >nul

call .\build_msvc.bat >nul 2>&1
if errorlevel 1 (
    echo [-] FAIL: Build failed
    set /a FAIL+=1
    goto :gcc_tests
)
copy "%ROOT%\test\out\test_host.exe" . >nul
copy %TARGET% original_version.dll >nul
if exist proof.txt del proof.txt

.\test_host.exe >nul 2>&1

if exist proof.txt (
    echo [+] PASS: MSVC non-embed + block works
    set /a PASS+=1
) else (
    echo [-] FAIL: Proof file missing
    set /a FAIL+=1
)

:gcc_tests
echo.
if "!HAS_GCC!"=="0" goto :summary

REM ============================================================
REM  GCC/MinGW Tests
REM ============================================================

echo [TEST 5/GCC] --embed --payload
echo ------------------------------------------------------------

python "%ROOT%\generate.py" %TARGET% --payload --embed --compiler gcc -o "%ROOT%\test\out\t5" >nul 2>&1
cd /d "%ROOT%\test\out\t5"
mingw32-make >nul 2>&1
if errorlevel 1 (
    echo [-] FAIL: Build failed
    set /a FAIL+=1
    goto :test6
)
copy "%ROOT%\test\out\test_host.exe" . >nul

.\test_host.exe > output.txt 2>&1
findstr /C:"GetFileVersionInfoSizeA" output.txt >nul 2>&1
if errorlevel 1 (
    echo [-] FAIL: Export forwarding did not work
    set /a FAIL+=1
) else (
    echo [+] PASS: GCC embed forwarding works
    set /a PASS+=1
)

:test6
echo.
echo [TEST 6/GCC] --embed --payload --block
echo ------------------------------------------------------------

python "%ROOT%\generate.py" %TARGET% --payload --embed --block --compiler gcc -o "%ROOT%\test\out\t6" >nul 2>&1
cd /d "%ROOT%\test\out\t6"
copy /Y "%ROOT%\test\test_payload_block.c" payload.c >nul
mingw32-make >nul 2>&1
if errorlevel 1 (
    echo [-] FAIL: Build failed
    set /a FAIL+=1
    goto :test7
)
copy "%ROOT%\test\out\test_host.exe" . >nul
if exist proof.txt del proof.txt

.\test_host.exe >nul 2>&1

if exist proof.txt (
    echo [+] PASS: GCC embed + block works
    set /a PASS+=1
) else (
    echo [-] FAIL: Proof file missing
    set /a FAIL+=1
)

:test7
echo.
echo [TEST 7/GCC] --payload (no embed, no block)
echo ------------------------------------------------------------

python "%ROOT%\generate.py" %TARGET% --payload --compiler gcc -o "%ROOT%\test\out\t7" >nul 2>&1
cd /d "%ROOT%\test\out\t7"
mingw32-make >nul 2>&1
if errorlevel 1 (
    echo [-] FAIL: Build failed
    set /a FAIL+=1
    goto :test8
)
copy "%ROOT%\test\out\test_host.exe" . >nul
copy %TARGET% original_version.dll >nul

.\test_host.exe > output.txt 2>&1
findstr /C:"GetFileVersionInfoSizeA" output.txt >nul 2>&1
if errorlevel 1 (
    echo [-] FAIL: Export forwarding did not work
    set /a FAIL+=1
) else (
    echo [+] PASS: GCC non-embed forwarding works
    set /a PASS+=1
)

:test8
echo.
echo [TEST 8/GCC] --payload --block (no embed)
echo ------------------------------------------------------------

python "%ROOT%\generate.py" %TARGET% --payload --block --compiler gcc -o "%ROOT%\test\out\t8" >nul 2>&1
cd /d "%ROOT%\test\out\t8"
copy /Y "%ROOT%\test\test_payload_block.c" payload.c >nul
mingw32-make >nul 2>&1
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
    echo [+] PASS: GCC non-embed + block works
    set /a PASS+=1
) else (
    echo [-] FAIL: Proof file missing
    set /a FAIL+=1
)

REM ============================================================
REM  MetaTwin Tests (metadata + signature cloning)
REM ============================================================

:test9
echo.
echo [TEST 9/META] MSVC --embed --payload --block (metadata + signature)
echo ------------------------------------------------------------

python "%ROOT%\generate.py" %TARGET% --payload --embed --block --compiler msvc -o "%ROOT%\test\out\t9" >nul 2>&1
cd /d "%ROOT%\test\out\t9"
copy /Y "%ROOT%\test\test_payload_block.c" payload.c >nul

call .\build_msvc.bat >nul 2>&1
if errorlevel 1 (
    echo [-] FAIL: Build failed
    set /a FAIL+=1
    goto :test10
)
copy "%ROOT%\test\out\test_host.exe" . >nul
if exist proof.txt del proof.txt

.\test_host.exe >nul 2>&1

set T9_OK=1
if not exist proof.txt (
    echo [-] FAIL: Proof file missing
    set T9_OK=0
    set /a FAIL+=1
)

python "%ROOT%\test\verify_meta.py" original_version.dll version.dll >nul 2>&1
if errorlevel 1 (
    echo [-] FAIL: Metadata/signature verification failed
    set T9_OK=0
    set /a FAIL+=1
)

if "!T9_OK!"=="1" (
    echo [+] PASS: MSVC embed + block + metatwin
    set /a PASS+=1
)

:test10
echo.
if "!HAS_GCC!"=="0" goto :payloaddll_tests

echo [TEST 10/META] GCC --embed --payload --block (metadata + signature)
echo ------------------------------------------------------------

python "%ROOT%\generate.py" %TARGET% --payload --embed --block --compiler gcc -o "%ROOT%\test\out\t10" >nul 2>&1
cd /d "%ROOT%\test\out\t10"
copy /Y "%ROOT%\test\test_payload_block.c" payload.c >nul

mingw32-make >nul 2>&1
if errorlevel 1 (
    echo [-] FAIL: Build failed
    set /a FAIL+=1
    goto :payloaddll_tests
)
copy "%ROOT%\test\out\test_host.exe" . >nul
if exist proof.txt del proof.txt

.\test_host.exe >nul 2>&1

set T10_OK=1
if not exist proof.txt (
    echo [-] FAIL: Proof file missing
    set T10_OK=0
    set /a FAIL+=1
)

python "%ROOT%\test\verify_meta.py" original_version.dll version.dll >nul 2>&1
if errorlevel 1 (
    echo [-] FAIL: Metadata/signature verification failed
    set T10_OK=0
    set /a FAIL+=1
)

if "!T10_OK!"=="1" (
    echo [+] PASS: GCC embed + block + metatwin
    set /a PASS+=1
)

REM ============================================================
REM  Payload-DLL Tests (embedded binary payload)
REM ============================================================

:payloaddll_tests
echo.
echo [TEST 11/MSVC] --embed --payload-dll (forwarding still works)
echo ------------------------------------------------------------

python "%ROOT%\generate.py" %TARGET% --embed --payload-dll "%ROOT%\test\out\test_payload.dll" --compiler msvc -o "%ROOT%\test\out\t11" >nul 2>&1
cd /d "%ROOT%\test\out\t11"
call .\build_msvc.bat >nul 2>&1
if errorlevel 1 (
    echo [-] FAIL: Build failed
    set /a FAIL+=1
    goto :test12
)
copy "%ROOT%\test\out\test_host.exe" . >nul

.\test_host.exe > output.txt 2>&1

findstr /C:"GetFileVersionInfoSizeA" output.txt >nul 2>&1
if errorlevel 1 (
    echo [-] FAIL: Export forwarding did not work
    set /a FAIL+=1
) else (
    echo [+] PASS: MSVC embed + payload-dll forwarding works
    set /a PASS+=1
)

:test12
echo.
echo [TEST 12/MSVC] --embed --payload-dll --payload-export --block
echo ------------------------------------------------------------

python "%ROOT%\generate.py" %TARGET% --embed --payload-dll "%ROOT%\test\out\test_payload.dll" --payload-export RunPayload --block --compiler msvc -o "%ROOT%\test\out\t12" >nul 2>&1
cd /d "%ROOT%\test\out\t12"
call .\build_msvc.bat >nul 2>&1
if errorlevel 1 (
    echo [-] FAIL: Build failed
    set /a FAIL+=1
    goto :test13
)
copy "%ROOT%\test\out\test_host.exe" . >nul
if exist payload_proof.txt del payload_proof.txt
if exist payload_export_proof.txt del payload_export_proof.txt

.\test_host.exe >nul 2>&1

set T12_OK=1
if not exist payload_proof.txt (
    echo [-] FAIL: Payload DLL was not loaded
    set T12_OK=0
    set /a FAIL+=1
)
if not exist payload_export_proof.txt (
    echo [-] FAIL: Payload export was not called
    set T12_OK=0
    set /a FAIL+=1
)

if "!T12_OK!"=="1" (
    echo [+] PASS: MSVC embed + payload-dll DllMain + export call
    set /a PASS+=1
)

:test13
echo.
if "!HAS_GCC!"=="0" goto :summary

echo [TEST 13/GCC] --embed --payload-dll (forwarding still works)
echo ------------------------------------------------------------

python "%ROOT%\generate.py" %TARGET% --embed --payload-dll "%ROOT%\test\out\test_payload.dll" --compiler gcc -o "%ROOT%\test\out\t13" >nul 2>&1
cd /d "%ROOT%\test\out\t13"
mingw32-make >nul 2>&1
if errorlevel 1 (
    echo [-] FAIL: Build failed
    set /a FAIL+=1
    goto :test14
)
copy "%ROOT%\test\out\test_host.exe" . >nul

.\test_host.exe > output.txt 2>&1

findstr /C:"GetFileVersionInfoSizeA" output.txt >nul 2>&1
if errorlevel 1 (
    echo [-] FAIL: Export forwarding did not work
    set /a FAIL+=1
) else (
    echo [+] PASS: GCC embed + payload-dll forwarding works
    set /a PASS+=1
)

:test14
echo.
echo [TEST 14/GCC] --embed --payload-dll --payload-export --block
echo ------------------------------------------------------------

python "%ROOT%\generate.py" %TARGET% --embed --payload-dll "%ROOT%\test\out\test_payload.dll" --payload-export RunPayload --block --compiler gcc -o "%ROOT%\test\out\t14" >nul 2>&1
cd /d "%ROOT%\test\out\t14"
mingw32-make >nul 2>&1
if errorlevel 1 (
    echo [-] FAIL: Build failed
    set /a FAIL+=1
    goto :summary
)
copy "%ROOT%\test\out\test_host.exe" . >nul
if exist payload_proof.txt del payload_proof.txt
if exist payload_export_proof.txt del payload_export_proof.txt

.\test_host.exe >nul 2>&1

set T14_OK=1
if not exist payload_proof.txt (
    echo [-] FAIL: Payload DLL was not loaded
    set T14_OK=0
    set /a FAIL+=1
)
if not exist payload_export_proof.txt (
    echo [-] FAIL: Payload export was not called
    set T14_OK=0
    set /a FAIL+=1
)

if "!T14_OK!"=="1" (
    echo [+] PASS: GCC embed + payload-dll DllMain + export call
    set /a PASS+=1
)

:summary
echo.
echo ============================================================
echo  Results: !PASS! passed, !FAIL! failed
echo ============================================================

if !FAIL! GTR 0 exit /b 1
exit /b 0
