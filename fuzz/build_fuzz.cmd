@echo off
chcp 65001 >nul
rem Сборка и прогон фаззеров разбора (libFuzzer + AddressSanitizer, MSVC x64).
rem Отдельно от программы: в exe фаззеры не входят, Npcap не нужен.
rem
rem   fuzz\build_fuzz.cmd            — только собрать fuzz\out\fuzz_dump.exe и fuzz_hello.exe
rem   fuzz\build_fuzz.cmd 150        — собрать и гонять каждый фаззер 150 секунд
rem
rem Затравка — fuzz\out\seeds (tools\gen_fuzz_seeds.py, нужен Python с cryptography);
rem новые интересные входы копятся в fuzz\out\corpus_*, падения — fuzz\out\crash-*.
rem Повторить падение: fuzz\out\fuzz_dump.exe fuzz\out\crash-<хеш>
setlocal
cd /d "%~dp0.."

where cl >nul 2>nul || call :vcvars || exit /b 1

set "OUT=fuzz\out"
set "FLAGS=/nologo /std:c++17 /utf-8 /EHsc /MD /Zi /O1 /W3 /DTA_FUZZ /D_CRT_SECURE_NO_WARNINGS /DWIN32_LEAN_AND_MEAN /DNOMINMAX /D_WINSOCK_DEPRECATED_NO_WARNINGS /fsanitize=fuzzer /fsanitize=address /I."
for %%h in (dump hello) do (
    if not exist "%OUT%\obj_%%h" mkdir "%OUT%\obj_%%h"
    cl %FLAGS% /Fe%OUT%\fuzz_%%h.exe /Fo%OUT%\obj_%%h\ /Fd%OUT%\obj_%%h\ fuzz\fuzz_%%h.cpp parser.cpp || exit /b 1
)
if "%~1"=="" exit /b 0

if not exist "%OUT%\seeds\dump" (
    python tools\gen_fuzz_seeds.py "%OUT%\seeds" || exit /b 1
)
if not exist "%OUT%\corpus_dump" mkdir "%OUT%\corpus_dump"
if not exist "%OUT%\corpus_hello" mkdir "%OUT%\corpus_hello"
set "OPTS=-max_total_time=%~1 -timeout=10 -rss_limit_mb=2048 -print_final_stats=1 -artifact_prefix=%OUT%\"
"%OUT%\fuzz_dump.exe" %OPTS% -max_len=32768 "%OUT%\corpus_dump" "%OUT%\seeds\dump" || exit /b 1
"%OUT%\fuzz_hello.exe" %OPTS% -max_len=4096 "%OUT%\corpus_hello" "%OUT%\seeds\hello" || exit /b 1
exit /b 0

:vcvars
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo Не найден vswhere.exe — нужна Visual Studio с C++ ^(MSVC x64^).
    exit /b 1
)
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -property installationPath`) do set "VSDIR=%%i"
if not defined VSDIR (
    echo Visual Studio не найдена.
    exit /b 1
)
call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
exit /b 0
