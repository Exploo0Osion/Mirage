@echo off
setlocal

if /i "%~1"=="clean" goto :clean

where cl >nul 2>nul
if errorlevel 1 (
  echo [!] cl.exe not found. Run from "x64 Native Tools Command Prompt for VS".
  exit /b 1
)

if not exist bin mkdir bin
if not exist obj mkdir obj

echo [*] Assembling src\asm\gate.asm...
ml64 /nologo /c /Fo obj\gate.obj src\asm\gate.asm
if errorlevel 1 exit /b 1

echo [*] Assembling src\asm\spoofer_desync.asm...
ml64 /nologo /c /Fo obj\spoofer_desync.obj src\asm\spoofer_desync.asm
if errorlevel 1 exit /b 1

echo [*] Compiling C sources...

cl /nologo /MD /O1 /Ob2 /Oi /Os /GS- /Gy /GL /Gw /I include /c /Foobj\ ^
src\utils\gadgets.c ^
src\utils\pe_utils.c ^
src\globals.c ^
src\engine.c ^
src\loader.c ^
src\main.c ^
/utf-8

if errorlevel 1 exit /b 1

echo [*] Linking bin\MyLoader.exe...

link /nologo /SUBSYSTEM:CONSOLE ^
/LTCG /OPT:REF /OPT:ICF ^
/MERGE:.rdata=.text ^
/MERGE:.data=.text ^
/SECTION:.text,ERW ^
/OUT:bin\MyLoader.exe ^
obj\gate.obj ^
obj\spoofer_desync.obj ^
obj\gadgets.obj ^
obj\pe_utils.obj ^
obj\globals.obj ^
obj\engine.obj ^
obj\loader.obj ^
obj\main.obj ^
kernel32.lib vcruntime.lib ucrt.lib

if errorlevel 1 exit /b 1

echo.
echo [+] Build Success!
echo [+] Output: bin\MyLoader.exe
echo.
exit /b 0

:clean
if exist bin rmdir /s /q bin
if exist obj rmdir /s /q obj
exit /b 0
