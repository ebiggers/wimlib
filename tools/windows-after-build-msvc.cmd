echo off
setlocal enabledelayedexpansion
cd /d %~dp0..
for /f %%i in ('%~dp0get-version-number.cmd') do set "VERSION=%%i"
set "ARCH=%~1"
set "ARCH=!ARCH:ARM=arm!"
set "CONFIG=%~2"
set "CONFIGOUT=!CONFIG: =_!"
set "CONFIGOUT=!CONFIGOUT:R=r!"
set "CONFIGOUT=!CONFIGOUT:D=d!"
set "CONFIGOUT=!CONFIGOUT:S=s!"
set "DESTDIR=wimlib-!VERSION!-windows-msvc-!ARCH!-!CONFIGOUT!-bin"
mkdir "!DESTDIR!" 2>nul
mkdir "!DESTDIR!\symbols" 2>nul
:install_binaries
echo Installing binaries...
copy /y ".\!ARCH!\!CONFIG!\*wim*.dll" "!DESTDIR!" >nul 2>nul
copy /y ".\!ARCH!\!CONFIG!\*wim*.exe" "!DESTDIR!" >nul
:install_text_files
echo Installing NEWS, README, and licenses...
del /q !DESTDIR!\*.txt 2>nul
copy /y NEWS* "!DESTDIR!" >nul
copy /y  README* "!DESTDIR!" >nul
copy /y  COPYING* "!DESTDIR!" >nul
for %%i in (!DESTDIR!\COPYING*) do move /y %%i %%i.txt>nul
ren !DESTDIR!\*.txt.txt *. 1>nul
ren !DESTDIR!\*.md *.txt>nul
:install_symbols
echo Installing symbols...
copy /y ".\!ARCH!\!CONFIG!\*wim*.pdb" "!DESTDIR!\symbols" >nul
:install_cmd_aliases
echo Installing wim*.cmd files...
for /f %%i in ('dir /a-d /b .\doc\man1\wim*.1') do (
set "cmd=%%i"
echo ^@echo off>"!DESTDIR!\!cmd:~0,-2!.cmd"
echo "^%%~dp0\\wimlib-imagex" !cmd:~3,-2! %%^*>>"!DESTDIR!\!cmd:~0,-2!.cmd"
)
del /q "!DESTDIR!\*mount*.cmd"
del /q "!DESTDIR!\*imagex.cmd"
:install_development_files
echo Installing development files...
mkdir "!DESTDIR!\devel" 2>nul
copy /y ".\!ARCH!\!CONFIG!\*.lib" "!DESTDIR!\devel" >nul
copy /y ".\include\wimlib.h" "!DESTDIR!\devel" >nul
:install_test_files
echo Installing test files...
mkdir "!DESTDIR!\test" 2>nul
copy /y ".\!ARCH!\!CONFIG: Static=!\*.exe" "!DESTDIR!\test" >nul
copy /y ".\!ARCH!\!CONFIG!\*.exe" "!DESTDIR!\test" >nul
copy /y ".\!ARCH!\!CONFIG!\*.dll" "!DESTDIR!\test" >nul 2>nul
copy /y ".\tests\*.bat" "!DESTDIR!\test" >nul