REM
REM Try building and running the example programs on Windows with Visual Studio.
REM

@echo off
setlocal EnableDelayedExpansion

copy .libs\libwim.dll.a libwim.lib
copy .libs\libwim-15.dll libwim-15.dll
for %%a in (examples\*.c) do (
	cl %%a libwim.lib /Iinclude /link /opt:noref
	if errorlevel 1 exit /b
)
call :do_test


cd examples
rename *.c *.cc
cd ..
for %%a in (examples\*.cc) do (
	cl %%a libwim.lib /Iinclude /link /opt:noref
	if errorlevel 1 exit /b
)
call :do_test
cd examples
rename *.cc *.c
cd ..

del *.exe *.obj *.dll *.lib

exit /b 0

:do_test
.\applywim.exe j:\test.wim e:\tmp1
if errorlevel 1 exit /b
.\capturewim.exe e:\tmp1 e:\tmp1.wim
if errorlevel 1 exit /b
REM Windows likes to give UAC prompts for programs with "update" in their name.
move /y updatewim.exe updat3wim.exe
.\updat3wim.exe e:\tmp1.wim examples examples
if errorlevel 1 exit /b

.\compressfile.exe j:\testdata e:\testdata.lzx
if errorlevel 1 exit /b
.\decompressfile.exe e:\testdata.lzx e:\testdata.orig
if errorlevel 1 exit /b
fc /b j:\testdata e:\testdata.orig
if errorlevel 1 exit /b

.\compressfile.exe j:\testdata e:\testdata.lzx XPRESS 16384
if errorlevel 1 exit /b
.\decompressfile.exe e:\testdata.lzx e:\testdata.orig
if errorlevel 1 exit /b
fc /b j:\testdata e:\testdata.orig
if errorlevel 1 exit /b
goto :eof
