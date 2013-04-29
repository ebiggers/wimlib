@echo off

REM
REM win32-test-imagex-capture_and_apply.bat
REM
REM Run some tests on the Windows version of wimlib-imagex.
REM
REM This must be run on Windows Vista or later in a clean directory, with
REM Administrator privileges.  wimlib-imagex and win32-tree-cmp must be
REM executable using the paths set below.

setlocal EnableDelayedExpansion
set WIN32_TREE_CMP=win32-tree-cmp
set WIMLIB_IMAGEX=wimlib-imagex

if exist in.dir rd /S /Q in.dir
if exist out.dir rd /S /Q out.dir
md in.dir
cd in.dir

REM
REM BEGIN TESTS
REM

REM goto :rpfix_tests

call :msg "empty directory"
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "single file"
echo 1 > file
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "different files"
echo 1 > file
echo 2 > anotherfile
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "identical files"
echo 1 > file
echo 1 > identicalfile
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "hard linked file"
echo 1 > file
mklink /h link file > nul
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "hard linked file, with other identical files"
echo 1 > file
mklink /h link file > nul
echo 1 > identicalfile
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "empty file"
type nul > emptyfile
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "various hard linked, identical, different, and empty files"
echo 1 > file
echo 5 > file
mklink /h link1 file > nul
mklink /h link2 file > nul
type nul > emptyfile
type nul > emptyfile2
mklink /h emptyfilelink emptyfile > nul
echo 5 > identicalfile
echo 1 > 1file
mklink /h 1filelink 1file > nul
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "multiple subdirectories, some empty, some not"
md subdir1
md subdir2
md subdir3
echo 1 > subdir1\1
echo 5 > subdir1\5
mklink /h link subdir1\1 > nul
md subdir2\subdir2subdir
type nul > subdir2\emptyfile
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "relative symlink"
mklink relink dest > nul
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "absolute symlink, with drive letter"
mklink abslink C:\absolute\target > nul
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "absolute symlink, without drive letter"
mklink abslink \absolute\target > nul
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "relative symlink, with file target"
echo 1 > 1
mklink relink 1 > nul
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "relative symlink, with directory target"
md subdir
mklink reldlink subdir > nul
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "junction"
md subdir
mklink /j junction subdir > nul
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "symlinks, junctions, files, subdirectories, etc."
echo 1 > 1
mklink relink 1 > nul
mklink rellinklink relink > nul
mklink /j junction . > nul
md subdir
mklink /h subdir\hardlink 1 > nul
echo "hello world!!!!" > hello
mklink subdir\hello hello > nul
mklink abslink C:\Users > nul
md subdir2
type nul > emptyfile
type nul > subdir2\emptyfile
md subdir2\s
md subdir2\s\s
md subdir2\s\s\s
echo "hello world!!!!" > subdir2\otherfile
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "compressed file"
echo "test" > test
compact /C test > nul
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "compressed directory"
md subdir
compact /C subdir > nul
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "compressed directory with files in it"
md subdir
compact /C subdir > nul
echo 1 > subdir\file1
echo 2 > subdir\file2
echo 1 > subdir\file1
md subdir\subsubdir
mklink /h subdir\hardlink subdir\file1 > nul
mklink /j subdir\j subdir\subsubdir > nul
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "compressed directory with some uncompressed files in it"
md subdir
compact /C subdir > nul
echo 1 > subdir\1
echo 5 > subdir\5
compact /U subdir\1 > nul
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "file with alternate data stream"
echo 1 > file
echo 5 > file:ads
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "file with multiple alternate data streams"
echo 1 > file
echo a > file:a
echo aa > file:aa
echo aaa > file:aaa
echo aaaa > file:aaaa
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "file with multiple alternate data streams, with hard link"
echo 1 > file
echo a > file:a
echo aa > file:aa
echo aaa > file:aaa
echo aaaa > file:aaaa
mklink /h link file > nul
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "files with multiple alternate data streams, some identical, with hard link"
echo 1 > file
echo 5 > file2
echo 1 > file:1
echo 1 > file:1again
echo aaa > file:aaa
echo 5 > file:5
mklink /h link file > nul
echo aaa > file2:aaa
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "root directory with alternate data stream"
echo 1 > ..\in.dir:ads
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "subdirectory with alternate data streams"
md subdir
echo 1 > subdir:1
echo 2 > subdir:2
echo 2 > subdir:2again
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "subdirectories and files with alternate data streams"
md subdir
echo hello > hello
echo hello > subdir:hello
echo hello > subdir:helloagain
echo hello > helloagain
mklink /h hellolink hello > nul
echo 1 > helloagain:1
echo 8 > helloagain:8
echo 1 > 1
type nul > helloagain:dummy
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "symbolic link and hard link, to file with alternate data streams"
echo 1 > 1
echo test > .\1:test
mklink symlink 1 > nul
mklink /h hardlink 1 > nul
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "compressed file with alternate data streams"
echo 1 > 1
echo 1 > .\1:1
echo 2 > .\1:2
compact /C 1 > nul
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "hidden file"
echo 1 > hidden
attrib +h hidden
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "hidden directory"
md subdir
attrib +h subdir
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "encrypted file"
echo "hello" > encrypted
cipher /e encrypted > nul
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "identical encrypted files"
echo "hello" > encrypted1
echo "hello" > encrypted2
cipher /e encrypted1 > nul
cipher /e encrypted2 > nul
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "encrypted directory"
md subdir
cipher /e subdir > nul
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "encrypted directory with encrypted file in it"
md subdir
echo 1 > subdir\1
cipher /e subdir > nul
cipher /e subdir\1 > nul
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "encrypted directory with unencrypted file in it"
md subdir
echo 1 > subdir\1
cipher /e subdir > nul
cipher /d subdir\1 > nul
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

call :msg "hardlinked, encrypted file with alternate data streams"
echo hello > file
echo hello > file:ads
cipher /e file > nul
mklink /h link file > nul
call :do_test
if %errorlevel% neq 0 exit /b %errorlevel%

:rpfix_tests

echo Testing rpfix junction
md subdir
echo 1 > subdir\file
mklink /j junction subdir > nul
cd ..
%WIMLIB_IMAGEX% capture in.dir test.wim > nul
rd /s /q in.dir
%WIMLIB_IMAGEX% apply test.wim out.dir > nul
echo 1 > tmp1
type out.dir\junction\file > tmp2
fc tmp1 tmp2 > nul
if %errorlevel% neq 0 exit /b %errorlevel%
rd /s /q out.dir
del tmp1 tmp2
md in.dir
cd in.dir

echo Testing rpfix exclude
mklink otherlink c:\some\other\directory > nul
cd ..
%WIMLIB_IMAGEX% capture in.dir test.wim > nul
%WIMLIB_IMAGEX% apply test.wim out.dir > nul
rd out.dir
if %errorlevel% neq 0 exit /b %errorlevel%
rd /s /q in.dir
md in.dir
cd in.dir

echo Testing rpfix relative
echo 1 > file
mklink relink file > nul
cd ..
%WIMLIB_IMAGEX% capture in.dir test.wim > nul
%WIMLIB_IMAGEX% apply test.wim out.dir > nul
fc in.dir\file out.dir\relink > nul
if %errorlevel% neq 0 exit /b %errorlevel%
rd /s /q in.dir out.dir
md in.dir
cd in.dir

REM
REM END OF TESTS
REM

cd ..
del test.wim
rd /s /q in.dir
exit /b 0

:do_test
cd ..
%WIMLIB_IMAGEX% capture in.dir test.wim --norpfix > NUL
if %errorlevel% neq 0 exit /b %errorlevel%
%WIMLIB_IMAGEX% apply test.wim out.dir > NUL
if %errorlevel% neq 0 exit /b %errorlevel%
%WIN32_TREE_CMP% in.dir out.dir
if %errorlevel% neq 0 (
	echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
	echo            TEST FAILED!!!!!!!
	echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
	exit /b %errorlevel%
)

REM Fun fact:  There are bugs in Microsoft's imagex.exe that make it fail some
REM of our tests.
REM
REM rd /S /Q out.dir
REM md out.dir
REM imagex /capture in.dir test.wim "test" /norpfix > nul
REM if %errorlevel% neq 0 exit /b %errorlevel%
REM imagex /apply test.wim 1 out.dir > nul
REM if %errorlevel% neq 0 exit /b %errorlevel%
REM %WIN32_TREE_CMP% in.dir out.dir
REM if %errorlevel% neq 0 (
	REM echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
	REM echo            TEST FAILED!!!!!!! ^(imagex^)
	REM echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
	REM exit /b %errorlevel%
REM )

rd /S /Q in.dir out.dir
md in.dir
cd in.dir
goto :eof

:msg
echo Testing capture and apply of %~1
goto :eof
