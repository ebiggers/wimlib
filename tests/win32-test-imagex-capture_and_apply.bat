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
set WIMLIB_IMAGEX=wimlib-imagex
set WIN32_TREE_CMP=win32-tree-cmp
set SET_REPARSE_POINT=set_reparse_point

if exist in.dir rd /S /Q in.dir
if exist out.dir rd /S /Q out.dir
md in.dir
cd in.dir

REM
REM BEGIN TESTS
REM

call :msg "empty directory"
call :do_test

call :msg "single file"
echo 1 > file
call :do_test

call :msg "different files"
echo 1 > file
echo 2 > anotherfile
call :do_test

call :msg "identical files"
echo 1 > file
echo 1 > identicalfile
call :do_test

call :msg "hard linked file"
echo 1 > file
mklink /h link file > nul
call :do_test

call :msg "hard linked file, with other identical files"
echo 1 > file
mklink /h link file > nul
echo 1 > identicalfile
call :do_test

call :msg "empty file"
type nul > emptyfile
call :do_test

call :msg "hard linked empty file"
type nul > file
mklink /h link file > nul
call :do_test

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

call :msg "file with custom security descriptor"
echo hello > file
icacls file /deny Administrator:F > nul
call :do_test

call :msg "directory with custom security descriptor (inheritence enabled)"
md subdir
icacls subdir /inheritance:e > nul
call :do_test

call :msg "directory with custom security descriptor (inheritence disabled)"
md subdir
icacls subdir /inheritance:d > nul
call :do_test

REM            win32-tree-cmp can't handle this case.
REM
REM call :msg "file with custom security descriptor (all inherited ACEs removed)"
REM echo hello > file
REM icacls file /inheritance:r > nul
REM call :do_test

call :msg "file with custom integrity level"
echo hello > file
icacls file /setintegritylevel H > nul
call :do_test

call :msg "relative symlink"
mklink relink dest > nul
call :do_test

call :msg "absolute symlink, with drive letter"
mklink abslink C:\absolute\target > nul
call :do_test

call :msg "absolute symlink, without drive letter"
mklink abslink \absolute\target > nul
call :do_test

call :msg "relative symlink, with file target"
echo 1 > 1
mklink relink 1 > nul
call :do_test

call :msg "relative symlink, with directory target"
md subdir
mklink reldlink subdir > nul
call :do_test

call :msg "junction"
md subdir
mklink /j junction subdir > nul
call :do_test

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

call :msg "reparse point that is neither a symlink nor a junction"
type nul > file
%SET_REPARSE_POINT% file
call :do_test

call :msg "reparse point with named data streams"
type nul > file
echo 11 > file:a
echo 1 > file:aa
%SET_REPARSE_POINT% file
call :do_test

call :msg "reparse point with unnamed data stream"
echo "test" > file
%SET_REPARSE_POINT% file
call :do_test

call :msg "reparse point with unnamed data stream and named data streams"
echo "test" > file
echo 11 > file:a
echo 1 > file:aa
%SET_REPARSE_POINT% file
call :do_test

call :msg "empty reparse point"
type nul > file
%SET_REPARSE_POINT% file 0
call :do_test

call :msg "empty reparse point with unnamed data stream"
echo hello > file
%SET_REPARSE_POINT% file 0
call :do_test

call :msg "empty reparse point with unnamed data stream and named data streams"
echo hello > file
echo hello > file:ads1
type nul > file:ads2
%SET_REPARSE_POINT% file 0
call :do_test

call :msg "maximum length reparse point"
type nul > file
%SET_REPARSE_POINT% file 16376
call :do_test

call :msg "directory reparse point that is neither a symlink nor a junction"
md subdir
%SET_REPARSE_POINT% subdir
call :do_test

call :msg "directory reparse point with named data streams"
md subdir
echo 11 > subdir:a
echo 1 > subdir:aa
%SET_REPARSE_POINT% subdir
call :do_test

call :msg "compressed file"
echo "test" > test
compact /C test > nul
call :do_test

call :msg "compressed directory"
md subdir
compact /C subdir > nul
call :do_test

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

call :msg "compressed directory with some uncompressed files in it"
md subdir
compact /C subdir > nul
echo 1 > subdir\1
echo 5 > subdir\5
compact /U subdir\1 > nul
call :do_test

call :msg "file with alternate data stream"
echo 1 > file
echo 5 > file:ads
call :do_test

call :msg "file with multiple alternate data streams"
echo 1 > file
echo a > file:a
echo aa > file:aa
echo aaa > file:aaa
echo aaaa > file:aaaa
call :do_test

call :msg "file with multiple alternate data streams, with hard link"
echo 1 > file
echo a > file:a
echo aa > file:aa
echo aaa > file:aaa
echo aaaa > file:aaaa
mklink /h link file > nul
call :do_test

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

call :msg "file with empty alternate data stream"
echo 1 > file
type nul > file:ads
call :do_test

call :msg "directory with empty alternate data stream"
md subdir
type nul > subdir:ads
call :do_test

call :msg "root directory with alternate data stream"
echo 1 > ..\in.dir:ads
call :do_test

call :msg "root directory with empty alternate data stream"
type nul > ..\in.dir:ads
call :do_test

call :msg "subdirectory with alternate data streams"
md subdir
echo 1 > subdir:1
echo 2 > subdir:2
echo 2 > subdir:2again
call :do_test

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

call :msg "symbolic link and hard link, to file with alternate data streams"
echo 1 > 1
echo test > .\1:test
mklink symlink 1 > nul
mklink /h hardlink 1 > nul
call :do_test

call :msg "compressed file with alternate data streams"
echo 1 > 1
echo 1 > .\1:1
echo 2 > .\1:2
compact /C 1 > nul
call :do_test

call :msg "hidden file"
echo 1 > hidden
attrib +h hidden
call :do_test

call :msg "hidden system file"
echo 1 > file
attrib +h +s file
call :do_test

call :msg "hidden, readonly, system file"
echo 1 > file
attrib +h +r +s file
call :do_test

call :msg "hidden directory"
md subdir
attrib +h subdir
call :do_test

call :msg "hidden system directory"
md subdir
attrib +h +s subdir
call :do_test

call :msg "hidden, readonly, system directory"
md subdir
attrib +h +r +s subdir
call :do_test

call :msg "readonly directory with named data stream"
md subdir
echo foo > subdir:ads
attrib +r subdir
call :do_test

call :msg "encrypted file"
echo "hello" > encrypted
cipher /e encrypted > nul
call :do_test

call :msg "identical encrypted files"
echo "hello" > encrypted1
echo "hello" > encrypted2
cipher /e encrypted1 > nul
cipher /e encrypted2 > nul
call :do_test

call :msg "encrypted directory"
md subdir
cipher /e subdir > nul
call :do_test

call :msg "encrypted directory with encrypted file in it"
md subdir
echo 1 > subdir\1
cipher /e subdir > nul
cipher /e subdir\1 > nul
call :do_test

call :msg "encrypted directory with unencrypted file in it"
md subdir
echo 1 > subdir\1
cipher /e subdir > nul
cipher /d subdir\1 > nul
call :do_test

call :msg "encrypted root directory"
cd ..
cipher /e in.dir > nul
cd in.dir
echo "hello" > encrypted
call :do_test

call :msg "unencrypted file in encrypted directory in compressed directory"
md 1
md 1\2
compact /c 1 > nul
cipher /e 1\2 > nul
echo hello > 1\2\file
cipher /d 1\2\file > nul
call :do_test

call :msg "encrypted directory with alternate data streams"
md subdir
cipher /e subdir > nul
echo ads1 > subdir:ads1
echo ads2 > subdir:ads2
call :do_test

call :msg "hardlinked, encrypted file with alternate data streams"
echo hello > file
echo hello > file:ads
cipher /e file > nul
mklink /h link file > nul
call :do_test

REM Note: since object IDs must be unique per filesystem, we can't expect them
REM to preserved using our testing scheme.  Therefore, win32-tree-cmp doesn't
REM compare them, and the below tests really just ensure the object ID code is
REM run to some extent.

call :msg "file with object ID"
echo hello > file
fsutil objectid create file > nul
call :do_test

call :msg "directory with object ID"
md subdir
fsutil objectid set f67394c12b17608e1d050d181ba8ffd2 7df80cbdf620f4c82c79b9e6799147b6 97621aff72915ade05abb96b15dea1a3 e0bda4caa9e33cfd461c92c16be9713d subdir
call :do_test

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
if %errorlevel% neq 0 goto :fail
rd /s /q out.dir
del tmp1 tmp2
md in.dir
cd in.dir

echo Testing rpfix relative
echo 1 > file
mklink relink file > nul
cd ..
%WIMLIB_IMAGEX% capture in.dir test.wim > nul
%WIMLIB_IMAGEX% apply test.wim out.dir > nul
type out.dir\relink > out.dir\tmp
if %errorlevel% neq 0 goto :fail
fc in.dir\file out.dir\tmp > nul
if %errorlevel% neq 0 goto :fail
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
if %errorlevel% neq 0 goto :fail
%WIMLIB_IMAGEX% apply test.wim out.dir > NUL
if %errorlevel% neq 0 goto :fail
%WIN32_TREE_CMP% in.dir out.dir
if %errorlevel% neq 0 goto :fail

REM  apply a second time so we test the case where the files already exist
%WIMLIB_IMAGEX% apply test.wim out.dir > NUL
if %errorlevel% neq 0 goto :fail
%WIN32_TREE_CMP% in.dir out.dir
if %errorlevel% neq 0 goto :fail

REM Fun fact: Microsoft's WIMGAPI has bugs that make it fail some of our tests.
REM Even the Windows 8.1 version has incorrect behavior with empty files with
REM multiple links, or files with named data streams and multiple links.
rd /S /Q out.dir
md out.dir
REM dism /capture-image /capturedir:in.dir /imagefile:test.wim /name:"test" /norpfix > nul
REM if %errorlevel% neq 0 goto :fail
dism /apply-image /imagefile:test.wim /index:1 /applydir:out.dir > nul
if %errorlevel% neq 0 goto :fail
%WIN32_TREE_CMP% in.dir out.dir

rd /S /Q in.dir out.dir
md in.dir
cd in.dir
goto :eof

:msg
echo Testing capture and apply of %~1
goto :eof

:fail
echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
echo            TEST FAILED!!!!!!!
echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
exit %errorlevel%
