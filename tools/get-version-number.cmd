echo off
setlocal enabledelayedexpansion
for /f %%i in ('git describe --abbrev^=8 --dirty --always 2^>nul') do set "vers=%%i"
if not defined vers set "vers=1.14.3"
echo !vers!