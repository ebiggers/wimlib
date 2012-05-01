wpeinit
net use j: \\server\windows7
j:\setup.exe /unattend:j:\autounattend.xml

@ECHO OFF

echo 
echo Unable to start setup.exe from remote server!  Try typing 
echo `ipconfig' to see if we have been assigned an IP address.  
echo If not, this computer probably needs a network driver 
echo that is not present in the Windows PE image.  
echo Or the connection to the server might be broken.
echo 

pause

cmd.exe
