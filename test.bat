
<nul set /p="Hello from a batch file starting with <"
echo.
start calc.exe
echo Running whoami:
whoami
echo.
echo Running curl google.com:
curl https://www.google.com
echo.
echo Checking groups:
whoami /groups
pause
