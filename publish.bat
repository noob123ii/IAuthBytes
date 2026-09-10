@echo off
setlocal
set VER=%1
if "%VER%"=="" set VER=1.1.0
echo Building release v%VER%...
dotnet publish IAuthBytes\IAuthBytes.csproj -c Release -r win-x64 --self-contained false -o publish_output
echo Creating zip...
powershell -Command "Compress-Archive -Path 'publish_output\*' -DestinationPath 'IAuthBytes-v%VER%.zip' -Force"
echo Done: IAuthBytes-v%VER%.zip
echo.
echo Next steps:
echo   1. Create a GitHub release: https://github.com/noob123ii/IAuthBytes/releases/new
echo   2. Tag: v%VER%, Title: v%VER%
echo   3. Upload IAuthBytes-v%VER%.zip as a release asset
echo   4. Update UpdateDetection\LatestUpdate.txt with ZipUrl pointing to the zip asset
echo   5. Git push
echo.
pause
