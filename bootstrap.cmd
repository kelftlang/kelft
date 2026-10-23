@echo off
setlocal
set "kelft_arch=%PROCESSOR_ARCHITECTURE%"
if defined PROCESSOR_ARCHITEW6432 set "kelft_arch=%PROCESSOR_ARCHITEW6432%"
if /I "%kelft_arch%"=="AMD64" set "kelft_arch=x86_64"
if /I "%kelft_arch%"=="ARM64" set "kelft_arch=arm64"
set "kelft_seed=%~dp0bootstrap\windows-%kelft_arch%"
if not exist "%kelft_seed%\READY" (
  echo The windows-%kelft_arch% seed is not ready for this workflow. See bootstrap/README.md. 1>&2
  exit /b 1
)
if "%~1"=="" (
  "%kelft_seed%\bin\kelft.exe" bootstrap --package "%kelft_seed%" -- help
) else (
  "%kelft_seed%\bin\kelft.exe" bootstrap --package "%kelft_seed%" -- %*
)
exit /b %ERRORLEVEL%
