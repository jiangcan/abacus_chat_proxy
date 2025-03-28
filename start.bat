@echo off
chcp 65001 > nul

echo checking python version...
python --version > nul 2>&1
if errorlevel 1 (
    echo No python found. Please install python and add it to the PATH.
    echo After installation, please restart the command prompt.
    pause
    exit /b
)

echo checking pip version...
pip --version > nul 2>&1
if errorlevel 1 (
    echo No pip found. Please install pip.
    echo After installation, please restart the command prompt.
    pause
    exit /b
)

echo checking venv module...
python -m venv venv
if errorlevel 1 (
    echo No venv module found. Please upgrade your python to 3.3+.
    pause
    exit /b
)

echo activating virtual environment...
call venv\Scripts\activate.bat
if errorlevel 1 (
 echo Failed to activate virtual environment, trying to install dependencies in global environment...
 goto install_dependencies
)

echo virtual environment activated.

:install_dependencies
echo installing dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo Failed to install dependencies. Please check your network connection and try again.
    pause
    exit /b
)

echo dependencies installed.

:menu
cls
echo ================================
echo        Abacus Chat Proxy
echo ================================
echo [0] Configure Proxy (run config_editor)
echo [1] Start Proxy (run app.py)
echo ================================
set /p choice="Please select an option (0/1): "

if "%choice%"=="0" (
    echo Starting configuration program...
    python config_editor.py
    if errorlevel 1 (
        echo Configuration program failed, please check the error message.
        pause
        exit /b
    )
    echo Configuration complete, do you want to start the proxy now? (Y/N)
    set /p start_now="Do you want to start the proxy now? (Y/N),enter your choice: "
    if /i "%start_now%"=="Y" (
        goto run_proxy
    ) else (
        goto menu
    )
)

if "%choice%"=="1" (
    goto run_proxy
)

echo Invalid choice, please try again!
timeout /t 2 > nul
goto menu

:run_proxy
echo Starting proxy server...
python app.py
if errorlevel 1 (
    echo Proxy server failed to start, please check the error message.
    pause
    exit /b
)
echo Proxy server is running: http://127.0.0.1:9876/
pause
exit /b