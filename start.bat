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

echo starting Flask app...
python app.py
if errorlevel 1 (
    echo Failed to start Flask app. Please check the error message above.
    pause
    exit /b
)
 
echo Flask app listening on http://127.0.0.1:9876/

pause
exit /b