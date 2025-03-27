#!/bin/bash

# Exit on error
set -e

# Check if Python is installed
echo "checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo "No Python found. Please install Python 3 and ensure it's in your PATH."
    exit 1
fi

# Check if pip is installed
echo "checking pip version..."
if ! command -v pip3 &> /dev/null; then
    echo "No pip found. Please install pip."
    exit 1
fi

# Create virtual environment (if it doesn't exist)
echo "checking virtual environment..."
if [ ! -d "venv" ]; then
    echo "creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "activating virtual environment..."
source venv/bin/activate || {
    echo "Failed to activate virtual environment, trying to install dependencies in global environment..."
}

# Install dependencies
echo "installing dependencies..."
pip install -r requirements.txt || {
    echo "Failed to install dependencies. Please check your network connection and try again."
    exit 1
}

echo "dependencies installed."

# Menu function
show_menu() {
    clear
    echo "================================"
    echo "        Abacus Chat Proxy"
    echo "================================"
    echo "[0] Configure Proxy (run config_editor)"
    echo "[1] Start Proxy (run app.py)"
    echo "================================"
}

# Start proxy function
start_proxy() {
    echo "Starting proxy server..."
    python app.py || {
        echo "Proxy server failed to start, please check the error message."
        exit 1
    }
}

# Main loop
while true; do
    show_menu
    read -p "Please select an option (0/1): " choice
    
    case $choice in
        0)
            echo "Starting configuration program..."
            python config_editor.py || {
                echo "Configuration program failed, please check the error message."
                exit 1
            }
            echo "Configuration complete, do you want to start the proxy now? (Y/N)"
            read -p "Enter your choice: " start_proxy_choice
            case $start_proxy_choice in
                [Yy]*)
                    start_proxy
                    break
                    ;;
                *)
                    continue
                    ;;
            esac
            ;;
        1)
            start_proxy
            break
            ;;
        *)
            echo "Invalid choice, please try again!"
            sleep 2
            ;;
    esac
done

# Catch interrupt signal (Ctrl+C) and termination signal
trap "exit" INT TERM 