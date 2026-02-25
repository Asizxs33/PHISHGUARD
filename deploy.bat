@echo off
echo ===================================================
echo CyberQalqan AI - Manual Deployment Script (Windows)
echo ===================================================

echo.
echo [1/3] Building Frontend (React/Vite)...
cd frontend
call npm install
call npm run build
cd ..

echo.
echo [2/3] Setting up Backend (FastAPI)...
cd backend
if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)
call venv\Scripts\activate
pip install -r requirements.txt
cd ..

echo.
echo [3/3] Setting up Telegram Bot...
cd telegram_bot
if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)
call venv\Scripts\activate
pip install -r requirements.txt
cd ..

echo.
echo ===================================================
echo Deployment setup complete!
echo To run the services manually in separate terminals:
echo.
echo BACKEND:  cd backend ^&^& venv\Scripts\activate ^&^& uvicorn main:app --host 0.0.0.0 --port 8000
echo FRONTEND: cd frontend ^&^& npm run preview
echo BOT:      cd telegram_bot ^&^& venv\Scripts\activate ^&^& python bot.py
echo ===================================================
pause
