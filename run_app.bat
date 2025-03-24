@echo off
echo ZKsrsyslog2 Uygulama Başlatıcı
echo ==============================
echo.
echo 1. Normal Kullanıcı olarak çalıştır
echo 2. Admin olarak çalıştır
echo.

set /p secim=Seçiminizi yapın (1 veya 2): 

if "%secim%"=="1" (
    echo Normal kullanıcı olarak başlatılıyor...
    python app.py
) else if "%secim%"=="2" (
    echo Admin olarak başlatılıyor...
    python app.py --admin
) else (
    echo Geçersiz seçim! Lütfen 1 veya 2 girin.
    pause
    exit /b
)

pause