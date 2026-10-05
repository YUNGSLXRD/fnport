@echo off
rem fnport: send Fortnite traffic (AWS in Europe) from this PC through the fnport virtual machine.
rem Double-click for a menu, or: fnport-routes.cmd on ^| persist ^| off
chcp 65001 >nul
setlocal
set GW=192.168.56.2
set NETS=3.0.0.0/255.0.0.0 13.32.0.0/255.224.0.0 15.0.0.0/255.0.0.0 18.0.0.0/255.0.0.0 35.156.0.0/255.252.0.0 35.176.0.0/255.248.0.0

rem routes need administrator rights: ask for them and start again
net session >nul 2>&1
if errorlevel 1 (
	if "%~1"=="" (
		powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
	) else (
		powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%~1' -Verb RunAs"
	)
	exit /b
)

set MODE=%~1
if "%MODE%"=="" (
	echo fnport: игровой трафик через виртуальную машину %GW%
	echo.
	echo   1 - включить до перезагрузки ПК
	echo   2 - включить насовсем
	echo   3 - выключить
	echo.
	choice /c 123 /n /m "Выберите 1, 2 или 3: "
	if errorlevel 3 (set MODE=off) else if errorlevel 2 (set MODE=persist) else (set MODE=on)
)

rem old routes through the machine go first: no duplicates, and "off" is just this
for %%n in (%NETS%) do (
	for /f "tokens=1,2 delims=/" %%a in ("%%n") do route delete %%a mask %%b %GW% >nul 2>&1
)
if /i "%MODE%"=="off" (
	echo Маршруты через машину fnport убраны, игра снова идёт напрямую.
	goto done
)

rem routes to a machine that is off would cut the game off
ping -n 2 -w 1000 %GW% | find "TTL=" >nul
if errorlevel 1 (
	echo Машина fnport ^(%GW%^) не отвечает: сначала запустите её. Маршруты не добавлены.
	goto done
)

set P=
if /i "%MODE%"=="persist" set P=-p
for %%n in (%NETS%) do (
	for /f "tokens=1,2 delims=/" %%a in ("%%n") do route %P% add %%a mask %%b %GW% >nul
)
if /i "%MODE%"=="persist" (
	echo Готово: трафик Fortnite идёт через машину fnport, в том числе после перезагрузки.
) else (
	echo Готово: трафик Fortnite идёт через машину fnport до перезагрузки ПК.
)

:done
if "%~1"=="" pause
