@echo off

rem Echo to indicate start of the program
echo STARTING PROGRAM...

rem Activate the virtual environment
call .venv\Scripts\activate.bat

rem Echo to indicate the start of the Python script
echo *** BEGIN PROGRAM ***

rem Run the Python script
python main.py %1

rem Echo to indicate the end of the Python script
echo *** END PROGRAM ***

rem Deactivate the virtual environment
deactivate

rem Echo to indicate program completion
echo PROGRAM EXECUTION COMPLETE.
