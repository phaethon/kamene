@echo off
set MYDIR=%cd%\..
set PYTHONPATH=%MYDIR%
if [%1]==[] (
  python %MYDIR%\kamene\tools\UTkamene.py -t regression.uts -f html -o kamene_regression_test_%DATE%.html
) else (
  python %MYDIR%\kamene\tools\UTkamene.py %1 %2 %3 %4 %5 %6 %7 %8 %9
)
