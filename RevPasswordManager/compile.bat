@echo off
if not exist bin mkdir bin
dir /s /B src\main\java\*.java > sources.txt
javac -d bin -cp "lib/*" @sources.txt
del sources.txt
echo Compilation complete.
