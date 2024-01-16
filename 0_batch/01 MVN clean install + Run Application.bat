@echo off
set JAVA_HOME=C:\PROGRA~1\JAVA\JDK-21
set M2_HOME=c:\\tools\\apache-maven-3.9.5
set JARFILE=target\Study18.jar
set MAINCLASS=kp.Application
pushd %cd%
cd ..
call %M2_HOME%\bin\mvn clean install
chcp 65001 > nul 2>&1
%JAVA_HOME%\bin\java -Dfile.encoding=UTF-8 -cp %JARFILE% %MAINCLASS%
pause
popd