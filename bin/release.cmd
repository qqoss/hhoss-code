@set cmdPath=%~dp0
@cd /d %cmdPath%..
@set logFile=release%date:~2,2%%date:~5,2%%date:~8,2%%time:~0,2%%time:~3,2%%time:~6,2%.log
mvn clean source:jar deploy >%cmdPath%%logFile%
pause
