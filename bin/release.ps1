$cmdFile = $MyInvocation.MyCommand.Definition
$cmdPath = [System.IO.Path]::GetDirectoryName($cmdFile)
$logFile = $cmdPath+"\release" + (Get-Date -Format yyMMddHHmmss) + ".log"
Set-Location  $cmdPath/..
$mvnCmd = mvn -X clean source:jar deploy
$mvnCmd | tee $logFile
#pause