#requires -version 3
<#
.SYNOPSIS
  Update/validate, start and monitor Blackwake Server

.DESCRIPTION
  Validation => ServerStart => LogMonitor => LogWrite

.INPUTS
  None

.OUTPUTS
  '$serverPath\logs\$additionalLogNameFormat'

.NOTES
  Version:        1.0
  Author:         man4red
  Creation Date:  27.02.2017
  Purpose/Change: Initial script development
  
.EXAMPLE
  As administrator "start powershell ./PsBlackwakeMonitor.ps1"
#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------
# CHECK FOR ADMIN ACCESS
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Warning "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
	Start-Sleep 5
    Break
}

#----------------------------------------------------------[Declarations]----------------------------------------------------------

# GLOBAL VARS
$global:dayOfWeek = $(Get-Date).DayOfWeek.value__
# Invocation Path
$global:path = Split-Path -parent $MyInvocation.MyCommand.Definition
# Output_log
$global:logFilePath = (Get-Item "$path\BlackwakeServer_Data\output_log.txt" -ErrorAction Stop)
# Blackwakeserver.exe
$global:serverExe = (Get-Item ($path + "\BlackwakeServer.exe") -ErrorAction Stop)
# Path to Server directory
$global:serverPath = $serverExe.DirectoryName
# Path to blackwakeserver.exe
$global:serverExePath = $serverExe.FullName
# Path to SteamCMD.exe
$global:steamCMD = (Get-Item ("C:\SteamCMD\steamcmd.exe") -ErrorAction Stop)
# Args for SteamCMD
$global:steamCMDArgs = "+login anonymous +force_install_dir $serverPath +app_update 423410 validate +quit"
# Server.cfg
$global:serverCfg = (Get-Item("$path\Server.cfg") -ErrorAction Stop)
# Server.cfg Content
$global:serverCfgContent = (Get-Content ($serverCfg) -Raw -ErrorAction Stop)

# Parse config
$configRegexPattern = [regex]"(?ims)serverName\s*?=\s*?(?<servername>.*?)\s*?$.*useIP\s*?=\s*?(?<ip>.*?)\s*?$.*port\s*?=\s*?(?<port>.*?)\s*?$.*sport\s*?=\s*?(?<sport>.*?)\s*?$.*playerUpdateRate\s*?=\s*?(?<updaterate>.*?)\s*?$.*"
$result = $configRegexPattern.Match($serverCfgContent)
if ($result.Success -eq $true) {
    # Server name
    $global:serverName             = ($result[0].Groups["servername"].Value)
    # Server IP
    $global:serverIp               = ($result[0].Groups["ip"].Value)
    # Server port
    $global:serverPort             = ($result[0].Groups["port"].Value)
    # Server sPort
    $global:serverSPort            = ($result[0].Groups["sport"].Value)
    # Server PlayerUpdateRate
    $global:serverPlayerUpdateRate = ($result[0].Groups["updaterate"].Value)
} else {
    Write-Host "Unable to parse config" -ForegroundColor Red
    Start-Sleep 60
    Exit (-8)
}

# Change PlayerUpdateRate on weekends ?
$global:changePlayerUpdateRateOnWeekends = $true
# PlayerUpdateRate for weekdays
$global:serverPlayerUpdateRateWeekDays = 16
# PlayerUpdateRate for weekends
$global:serverPlayerUpdateRateWeekends = 24
# Server process priority
$global:serverProcessPriorityClass = "High"
# Skip server validation on start?
$global:skipValidation = $false
# Output log name format
$global:additionalLogNameFormat = "$(Get-Date -Format 'yyyy.MM.dd').log"
# Path to additional output log
$global:additionalLogPath = "$serverPath\logs\$additionalLogNameFormat"
# Wait for server port on server start?
$global:waitForPort = $true

# Default windows title
$global:windowTitle = "$serverName | $serverIp`:$serverPort | UpdateRate`: $serverPlayerUpdateRate | ServerOnline`: $([bool]$serverProcess) | PlayersOnline`: 0"

# SEARCH REGEX PATTERNS
# Pattern1 (GREEN COLOR)
$global:greenPattern = "(?i)(Steam game server started\.|A client connected on socket \d{0,2}, there are now \d{0,2} clients connected|\[TeamSelect\] player .* joined$|\[TeamSelect\] player .* joined team .*$|Player .* requested to join team \d{0,2}|Player .* is now on team \d{0,2})"
# Pattern2 (YELLOW COLOR)
$global:yellowPattern = "(?i)(Server\: Received disconnect from \d{0,2}, there are now \d{0,2} clients connected|Auth ticket canceled for player \d{1,2})"
# Pattern3 (RED COLOR)
$global:redPattern = "(?i)(kick(ed|ing)?|ban(ned|ning)?|\d{1,100} bans)"
# ExcludePattern
$global:excludePattern = "(?ims)(wrong connectionId in received user packet|Failed to get arg count|InternalInvoke|WrongConnection|because the the game object|k_EBeginAuthSessionResultOK|got info for|Got id for|Getting large avatar|Getting stats for|Got players stats|temporarily using client score|runtime|Line: 42|\.gen\.cpp|UnityEngine|Grapple index|Exception has been thrown|Could not get lobby info|Timeout Socket|Object reference not set|Validated outfit|Packet has been already received|could not be played| no free slot for incoming connection|Shot denied for|Filename:|If you absolutely need|The effective box size|BoxColliders does not|image effect|RectTransform|could not load|platform assembly|Loading|deprecated|Current environment|object was null|NoResources|Debug|Sending current player|has been disconnected by timeout|song ended for team |sent incorrect|Error: NoResources Socket: |or call this function only for existing animations|Could not get lobby info for player|Filename:|does not support|The effective box size has been|If you absolutely need to use|Visible only by this ship|NullReferenceException|filename unknown)"
# PlayersOnline Pattern
$global:playersOnlinePattern = ".*A client connected on socket \d{0,2}, there are now (?<online>\d{0,2}) clients connected.*|.*disconnect from \d{0,2}, there are now (?<online>\d{0,2}) clients connected.*"

#-----------------------------------------------------------[Functions]------------------------------------------------------------
# CLOSE PREVIOUS POWERSHELL CAPTURE WINDOWS
Function CloseWindowByTitle($title) {
	$result = (Get-Process |where {$_.mainWindowTItle -like "*$title*" -and $_.Name -eq "powershell" })
	if ($result.Count -ge 1) {
		$result | Kill -Force -Confirm:$false
	}
}
# GET BLACKWAKE PROCESS THROUGH WMI
Function GetBlackwakeProcessPath () {
	$wmiQuery = "select ProcessId,ExecutablePath from win32_process where Name='{0}'" -f ($serverExe.Name)
	$wmiProcess = (get-wmiobject -query $wmiQuery) | Where {$_.ExecutablePath -eq $serverExePath}
	$processCount = ($wmiProcess | Measure).Count
	if ($processCount -eq 1 -and [bool]$wmiProcess.ProcessId) {
		$process = Get-Process -PID $wmiProcess.ProcessId
		if ([bool]$process) {
			return $process
		}
	}
	return $false
}

# REMOVE UTF8 BOM FROM FILE
Function Remove-Utf8BOM
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    PARAM(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.IO.FileInfo]$File
    )
    BEGIN
    {
        $byteBuffer = New-Object System.Byte[] 3
    }
    PROCESS
    {
        $reader = $File.OpenRead()
        $bytesRead = $reader.Read($byteBuffer, 0, 3)
        if ($bytesRead -eq 3 -and
            $byteBuffer[0] -eq 239 -and
            $byteBuffer[1] -eq 187 -and
            $byteBuffer[2] -eq 191)
        {
            if ($PSCmdlet.ShouldProcess($File.FullName, 'Removing UTF8 BOM'))
            {
                $tempFile = [System.IO.Path]::GetTempFileName()
                $writer = [System.IO.File]::OpenWrite($tempFile)
                $reader.CopyTo($writer)
                $writer.Dispose()
                $reader.Dispose()
                Move-Item -Path $tempFile -Destination $file.FullName -Force
            }
        }
        else
        {
            $reader.Dispose()
        }
    }
}

Function TimedPrompt($prompt,$secondsToWait){   
    Write-Host -NoNewline $prompt
    $secondsCounter = 0
    $subCounter = 0
    While ( (!$host.ui.rawui.KeyAvailable) -and ($count -lt $secondsToWait) ){
        start-sleep -m 10
        $subCounter = $subCounter + 10
        if($subCounter -eq 1000)
        {
            $secondsCounter++
            $subCounter = 0
            Write-Host -NoNewline "."
        }       
        If ($secondsCounter -eq $secondsToWait) { 
            Write-Host "`r`n"
            return $false;
        }
    }
    Write-Host "`r`n"
    return $true;
}

# SERVER MONITOR PROCESS
function StartServerMonitor
{
   param(
		[Parameter(Mandatory = $false, ValueFromPipeline = $true)]
		[string] $InputObject
	)
	begin{
		$r1 = [regex]$greenPattern;
		$r2 = [regex]$yellowPattern;
		$r3 = [regex]$redPattern;
		$excludePattern = [regex]$excludePattern;
		$playersOnlinePattern = [regex]$playersOnlinePattern;
	}
	process
	{
		# EXCLUDE PATTERN
		if ($inputObject.Length -lt 2 -or ([bool]$ExcludePattern -eq $True -and [bool](Select-String -input $inputObject -Pattern $ExcludePattern -AllMatches))) { return; }
		
		# MATCHES
		$ms1 = $r1.Matches($inputObject)
		$ms2 = $r2.Matches($inputObject)
		$ms3 = $r3.Matches($inputObject)
		$ms4 = $playersOnlinePattern.Matches($inputObject)
		$startIndex = 0
		Write-Host "$(Get-Date -Format 'HH:mm:ss') " -NoNew -ForegroundColor Gray

		# GREEN COLOR
		if ([bool]$greenPattern -eq $True) {
			foreach($m in $ms1)
			{
				$nonMatchLength = $m.Index - $startIndex
				if ($nonMatchLength -ge 0) {
					Write-Host $inputObject.Substring($startIndex, $nonMatchLength) -NoNew
				}
				Write-Host $m.Value -ForegroundColor Green -NoNew
				$startIndex = $m.Index + $m.Length
			}
			
		}

		# YELLOW COLOR
		if ([bool]$yellowPattern -eq $True) {
			foreach($m in $ms2)
			{
				$nonMatchLength = $m.Index - $startIndex
				if ($nonMatchLength -ge 0) {
					Write-Host $inputObject.Substring($startIndex, $nonMatchLength) -NoNew
				}
				Write-Host $m.Value -ForegroundColor Yellow -NoNew
				$startIndex = $m.Index + $m.Length
			}
		}
		
		# RED COLOR
		if ([bool]$redPattern -eq $True) {
			foreach($m in $ms3)
			{
				$nonMatchLength = $m.Index - $startIndex
				if ($nonMatchLength -ge 0) {
					Write-Host $inputObject.Substring($startIndex, $nonMatchLength) -NoNew
				}
				Write-Host $m.Value -ForegroundColor Red -NoNew
				$startIndex = $m.Index + $m.Length
			}
		}

		# GRAY COLOR (DEFAULT)
		if($startIndex -lt $inputObject.Length)
		{
			Write-Host $inputObject.Substring($startIndex) -NoNew -ForegroundColor Gray
		}
		
		# PLAYERS ONLINE
		if ($ms4.Success -eq $true -and $ms4.Captures.Groups.Count -eq 2) {
			$playersOnline = $ms4.Captures.Groups["online"].Value
			$pswindow.WindowTitle = $pswindow.WindowTitle -replace 'PlayersOnline: \d{1,2}', "PlayersOnline: $playersOnline"
		}
		
		# SERVER ONLINE
		$pswindow.WindowTitle = $pswindow.WindowTitle -replace 'ServerOnline: (True|False)', "ServerOnline: $([bool](GetBlackwakeProcessPath))"

		# CAPTURE ADDITIONAL LOG?
		if ([bool]$additionalLogPath -eq $true) {
			$timestamp = (Get-Date -Format 'HH:mm:ss')
			@{$true="$timestamp $($ms1[0].Value)";}[$ms1[0].Value.Length -gt 1] | Out-File $additionalLogPath -Append -Encoding UTF8
			@{$true="$timestamp $($ms2[0].Value)";}[$ms2[0].Value.Length -gt 1] | Out-File $additionalLogPath -Append -Encoding UTF8
			@{$true="$timestamp $($ms3[0].Value)";}[$ms3[0].Value.Length -gt 1] | Out-File $additionalLogPath -Append -Encoding UTF8
		}

		Write-Host
	}
}

#-----------------------------------------------------------[Execution]------------------------------------------------------------

#Close previous window if present
CloseWindowByTitle "$serverIp`:$serverPort"

# SET WINDOW PROPERTIES
$pshost = get-host
if ($pshost.Name -eq "ConsoleHost") {
    $pswindow = $pshost.ui.RawUI
    #BUFER SIZE
    $newsize = $pswindow.buffersize
    $newsize.height = 1000
    $newsize.width = 150
    $pswindow.buffersize = $newsize
    #WINDOW SIZE
    $newsize = $pswindow.windowsize
    $newsize.height = 20
    $newsize.width = 150
    $pswindow.windowsize = $newsize
}

# START SERVER
$validated = $false
$v = 1
$s = 1;

# CHECK IF NOT VALIDATED AND STARTED
while (-not [bool]($global:serverProcess = (GetBlackwakeProcessPath)) `
			-or `
			(-not ($validated) -and -not [bool]($global:serverProcess = (GetBlackwakeProcessPath))) )
{
	# SET BRAKE ON 3rd ATTEMPT
	if ($v -gt 1) {
		Write-Host "Failed validate ($($v-1) attempt)" -ForegroundColor Red
		if ($v -gt 3) {
			Write-Host "Can't start server on validation stage. $($v-1) attempts were made" -ForegroundColor Red
			Start-Sleep 60
			Exit(-1);
		}
	}

	# VALIDATION | UPDATE
	if (-not $skipValidation) {
        Write-Host "Validating server at ""$serverPath\""..." -NoNew

		$pinfo = New-Object System.Diagnostics.ProcessStartInfo
		$pinfo.FileName = $steamCMD
		$pinfo.RedirectStandardError = $true
		$pinfo.RedirectStandardOutput = $true
		$pinfo.UseShellExecute = $false
		$pinfo.WindowStyle = "Hidden"
		$pinfo.Arguments = $steamCMDArgs
		$p = New-Object System.Diagnostics.Process
		$p.StartInfo = $pinfo
		$p.Start() | Out-Null
		$p.WaitForExit()
		$stdout = $p.StandardOutput.ReadToEnd()
		$stderr = $p.StandardError.ReadToEnd()
        if ([bool]$additionalLogPath) {
            $stdout | Out-File $additionalLogPath -Append utf8
            $stderr | Out-File $additionalLogPath -Append utf8
        }
	} else {
		Write-Host "Skipping server validation at ""$serverPath\""..." -NoNew -ForegroundColor Yellow
	}
    if ($skipValidation -eq $false -and $p.ExitCode -ne 0) {
        $validated = $False
		Write-Host " Failed" -ForegroundColor Red
        Write-Host "exit code: " + $p.ExitCode; Write-Host "stderr: $stderr"; Write-Host "stdout: $stdout"
        $v++
    } else {
        $validated = $True
		Write-Host " OK" -ForegroundColor Green
		
		# CHANGE PLAYER UPDATE RATE ON WEEKENDS
		if ($changePlayerUpdateRateOnWeekends -ieq $true) {
			Write-Host "Setting up LOG File..." -NoNew
			if ($dayOfWeek -ge 5) {$playerUpdateRate = $serverPlayerUpdateRateWeekends} else {$playerUpdateRate = $serverPlayerUpdateRateWeekDays}
			# UPDATE CFG
			$serverCfgContent = $serverCfgContent -replace 'playerUpdateRate=\d{2}', "playerUpdateRate=$playerUpdateRate"
			$serverCfgContent | Out-File $serverCfg -Encoding UTF8
			
			Remove-Utf8BOM $serverCfg.FullName
			Write-Host " OK" -ForegroundColor Green
		}
		
		while (-not [bool]($serverProcess = (GetBlackwakeProcessPath))) {
		
			# START SERVER
			Write-Host "Waiting server to start..." -NoNew;

			if ($s -gt 1) {
				Write-Host "Failed ($($s-1) attempt)" -ForegroundColor Red
				if ($s -gt 3) {
					Write-Host "Can't start server. $($s-1) attempts were made" -ForegroundColor Red
					Start-Sleep 60
					Exit(-2);
				}
			}
			
			# REMOVE CURRENT LOG
			Remove-Item $logFilePath -Force -Confirm:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
			
			# START SERVER
			Start-Process $serverExe "-batchmode -nographics" -ErrorAction SilentlyContinue
			Start-Sleep 5
			
			# SET PROCESS PRIORITY
			$serverProcess = (GetBlackwakeProcessPath)
			if ([bool]$serverProcess -eq $True) {
				Write-Host " OK" -ForegroundColor Green
			
				if ($serverProcess.PriorityClass -ne $serverProcessPriorityClass) {
					$serverProcess.PriorityClass = $serverProcessPriorityClass
					Write-Host "Process $($serverProcess.Name) ID $($serverProcess.ID) is now set to $serverProcessPriorityClass" -ForegroundColor Green
				} else {
					Write-Host "Process $($serverProcess.Name) already running with ID $($serverProcess.ID) and priority is already set to $serverProcessPriorityClass"  -ForegroundColor Yellow
				}

				# WAIT FOR PORT
				if ($waitForPort) {
					$timeout = new-timespan -Minutes 5
					$sw = [diagnostics.stopwatch]::StartNew()
					Write-Host "Waiting for port $serverPort and $serverSPort ..." -NoNew
					$portStarted = $false
					$sPortStarted = $false
					while ($sw.elapsed -lt $timeout){
						if(($portStarted = [bool](netstat -an -p udp | findstr $serverPort)) -and ($sPortStarted = [bool](netstat -an -p udp | findstr $serverSPort))) {
							Write-Host " OK" -ForegroundColor Green
							break
						}
						Start-Sleep 10
					}
					if ($sw.elapsed -ge $timeout -and -not $portStarted -and -not $sPortStarted) {
						Write-Host " Failed. Timeout!" -ForegroundColor Red
						Start-Sleep 60
						Exit(-3)
					}
				}
				
			} else {
				Write-Host " Failed. Process not found!" -ForegroundColor Red
				Start-Sleep 60
				Exit(-4)
			}
			
			$s++;
			Start-Sleep 10;
		}
    }
}


$pswindow.WindowTitle = $windowTitle

while (-not (Test-Path $logFilePath)) { Write-Host "Waiting for log..."; Start-Sleep 10;  }
Get-Content $logFilePath -Wait -Tail 1000 | StartServerMonitor
