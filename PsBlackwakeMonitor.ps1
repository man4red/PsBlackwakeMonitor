# CHECK FOR ADMIN ACCESS
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Warning "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
	Start-Sleep 5
    Break
}

# GLOBAL VARS
$global:dayOfWeek = $(Get-Date).DayOfWeek.value__
$global:path = Split-Path -parent $MyInvocation.MyCommand.Definition
$global:logFilePath = ("$path\BlackwakeServer_Data\output_log.txt").ToString()
$global:serverCfgPath = ("$path\Server.cfg")
$global:serverCfg = (Get-Content ($serverCfgPath) -ErrorAction Stop)
$global:serverName = ($serverCfg | Select-String -Pattern "serverName=(.*)$").Matches.groups[1].value
$global:serverIp = ($serverCfg | Select-String -Pattern "useIP=(.*)$").Matches.groups[1].value
$global:serverPort = ($serverCfg | Select-String -Pattern "port=(.*)$").Matches.groups[1].value
$global:serverSPort = ($serverCfg | Select-String -Pattern "sport=(.*)$").Matches.groups[1].value
$global:serverPlayerUpdateRate = ($serverCfg | Select-String -Pattern "playerUpdateRate=(.*)$").Matches.groups[1].value
$global:steamCMD = "C:\SteamCMD\steamcmd.exe"
$global:serverExe = (Get-Item ($path + "\BlackwakeServer.exe") -ErrorAction Stop)
$global:serverPath = $serverExe.DirectoryName
$global:serverExePath = $serverExe.FullName
$global:changePlayerUpdateRateOnWeekends = $true
$global:serverPlayerUpdateRateWeekDays = 16
$global:serverPlayerUpdateRateWeekends = 24
$global:serverProcessPriorityClass = "High"
$global:skipValidation = $false
$global:additionalLogNameFormat = "$(Get-Date -Format 'yyyy.MM.dd').log"
$global:additionalLogPath = "$serverPath\logs\$additionalLogNameFormat"
$global:waitForPort = $true

# SEARCH REGEX PATTERNS
# Pattern1 (GREEN COLOR)
$pattern1 = "(?i)(Steam game server started\.|A client connected on socket \d{0,2}, there are now \d{0,2} clients connected|\[TeamSelect\] player .* joined$|\[TeamSelect\] player .* joined team .*$|Player .* requested to join team \d{0,2}|Player .* is now on team \d{0,2})"
# Pattern2 (YELLOW COLOR)
$pattern2 = "(?i)(Server\: Received disconnect from \d{0,2}, there are now \d{0,2} clients connected|Auth ticket canceled for player \d{1,2})"
# Pattern3 (RED COLOR)
$pattern3 = "(?i)(kick(ed|ing)?|ban(ned|ning)?|\d{1,100} bans)"
# ExcludePattern
$ExcludePattern = "(?ims)(WrongConnection|because the the game object|k_EBeginAuthSessionResultOK|got info for|Got id for|Getting large avatar|Getting stats for|Got players stats|temporarily using client score|runtime|Line: 42|\.gen\.cpp|UnityEngine|Grapple index|Exception has been thrown|Could not get lobby info|Timeout Socket|Object reference not set|Validated outfit|Packet has been already received|could not be played| no free slot for incoming connection|Shot denied for|Filename:|If you absolutely need|The effective box size|BoxColliders does not|image effect|RectTransform|could not load|platform assembly|Loading|deprecated|Current environment|object was null|NoResources|Debug|Sending current player|has been disconnected by timeout|song ended for team |sent incorrect|Error: NoResources Socket: |or call this function only for existing animations|Could not get lobby info for player|Filename:|does not support|The effective box size has been|If you absolutely need to use|Visible only by this ship|NullReferenceException|filename unknown)"

# CLOSE PREVIOUS POWERSHELL CAPTURE WINDOWS
Function CloseWindowByTitle($title) {
	$result = (Get-Process |where {$_.mainWindowTItle -like "*$title*" -and $_.Name -eq "powershell" })
	if ($result.Count -ge 1) {
		$result | Kill -Force -Confirm:$false
	}
}

# REMOVE UTF8 BOM FROM FILE
function Remove-Utf8BOM
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
		[string] $InputObject,

		[Parameter(Mandatory = $true, Position = 0)]
		[string] $Pattern1,

		[Parameter(Mandatory = $false, Position = 1)]
		[string] $Pattern2,

		[Parameter(Mandatory = $false, Position = 2)]
		[string] $Pattern3,

		[Parameter(Mandatory = $false, Position = 3)]
		[string] $ExcludePattern,

		[Parameter(Mandatory = $false, Position = 4)]
		[string] $additionalLog
	)
	begin{
		$r1 = [regex]$Pattern1;
		$r2 = [regex]$Pattern2;
		$r3 = [regex]$Pattern3;
		$ExcludePattern = [regex]$ExcludePattern;
		$pOnline = [regex]".*A client connected on socket \d{0,2}, there are now (?<online>\d{0,2}) clients connected.*|.*disconnect from \d{0,2}, there are now (?<online>\d{0,2}) clients connected.*";
	}
	process
	{
		# EXCLUDE PATTERN
		if ($inputObject.Length -lt 2 -or ([bool]$ExcludePattern -eq $True -and [bool](Select-String -input $inputObject -Pattern $ExcludePattern -AllMatches))) { return; }
		
		# MATCHES
		$ms1 = $r1.Matches($inputObject)
		$ms2 = $r2.Matches($inputObject)
		$ms3 = $r3.Matches($inputObject)
		$ms4 = $pOnline.Matches($inputObject)
		$startIndex = 0

		# GREEN COLOR
		if ([bool]$Pattern2 -eq $True) {
			foreach($m in $ms1)
			{
				$nonMatchLength = $m.Index - $startIndex
				Write-Host $inputObject.Substring($startIndex, $nonMatchLength) -NoNew
				Write-Host $m.Value -ForegroundColor Green -NoNew
				$startIndex = $m.Index + $m.Length
			}
			
		}

		# YELLOW COLOR
		if ([bool]$Pattern2 -eq $True) {
			foreach($m in $ms2)
			{
				$nonMatchLength = $m.Index - $startIndex
				Write-Host $inputObject.Substring($startIndex, $nonMatchLength) -NoNew
				Write-Host $m.Value -ForegroundColor Yellow -NoNew
				$startIndex = $m.Index + $m.Length
			}
		}
		
		# RED COLOR
		if ([bool]$Pattern3 -eq $True) {
			foreach($m in $ms3)
			{
				$nonMatchLength = $m.Index - $startIndex
				Write-Host $inputObject.Substring($startIndex, $nonMatchLength) -NoNew
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
			$pswindow.WindowTitle = $pswindow.WindowTitle -replace 'PlayersOnline: \d{0,2}', "PlayersOnline: $playersOnline"
		}

		# CAPTURE ADDITIONAL LOG?
		if ([bool]$additionalLog -eq $true) {
			$ms1[0].Value | Out-File $additionalLog -Append
			$ms2[0].Value | Out-File $additionalLog -Append
			$ms3[0].Value | Out-File $additionalLog -Append
			<#if ($startIndex -lt $inputObject.Length) {
				$inputObject  | Out-File "OutNew" -Append
			}#>
		}
		
		Write-Host
	}
}
########################################################################################
###################################### START MAIN ######################################
########################################################################################

#Close previous window if present
CloseWindowByTitle "$serverIp`:$serverPort"

# SET WINDOW PROPERTIES
$pshost = get-host
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

Start-Sleep 1

# START SERVER
$validated = $false
$v = 1
$s = 1;

# CHECK IF NOT VALIDATED AND STARTED
while (-not [bool]($serverProcess = (Get-Process | ? Path -ieq $serverExePath)) `
			-or `
			(-not ($validated) -and -not [bool]($serverProcess = (Get-Process | ? Path -ieq $serverExePath))) )
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
		$pinfo.Arguments = "+login anonymous +force_install_dir $serverPath +app_update 423410 validate +quit"
		$p = New-Object System.Diagnostics.Process
		$p.StartInfo = $pinfo
		$p.Start() | Out-Null
		$p.WaitForExit()
		$stdout = $p.StandardOutput.ReadToEnd()
		$stderr = $p.StandardError.ReadToEnd()
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
			$serverCfg = $serverCfg -replace 'playerUpdateRate=\d{2}', "playerUpdateRate=$playerUpdateRate"
			$result = $serverCfg | Out-File $serverCfgPath -Encoding UTF8
			
			Remove-Utf8BOM $serverCfgPath
			Write-Host " OK" -ForegroundColor Green
		}
		
		while (-not [bool]($serverProcess = (Get-Process | ? Path -ieq $serverExePath))) {
		
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
			$serverProcess = (Get-Process | ? Path -ieq $serverExePath)
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


$pswindow.WindowTitle = "$serverName | $serverIp`:$serverPort | UpdateRate`: $serverPlayerUpdateRate | ServerOnline`: $([bool]$serverProcess) | PlayersOnline`: 0"

while (-not (Test-Path $logFilePath)) { Write-Host "Waiting for log..."; Start-Sleep 10;  }
Get-Content $logFilePath -Wait -Tail 100000 | StartServerMonitor -Pattern1 $pattern1 -Pattern2 $pattern2 -Pattern3 $pattern3 -ExcludePattern $ExcludePattern -additionalLog $additionalLogPath