<#
.Name
Centrify.PowerShell.PAS.Logger.ps1

.Sample 

Copyright 2019 by written http://www.rebuiltarchitect.com
#>


# all logging settins are here on top
param(
    [Parameter(Mandatory=$false)]
        [string]$logFile = "$(gc env:computername).log",
    [Parameter(Mandatory=$false)]
        [string]$logLevel = "DEBUG", # ("DEBUG","INFO","WARN","ERROR","FATAL")
    [Parameter(Mandatory=$false)]
        [int64]$logSize = 10mb,
    [Parameter(Mandatory=$false)]
        [int]$logCount = 25
) 
# end of settings

function Write-Log-Line ($line, $logFile) {
    $logFile | %{ 
           If (Test-Path -Path $_) { Get-Item $_ } 
           Else { New-Item -Path $_ -Force } 
    } | Add-Content -Value $Line -erroraction SilentlyCOntinue
}

function Roll-logFile
{
    #function checks to see if file in question is larger than the paramater specified if it is it will roll a log and delete the oldes log if there are more than x logs.
    param(
        [string]$fileName = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")+".log", 
        [int64]$maxSize = $logSize, 
        [int]$maxCount = $logCount
    )
    $logRollStatus = $true
    if(test-path $filename) {
        $file = Get-ChildItem $filename
        # Start the log-roll if the file is big enough

        #Write-Log-Line "$Stamp INFO Log file size is $($file.length), max size $maxSize" $logFile
        #Write-Host "$Stamp INFO Log file size is $('{0:N0}' -f $file.length), max size $('{0:N0}' -f $maxSize)"
        if($file.length -ge $maxSize) {
            Write-Log-Line "$Stamp INFO Log file size $('{0:N0}' -f $file.length) is larger than max size $('{0:N0}' -f $maxSize). Rolling log file!" $logFile
            #Write-Host "$Stamp INFO Log file size $('{0:N0}' -f $file.length) is larger than max size $('{0:N0}' -f $maxSize). Rolling log file!"
            $fileDir = $file.Directory
            $fbase = $file.BaseName
            $fext = $file.Extension
            $fn = $file.name #this gets the name of the file we started with

            function refresh-log-files {
                 Get-ChildItem $filedir | ?{ $_.Extension -match "$fext" -and $_.name -like "$fbase*"} | Sort-Object lastwritetime
            }
            function fileByIndex($index) {
                $fileByIndex = $files | ?{($_.Name).split("-")[-1].trim("$fext") -eq $($index | % tostring 00)}
                #Write-Log-Line "LOGGER: fileByIndex = $fileByIndex" $logFile
                $fileByIndex
            }
            function getNumberOfFile($theFile) {
                $NumberOfFile = $theFile.Name.split("-")[-1].trim("$fext")
                if ($NumberOfFile -match '[a-z]'){
                    $NumberOfFile = "01"
                }
                #Write-Log-Line "LOGGER: GetNumberOfFile = $NumberOfFile" $logFile
                $NumberOfFile
            }

            refresh-log-files | %{
                [int32]$num = getNumberOfFile $_
                Write-Log-Line "LOGGER: checking log file number $num" $logFile
                if ([int32]$($num | % tostring 00) -ge $maxCount) {
                    write-host "Deleting files above log max count $maxCount : $_"
                    Write-Log-Line "LOGGER: Deleting files above log max count $maxCount : $_" $logFile
                    Remove-Item $_.fullName
                }
            }

            $files = @(refresh-log-files)

            # Now there should be at most $maxCount files, and the highest number is one less than count, unless there are badly named files, eg non-numbers
            for ($i = $files.count; $i -gt 0; $i--) {
                $newfilename = "$fbase-$($i | % tostring 00)$fext"
                #$newfilename = getFileNameByNumber ($i | % tostring 00) 
                if($i -gt 1) {
                    $fileToMove = fileByIndex($i-1)
                } else {
                    $fileToMove = $file
                }
                if (Test-Path $fileToMove.PSPath) { # If there are holes in sequence, file by index might not exist. The 'hole' will shift to next number, as files below hole are moved to fill it
                    write-host "moving '$fileToMove' => '$newfilename'"
                    #Write-Log-Line "LOGGER: moving $fileToMove => $newfilename" $logFile
                    # $fileToMove is a System.IO.FileInfo, but $newfilename is a string. Move-Item takes a string, so we need full path
                    Move-Item ($fileToMove.FullName) -Destination $fileDir\$newfilename -Force
                }
            }
        } else {
            $logRollStatus = $false
        }
    } else {
        $logrollStatus = $false
    }
    $LogRollStatus
}


Function Write-Log {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    [string]
    $Message,

    [Parameter(Mandatory=$False)]
    [String]
    $logFile = "log-$(gc env:computername).log",

    [Parameter(Mandatory=$False)]
    [String]
    $Level = "INFO"
    )
    #Write-Host $logFile
    $levels = ("DEBUG","INFO","WARN","ERROR","FATAL")
    $logLevelPos = [array]::IndexOf($levels, $logLevel)
    $levelPos = [array]::IndexOf($levels, $Level)
    $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss:fff")

    # First roll the log if needed to null to avoid output
    $Null = @(
        Roll-logFile -fileName $logFile -filesize $logSize -logcount $logCount
    )

    if ($logLevelPos -lt 0){
        Write-Log-Line "$Stamp ERROR Wrong logLevel configuration [$logLevel]" $logFile
    }

    if ($levelPos -lt 0){
        Write-Log-Line "$Stamp ERROR Wrong log level parameter [$Level]" $logFile
    }

    # if level parameter is wrong or configuration is wrong I still want to see the 
    # message in log
    if ($levelPos -lt $logLevelPos -and $levelPos -ge 0 -and $logLevelPos -ge 0){
        return
    }

    $Line = "$Stamp $Level $Message"
    Write-Log-Line $Line $logFile
}