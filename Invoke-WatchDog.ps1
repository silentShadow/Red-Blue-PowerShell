function Get-RegKeyValue {
    param(
        $e,

        [Parameter(Mandatory=$true)]
        [string]
        $Computername = $env:COMPUTERNAME,
        
        [Parameter(Mandatory=$true)]
        [string]
        [ValidateSet("HKCR", "HKCU", "HKLM", "HKUS", "HKCC")]
        $Hive,

        [Parameter(Mandatory=$true)]
        [string]
        $Key
    )


        switch ($Hive) {
            "HKCR" {$reghive = 2147483648}
            "HKCU" {$reghive = 2147483649}
            "HKLM" {$reghive = 2147483650}
            "HKUS" {$reghive = 2147483651}
            "HKCC" {$reghive = 2147483653}
        }
    
        $reg = [wmiclass]"\\$Computername\root\default:StdRegProv"
        $subkeys = $reg.EnumValues($reghive, $Key)

        $subkeys | foreach {
            $_
        }



        $subkeys.snames | foreach {
            if ($_ -notlike "{*}") {
                $key2 = "$key\$_"
                
                Write-Output $key2
            }
        }
    }



function Remove-RegKeyValue {
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $Computername = $env:COMPUTERNAME,
        
        [Parameter(Mandatory=$true)]
        [string]
        [ValidateSet("HKCR", "HKCU", "HKLM", "HKUS", "HKCC")]
        $Hive,

        [Parameter(Mandatory=$true)]
        [string]
        $Key
    )

    PROCESS {
        switch ($Hive) {
            "HKCR" {$reghive = 2147483648}
            "HKCU" {$reghive = 2147483649}
            "HKLM" {$reghive = 2147483650}
            "HKUS" {$reghive = 2147483651}
            "HKCC" {$reghive = 2147483653}
        }

        $reg = [wmiclass]"\\$Computername\root\default:StdRegProv"
        $reg.DeleteKey($reghive, $Key)
    }
}

#Get-RegKeyValue -Computername $env:COMPUTERNAME -Hive HKLM -Key "Software\Microsoft\Windows\CurrentVersion\Run"
#Get-RegKeyValue -Computername $env:COMPUTERNAME -Hive HKLM -Key "Software\Microsoft\Windows\CurrentVersion\Uninstall"



<#

TODO:
    Get the values of the keys by determing the key's type
    Need to find the most efficient way to do this for each key found

    Switch statement does ok but need to try a hashtable or convertfrom-stringdata DATA{} object

    $regtypes = ConvertFrom-StringData -StringData @"
1 = REG_SZ
2 = REG_EXPAND_SZ
3 = REG_BINARY
4 = REG_DWORD
7 = REG_MULTI_SZ
"@

    $regtypes.GetEnumerator() | sort Key


$reg = [wmiclass]"\\$env:Computername\root\default:StdRegProv"
$reg | gm



$subs = $reg.EnumValues(2147483650, "Software\Microsoft\Windows\CurrentVersion\RunOnce")
$subs


$numValues = ($subs.sNames).Count


$subs | foreach {
    $_.Types
    switch ($_.Types) {
        1 {$type = "REG_SZ"}
        2 {$type = "REG_EXPAND_SZ"}
        3 {$type = "REG_BINARY"}
        4 {$type = "REG_DWORD"}
        7 {$type = "REG_MULTI_SZ"}
    }

    $type
}

#>


function Get-Filez {
    param ($e)
        $time = $e.TimeGenerated     # what time
     
        if (!($e.SourceIdentifier -eq "modfile")){
            
            $pc = $e.SourceEventArgs.NewEvent.TargetInstance.PartComponent 
            $data = $pc -split "="
            $file = $data[1].Replace("\\","\").Replace("""","")
         }
     
         else {
            $file = $e.SourceEventArgs.NewEvent.PreviousInstance.Name
         }
 
     switch ($e.SourceIdentifier) {
        "newfiles" {Write-Host -ForegroundColor Cyan "$time : File $file has been created"; break}
        "delfiles" {Write-Host -ForegroundColor Red "$time : File $file has been deleted"; break}
        "modfile"  {Write-Host -ForegroundColor Green "$time : File $file has been modified"; break}
     }
}



function Show-BalloonTip {
 
    [CmdletBinding(SupportsShouldProcess = $true)]
        param(
            [Parameter(Mandatory=$true,
                       Position=0)]
            $Text="PShell Monitor 2.0 protecting you from Metasploit",
   
            [Parameter(Mandatory=$true,
                       Position=1)]
            $Title="PShell Monitor 2.0",

            [Parameter(Mandatory=$false,
                       Position=2)]
            [ValidateSet($true, $false)]
            $Visible=$true,
   
            [ValidateSet('None', 'Info', 'Warning', 'Error')]
            $Icon = 'Info',

            $Timeout = 10000
        )
 
        Add-Type -AssemblyName System.Windows.Forms

        if ($script:balloon -eq $null) {
            $script:balloon = New-Object System.Windows.Forms.NotifyIcon
    
        }

        $path                    = Get-Process -id $pid | Select-Object -ExpandProperty Path
        $balloon.Icon            = [System.Drawing.Icon]::ExtractAssociatedIcon($path)
        $balloon.BalloonTipIcon  = $Icon
        $balloon.BalloonTipText  = $Text
        $balloon.BalloonTipTitle = $Title
        $balloon.Visible         = $Visible

        $balloon.ShowBalloonTip($Timeout)
}



function Find-Persistence {
    param ($e)
        $time = $e.TimeGenerated     # what time
        
        $pc = $e.SourceEventArgs.NewEvent.TargetInstance.PartComponent 
        $data = $pc -split "="
        $file = $data[1].Replace("\\","\").Replace("""","")

        Write-Host -ForegroundColor Cyan "File $file was created"

        if( (Get-Item -Path $file).Extension -eq ".vbs" -and (Get-Item -Path $file).BaseName -cmatch "[a-zA-z]{8}") {
            Write-Host -ForegroundColor Red -BackgroundColor Yellow "Possible persistence file found!!!"

            Show-BalloonTip -Title "Possible Persistence" -Text "$file is a possible persistence file... Trying to remove it" -Icon Warning

            try{
                Remove-Item -Path $file -Force -Verbose -ErrorAction Stop -ErrorVariable $CustomError
            }
            catch{
                Write-Error -Message $CustomError
            }
        }
}


$WMIProcStart = @{
    #Query = "SELECT * FROM __InstanceCreationEvent WITHIN 3 WHERE TargetInstance ISA 'Win32_Process'"
    Query = "SELECT * FROM Win32_ProcessStartTrace"
    Action = {
        if ($Event.SourceEventArgs.NewEvent) {
            $Global:Data = $Event
            Write-Host -Fore Green -Back Black ("Process: {0} runnnng with PID: {1}" -f $event.SourceEventArgs.NewEvent.ProcessName,
                                                                                        $event.SourceEventArgs.NewEvent.ProcessId) 
        }
    }

    SourceIdentifier = "ProcessStart"
}


$WMIProcStop = @{
    Query = "SELECT * FROM Win32_ProcessStopTrace"
    Action = { Write-Host -Fore Red -Back Black ("Process $($event.SourceEventArgs.NewEvent.ProcessName) terminated") }
    SourceIdentifier = "ProcessStop"

}


$TempDirFileCreate = @{
    Query = "SELECT * FROM __InstanceCreationEvent WITHIN 2 
                WHERE TargetInstance ISA 'CIM_DirectoryContainsFile' 
                AND TargetInstance.GroupComponent = 'Win32_Directory.Name=""C:\\\\Windows\\\\Temp""'"
    Action = {Find-Persistence($event)}
    SourceIdentifier = "File Creation"
}


$TempDirFileDelete = @{
    Query = "SELECT * FROM __InstanceDeletionEvent WITHIN 2 
                WHERE TargetInstance ISA 'CIM_DirectoryContainsFile' 
                AND TargetInstance.GroupComponent = 'Win32_Directory.Name=""C:\\\\Windows\\\\Temp""'"
    Action = { Write-Host -Fore Red "A file was deleted from the Windows Temp dir" }
    SourceIdentifier = "File Deletion"
}


$UserTempDir = @{
    Query = "SELECT * FROM __InstanceDeletionEvent WITHIN 2 
                WHERE TargetInstance ISA 'CIM_DirectoryContainsFile' 
                AND TargetInstance.GroupComponent = 'Win32_Directory.Name=""C:\\\\Users\\\\admin\\\\AppData\\\\Local\\\\Temp""'"
    Action = {Find-Persistence($event)}
    SourceIdentifier = "User Temp Dir"
}


$RunKeyChange = @{
    Query = "SELECT * FROM RegistryKeyChangeEvent 
                WHERE Hive='HKEY_LOCAL_MACHINE' 
                AND KeyPath='SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'"
    Action = {$Global:Reg = $event
              Write-Host -Fore Yellow -Back Black "RegKey change for HKLM::Software\Microsoft\CurrentVersion\Run"
              Show-BalloonTip -Title "Run Key Change" -Text "The RunOnce Key has been modified!" -Icon Warning
    }
    SourceIdentifier = "Run Key"
}


$RunOnceKeyChange = @{
    Query = "SELECT * FROM RegistryKeyChangeEvent 
                WHERE Hive='HKEY_LOCAL_MACHINE' 
                AND KeyPath='SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'"
    Action = {Write-Host -Fore Yellow -Back Black "RegKey change for HKLM::Software\Microsoft\CurrentVersion\RunOnce"
              Show-BalloonTip -Title "RunOnce Key Change" -Text "The RunOnce Key has been modified!" -Icon Warning
    }
    SourceIdentifier = "RunOnce Key"
}


# This seems to do the exact same thing as RegistryKeyChangeEvent?? 
$TreeChange = @{
    Query = "SELECT * FROM RegistryTreeChangeEvent 
                WHERE Hive='HKEY_LOCAL_MACHINE' 
                AND RootPath='SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'"
    Action = {Show-BalloonTip -Title "Run Key Change" -Text "The Run Key has been modified!" -Icon Warning}
    SourceIdentifier = "Tree Change"
}


<#
    Clean up any current subscribers that match the source identifiers since
    there cannot be any duplicates
#>
function Invoke-Cleanup {
    if (Get-EventSubscriber | where {$_.SourceIdentifier -eq "ProcessStart"  })     { Unregister-Event -SourceIdentifier "ProcessStart"  }
    if (Get-EventSubscriber | where {$_.SourceIdentifier -eq "ProcessStop"   })     { Unregister-Event -SourceIdentifier "ProcessStop"   }
    if (Get-EventSubscriber | where {$_.SourceIdentifier -eq "File Creation" })     { Unregister-Event -SourceIdentifier "File Creation" }
    if (Get-EventSubscriber | where {$_.SourceIdentifier -eq "File Deletion" })     { Unregister-Event -SourceIdentifier "File Deletion" }
    if (Get-EventSubscriber | where {$_.SourceIdentifier -eq "Run Key"       })     { Unregister-Event -SourceIdentifier "Run Key"       }
    if (Get-EventSubscriber | where {$_.SourceIdentifier -eq "RunOnce Key"   })     { Unregister-Event -SourceIdentifier "RunOnce Key"   }
    if (Get-EventSubscriber | where {$_.SourceIdentifier -eq "User Temp Dir" })     { Unregister-Event -SourceIdentifier "User Temp Dir" }
    if (Get-EventSubscriber | where {$_.SourceIdentifier -eq "Tree Change"   })     { Unregister-Event -SourceIdentifier "Tree Change"   }
}



Invoke-Cleanup


Register-WMIEvent @WMIProcStart
Register-WmiEvent @WMIProcStop
Register-WmiEvent @TempDirFileCreate
Register-WmiEvent @TempDirFileDelete
Register-WmiEvent @UserTempDir
#Register-WmiEvent @RunKeyChange
Register-WmiEvent @TreeChange
Register-WmiEvent @RunOnceKeyChange




# Kill any old jobs that are stopped
if (Get-Job | where state -eq stopped){
    $job = Get-Job | where state -eq stopped | select Id
    Write-Host -ForegroundColor Cyan "`nFound and removed stopped job(s)"
    Get-Job | where state -eq stopped | Remove-Job  
}

else {
    Write-Host -ForegroundColor Cyan "`nNo stopped job(s) found"
}
