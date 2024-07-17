$projectName = "UniAgent"
$localPath = "C:\inetpub\wwwroot\$projectName"
$siteName = $projectName
$appPoolName = $projectName
$zipFilePath = "C:\Users\subham.pandey\Desktop\UniAgent.zip"
$expandedPath = "C:\Users\subham.pandey\Desktop\$projectName"
$certificateFriendlyName = "UniAgentSelfSignedCert"

function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Output "This script needs to be run as an administrator."
    exit 1
}

try {
    # Check if IIS is installed and install if not using DISM
    $iisInstalled = (dism /online /get-features /format:table | Select-String -Pattern "IIS-WebServerRole" | Select-String -Pattern "Enabled")
    if (-not $iisInstalled) {
        Write-Output "IIS is not installed. Installing IIS..."
        Start-Process -FilePath "dism" -ArgumentList "/online /enable-feature /featurename:IIS-WebServerRole /all" -Wait -NoNewWindow
        Start-Process -FilePath "dism" -ArgumentList "/online /enable-feature /featurename:IIS-WebServerManagementTools /all" -Wait -NoNewWindow
        Start-Process -FilePath "dism" -ArgumentList "/online /enable-feature /featurename:IIS-ManagementConsole /all" -Wait -NoNewWindow

        # Additional IIS features
        Start-Process -FilePath "dism" -ArgumentList "/Online /Enable-Feature /FeatureName:IIS-DefaultDocument /All" -Wait -NoNewWindow
        Start-Process -FilePath "dism" -ArgumentList "/Online /Enable-Feature /FeatureName:IIS-ISAPIFilter /All" -Wait -NoNewWindow
        Start-Process -FilePath "dism" -ArgumentList "/Online /Enable-Feature /FeatureName:IIS-ISAPIExtensions /All" -Wait -NoNewWindow
        Start-Process -FilePath "dism" -ArgumentList "/Online /Enable-Feature /FeatureName:IIS-ManagementService /All" -Wait -NoNewWindow
        Start-Process -FilePath "dism" -ArgumentList "/Online /Enable-Feature /FeatureName:IIS-ManagementScriptingTools /All" -Wait -NoNewWindow

        # Install ASP.NET if needed
        Start-Process -FilePath "dism" -ArgumentList "/Online /Enable-Feature /FeatureName:IIS-ASPNET45 /All" -Wait -NoNewWindow

        # Restart IIS
        Restart-Service W3SVC

        if ($?) {
            Write-Output "IIS and features installed successfully."
        } else {
            throw "Failed to install IIS and features."
        }
    }

    # Ensure WebAdministration module is available
    Import-Module WebAdministration -ErrorAction Stop

    # Download the UniAgent.zip from GitHub repository
    if (Test-Path $zipFilePath) {
        Remove-Item -Path $zipFilePath -Force
    }
    Invoke-WebRequest -Uri "https://github.com/subhampandey-consilium/UniAgent/raw/main/UniAgent.zip" -OutFile $zipFilePath

    # Create Application Pool if it doesn't exist
    if (Get-Command -Name New-WebAppPool -ErrorAction SilentlyContinue) {
        if (-not (Test-Path "IIS:\AppPools\$appPoolName")) {
            $appPool = New-WebAppPool -Name $appPoolName
            $appPool | Set-ItemProperty -Name "ManagedPipelineMode" -Value "Integrated"
            $appPool | Set-ItemProperty -Name "ManagedRuntimeVersion" -Value ""
            $appPool | Set-ItemProperty -Name "processModel.identityType" -Value "ApplicationPoolIdentity"
        }
    } else {
        throw "WebAdministration cmdlets are not available."
    }

    # Unzip the contents of UniAgent.zip to expandedPath
    Expand-Archive -Path $zipFilePath -DestinationPath $expandedPath -Force

    # Ensure the localPath directory exists and is empty
    if (Test-Path $localPath) {
        Remove-Item -Path "$localPath\*" -Recurse -Force
    } else {
        New-Item -Path $localPath -ItemType Directory
    }

    # Copy all files and folders from the expanded path to the localPath
    $sourcePath = "$expandedPath\$projectName"
    Get-ChildItem -Path $sourcePath -Recurse | ForEach-Object {
        $destinationPath = $_.FullName.Replace($sourcePath, $localPath)
        if ($_.PSIsContainer) {
            if (-not (Test-Path $destinationPath)) {
                New-Item -ItemType Directory -Path $destinationPath
            }
        } else {
            Copy-Item -Path $_.FullName -Destination $destinationPath -Force
        }
    }

    # Create self-signed certificate for HTTPS
    $cert = New-SelfSignedCertificate -CertStoreLocation "Cert:\LocalMachine\My" -DnsName "localhost" -FriendlyName $certificateFriendlyName -NotAfter (Get-Date).AddYears(5)

    # Check if the website already exists
    $existingSite = Get-WebSite -Name $siteName -ErrorAction SilentlyContinue
    if ($existingSite) {
        Write-Output "Website '$siteName' already exists. Removing and recreating..."
        Remove-WebSite -Name $siteName -Force
    }

    # Create Site in IIS
    New-WebSite -Name $siteName -PhysicalPath $localPath -Port 44305 -ApplicationPool $appPoolName -Force

    # Create HTTPS binding for the site
    New-WebBinding -Name $siteName -IPAddress "*" -Port 44305 -Protocol "https"
    $binding = Get-WebBinding -Name $siteName -Port 44305 -Protocol "https"
    $binding.AddSslCertificate($cert.Thumbprint, "My")

    Write-Output "Deployment completed successfully!"
} catch {
    Write-Output "An error occurred: $_"
}
