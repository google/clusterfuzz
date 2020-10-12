# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

Set-PSDebug -Trace 1
Write-Host "Start"

# Helper variables.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$webClient = New-Object System.Net.WebClient
$webClient.Headers.add('Metadata-Flavor', 'Google')
$hostName = ($webClient.DownloadString('http://metadata.google.internal/computeMetadata/v1/instance/hostname')).split('.')[0]
$preemptible = [string]($hostname -Match '-pre-')
$gpu = $hostname -Match '-gpu-'
$queueOverride = If ($gpu) {'WINDOWS_WITH_GPU'} Else {''}

# For NFS, it is recommended to setup a Google Cloud Filestore instance.
# See https://cloud.google.com/filestore/docs.
$nfsHost = '10.0.0.2'
$nfsVolume = 'cfvolume'
$nfsRoot = If (Test-Connection $nfsHost) {'X:\'} Else {''}

$registrySetupFilePath = 'c:\registry.setup'
$packageSetupFilePath = 'c:\package.setup.1'

# Create clusterfuzz admin account.
$domain = 'CLUSTERFUZZ-WIN'
$username = 'clusterfuzz'
$password = $webClient.DownloadString('http://metadata.google.internal/computeMetadata/v1/project/attributes/windows-password')
$group = 'Administrators'
$adsi = [ADSI]"WinNT://$env:COMPUTERNAME"
$existing = $adsi.Children | where {$_.SchemaClassName -eq 'user' -and $_.Name -eq $Username }
if ($existing -eq $null) {
    & NET USER $Username $Password /add /y /expires:never
    & NET LOCALGROUP $group $Username /add
}
else {
    $existing.SetPassword($Password)
}
& WMIC USERACCOUNT WHERE "Name='$Username'" SET PasswordExpires=FALSE

# Make sure NFS client is installed.
Add-WindowsFeature NFS-Client

# Set registry keys.
$s = "if not exist $registrySetupFilePath ( netdom renamecomputer %COMPUTERNAME% /Newname $hostName /force`nreg add `"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`" /v DisableAntispyware /t REG_DWORD /f /d 1`nreg add `"HKLM\SYSTEM\CurrentControlSet\Control\Windows`" /v NoInteractiveServices /t REG_DWORD /f /d 0`nreg add `"HKLM\SYSTEM\ControlSet001\Control\FileSystem`" /v LongPathsEnabled /t REG_DWORD /f /d 1`nreg add `"HKLM\SYSTEM\CurrentControlSet\Control\FileSystem`" /v LongPathsEnabled /t REG_DWORD /f /d 1`nreg add `"HKLM\Software\Microsoft\ClientForNFS\CurrentVersion\Default`" /v AnonymousUid /t REG_DWORD /f /d 1337`nreg add `"HKLM\Software\Microsoft\ClientForNFS\CurrentVersion\Default`" /v AnonymousGid /t REG_DWORD /f /d 1337`nreg add `"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon`" /v AutoAdminLogon /t REG_SZ /f /d 1`nreg add `"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon`" /v DefaultUserName /t REG_SZ /f /d $username`nreg add `"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon`" /v DefaultPassword /t REG_SZ /f /d `"$password`"`nreg add `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`" /v DefaultDomainName /t REG_SZ /d `"CLUSTERFUZZ-WIN`" /f`nreg add `"HKLM\Software\Microsoft\Windows\Windows Error Reporting`" /v Disabled /t REG_DWORD /f /d 1`nreg add `"HKLM\Software\Microsoft\Windows\Windows Error Reporting`" /v DontShowUI /t REG_DWORD /f /d 1`nreg add `"HKCU\Software\Microsoft\Windows\Windows Error Reporting`" /v Disabled /t REG_DWORD /f /d 1`nreg add `"HKCU\Software\Microsoft\Windows\Windows Error Reporting`" /v DontShowUI /t REG_DWORD /f /d 1`ncopy NUL $registrySetupFilePath`n# shutdown -t 30 -r -f`n)`n"
Set-Content c:\autologin.bat $s

# Set the following variable globally in system environment.
setx /M PYTHONUNBUFFERED "1"
setx /M PYTHONDONTWRITEBYTECODE "1"
setx /M PYTHONIOENCODING "UTF-8"
setx /M RUBY_GC_HEAP_OLDOBJECT_LIMIT_FACTOR "0.9"

# Set startup script contents.
$s = "if not exist $registrySetupFilePath ( EXIT )`nw32tm /resync`nnetsh winhttp import proxy source=ie`nnfsadmin client config protocol=tcp+udp UseReservedPorts=yes`nnfsadmin client stop`nnfsadmin client start`nset NFS_HOST=$nfsHost`nset NFS_VOLUME=$nfsVolume`nset NFS_ROOT=$nfsRoot`nmount -o anon -o nolock -o retry=10 $nfsHost`:/$nfsVolume $nfsRoot`nnet start w32time`nw32tm /resync`nset PREEMPTIBLE=$preemptible`nset QUEUE_OVERRIDE=$queueOverride`nset USER=bot`nset BOT_TMPDIR=c:\tmp`nset PYTHONPATH=c:\clusterfuzz\src`nset ROOT_DIR=c:\clusterfuzz`nset PATH=c:\java\bin;c:\python37;c:\python27;c:\Windows\System32;c:\nodejs;c:\Program Files (x86)\Windows Kits\10\Debuggers\x64;c:\Program Files (x86)\Google\Cloud SDK\google-cloud-sdk\bin;%PATH%`nc: `ncd \ `ncd clusterfuzz\src\python\bot\startup `npython -W ignore run.py"
Set-Content c:\startup.bat $s

if (!(Test-Path ($packageSetupFilePath))) {

# Create helpers.
$shell = new-object -com shell.application
Function unzip($fileName, $folder = "c:\") {
  $zip = $shell.NameSpace($fileName)
  foreach($item in $zip.items()) {
    $shell.Namespace($folder).copyhere($item)
  }
}

# Disable NetBIOS over TCP/IP
wmic nicconfig where TcpipNetbiosOptions=0 call SetTcpipNetbios 2
wmic nicconfig where TcpipNetbiosOptions=1 call SetTcpipNetbios 2

# Create temp directories.
$tmp = "c:\cftemp"
$tmp2 = "c:\tmp"
if (!(Test-Path ($tmp))) {
  new-item $tmp -itemtype directory
}
if (!(Test-Path ($tmp2))) {
  new-item $tmp2 -itemtype directory
}

# Download Windows 10 SDK.
$fileName = "$tmp\winsdksetup.exe"
if (!(Test-Path ($fileName))) {
  $webClient.DownloadFile("https://commondatastorage.googleapis.com/clusterfuzz-data/winsdksetup.exe", $fileName)
  cmd /c $fileName /q
}

# Download Visual C++ 2013 redistributable package (64-bit).
$fileName = "$tmp\vcredist_2013_x64.exe"
if (!(Test-Path ($fileName))) {
  $webClient.DownloadFile("https://commondatastorage.googleapis.com/clusterfuzz-data/vcredist_2013_x64.exe", $fileName)
  cmd /c $fileName /q
}

# Download Visual C++ 2013 redistributable package (32-bit).
$fileName = "$tmp\vcredist_2013_x86.exe"
if (!(Test-Path ($fileName))) {
  $webClient.DownloadFile("https://commondatastorage.googleapis.com/clusterfuzz-data/vcredist_2013_x86.exe", $fileName)
  cmd /c $fileName /q
}

# Download Visual C++ 2015/2017/2019 redistributable package (64-bit).
$fileName = "$tmp\vcredist_2015_x64.exe"
if (!(Test-Path ($fileName))) {
  $webClient.DownloadFile("https://commondatastorage.googleapis.com/clusterfuzz-data/vcredist_2015_x64.exe", $fileName)
  cmd /c $fileName /q
}

# Download Visual C++ 2015/2017/2019 redistributable package (32-bit).
$fileName = "$tmp\vcredist_2015_x86.exe"
if (!(Test-Path ($fileName))) {
  $webClient.DownloadFile("https://commondatastorage.googleapis.com/clusterfuzz-data/vcredist_2015_x86.exe", $fileName)
  cmd /c $fileName /q
}

# Download VS 2008 compiler for python packages.
$fileName = "$tmp\VCForPython27.msi"
if (!(Test-Path ($fileName))) {
  $webClient.DownloadFile("https://commondatastorage.googleapis.com/clusterfuzz-data/VCForPython27.msi", $fileName)
  cmd /c msiexec /i $fileName /quiet /qn /norestart
}

# Download msdia120.dll, needed for llvm symbolizer to work.
$fileName = "$tmp\msdia120.dll"
if (!(Test-Path ($fileName))) {
  $webClient.DownloadFile("https://commondatastorage.googleapis.com/clusterfuzz-data/msdia120.dll", $fileName)
  cmd /c regsvr32 /s $fileName
}

# Download msdia140.dll, needed for llvm symbolizer to work.
$fileName = "$tmp\msdia140.dll"
if (!(Test-Path ($fileName))) {
  $webClient.DownloadFile("https://commondatastorage.googleapis.com/clusterfuzz-data/msdia140.dll", $fileName)
  cmd /c regsvr32 /s $fileName
}

# Install Python 2.7.15.
$fileName = "$tmp\python-2.7.15.amd64.msi"
if (!(Test-Path ($fileName))) {
  $webClient.DownloadFile("https://commondatastorage.googleapis.com/clusterfuzz-data/python-2.7.15.amd64.msi", $fileName)
  Remove-Item c:\python27 -Recurse -ErrorAction Ignore
  cmd /c msiexec /qn /i $fileName TARGETDIR=c:\python27
}

Copy-Item "c:\python27\python.exe" -Destination "c:\python27\python2.exe"

$fileName = "$tmp\python-3.7.7-amd64.exe"
if (!(Test-Path ($fileName))) {
  $webClient.DownloadFile("https://www.python.org/ftp/python/3.7.7/python-3.7.7-amd64.exe", $fileName)
  Remove-Item c:\python37 -Recurse -ErrorAction Ignore
  cmd /c $fileName /quiet InstallAllUsers=1 Include_test=0 TargetDir=c:\python37
}

# Install specific python package versions.
cmd /c c:\python27\python -m ensurepip --default-pip
cmd /c c:\python27\python -m pip install -U pip
cmd /c c:\python27\python -m pip install -U setuptools
cmd /c c:\python27\python -m pip install -U wheel
cmd /c c:\python27\python -m pip install crcmod==1.7 pyOpenSSL==17.4.0 pywinauto==0.6.4 psutil==5.4.7 future==0.17.1

cmd /c c:\python37\python -m pip install -U pip
cmd /c c:\python37\python -m pip install pipenv

# Install NodeJS.
$fileName = "$tmp\nodejs.zip"
if (!(Test-Path ($fileName))) {
  $webClient.DownloadFile("https://commondatastorage.googleapis.com/clusterfuzz-data/nodejs.zip", $fileName)
  unzip $fileName
}

# Install Java.
$fileName = "$tmp\openjdk-11.0.2_windows-x64_bin.zip"
if (!(Test-Path ($fileName))) {
  $webClient.DownloadFile("https://commondatastorage.googleapis.com/clusterfuzz-data/openjdk-11.0.2_windows-x64_bin.zip", $fileName)
  unzip $fileName
  mv C:\jdk-11.0.2 C:\java
}

# Install Chrome, helps to install the google crash handler.
$fileName = "$tmp\ChromeSetup.exe"
if (!(Test-Path ($fileName))) {
  $webClient.DownloadFile("https://commondatastorage.googleapis.com/clusterfuzz-data/ChromeSetup.exe", $fileName)
  cmd /c $fileName /silent /installsource silent /install
}

# Install Google crash handler.
$fileName = "$tmp\GoogleUpdateSetup.exe"
if (!(Test-Path ($fileName))) {
  $webClient.DownloadFile("https://commondatastorage.googleapis.com/clusterfuzz-data/GoogleUpdateSetup.exe", $fileName)
  cmd /c $fileName /install "runtime=true^&needsadmin=false" /silent
}

# Download PSTools
$fileName = "$tmp\pstools.zip"
if (!(Test-Path ($fileName))) {
  $webClient.DownloadFile("https://commondatastorage.googleapis.com/clusterfuzz-data/PSTools.zip", $fileName)
  unzip $fileName
}

# Download and install google-fluentd
$fileName = "$tmp\StackdrvierLogging-v1-3.exe"
if (!(Test-Path ($fileName))) {
  $webClient.DownloadFile("https://dl.google.com/cloudagents/windows/StackdriverLogging-v1-3.exe", $fileName)
  cmd /c $fileName /S

  $configFile = "C:\GoogleStackdriverLoggingAgent\fluent.conf"
  $loggingConfig = @"
    `r
    <source>`r
      type tcp`r
      format json`r
      port 5170`r
      bind 127.0.0.1`r
      tag bot`r
    </source>`r
"@
  Add-Content $configFile $loggingConfig
  (Get-Content $configFile) -replace "flush_interval 5s","flush_interval 60s" | out-file -encoding ASCII $configFile

  Start-Sleep -s 30

  net stop fluentdwinsvc
  net start fluentdwinsvc
}

# Install NVIDIA driver (Tesla P100).
$nvidiaDriverVersion = "391.29"
$fileName = "$tmp\$nvidiaDriverVersion-tesla-desktop-winserver2016-international.exe"
if ($gpu -and !(Test-Path ($fileName))) {
  $webClient.DownloadFile("https://commondatastorage.googleapis.com/clusterfuzz-data/$nvidiaDriverVersion-tesla-desktop-winserver2016-international.exe", $fileName)

  # Unpack files by running installer, then run setup.exe from extracted path.
  cmd /c $fileName -s
  cmd /c "C:\NVIDIA\DisplayDriver\$nvidiaDriverVersion\Win10_64\International\setup.exe" -s
}

# Install NVIDIA GRID driver (needs to be done after GPU driver is installed).
$nvidiaGridDriverVersion = "386.09"
$fileName = "$tmp\${nvidiaGridDriverVersion}_grid_win10_server2016_64bit_international.exe"
if ($gpu -and !(Test-Path ($fileName))) {
  $webClient.DownloadFile("https://commondatastorage.googleapis.com/clusterfuzz-data/${nvidiaGridDriverVersion}_grid_win10_server2016_64bit_international.exe", $fileName)

  # Unpack files by running installer, then run setup.exe from extracted path.
  cmd /c $fileName -s
  cmd /c C:\NVIDIA\$nvidiaGridDriverVersion\setup.exe -s
}

# Set time zone.
cmd /c tzutil /s "Pacific Standard Time"
cmd /c net stop w32time
cmd /c net start w32time
cmd /c w32tm /resync

# Setup OpenSSH
$fileName = "$tmp\OpenSSH-Win64.zip"
if (!(Test-Path ($fileName))) {
  $webClient.DownloadFile("https://commondatastorage.googleapis.com/clusterfuzz-data/OpenSSH-Win64.zip", $fileName)
  unzip $fileName 'c:\Program Files'
  # OpenSSH needs to be in c:\Program Files\OpenSSH because its default
  # sshd_config expects that folder.
  move "c:\Program Files\OpenSSH-Win64" "c:\Program Files\OpenSSH"
  Invoke-Expression -Command "& 'c:\Program Files\OpenSSH\install-sshd.ps1'"
  cmd /s /c "cd /d "c:\Program Files\OpenSSH" && "C:\Program Files\OpenSSH\ssh-keygen.exe" -A"
  netsh advfirewall firewall add rule name="SSH Port" dir=in action=allow protocol=TCP localport=22
  cmd /c sc config "sshd" start= auto
  cmd /c sc failure "sshd"  actions= restart/60000/restart/60000/restart/60000 reset= 86400
  net start sshd
}

# Update root certs. certutil called twice due to being crashy on first call.
certutil -generateSSTFromWU roots.sst
certutil -generateSSTFromWU roots.sst
Import-Certificate -FilePath roots.sst -CertStoreLocation Cert:\LocalMachine\Root > $null

# Clean up cached symbols directory.
rm "C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\sym" -Recurse -Force
rm "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\sym" -Recurse -Force

# Get deployment bucket from project metadata.
$deploymentBucket = $webClient.DownloadString('http://metadata.google.internal/computeMetadata/v1/project/attributes/deployment-bucket')

# Download ClusterFuzz source.
rm c:\clusterfuzz -Recurse -Force
$fileName = "$tmp\clusterfuzz.zip"
gsutil cp gs://$deploymentBucket/windows-3.zip $fileName
unzip $fileName

# Resize partition to max available size.
$MaxSize = (Get-PartitionSupportedSize -DriveLetter c).sizeMax
Resize-Partition -DriveLetter c -Size $MaxSize

Set-Content $packageSetupFilePath " "

# Run autologin so that the hostname changes at reboot.
c:\autologin.bat

Write-Host "Restarting"

Restart-Computer -Force
exit

} # !(Test-Path ($packageSetupFilePath))

Set-Content $packageSetupFilePath "Skipped package install"

# Schedule chkdsk on every reboot.
echo y | chkdsk C: /F /I /C

# Install Pipfile dependencies
$env:Path += ";c:\python37;c:\python37\scripts"
cd c:\clusterfuzz
cmd /c c:\python37\scripts\pipenv install --deploy --system

# Can't be managed by pipenv due to https://github.com/pypa/pipenv/issues/3193.
cmd /c c:\python37\python -m pip install pywinauto==0.6.8

# Run the scripts.
Write-Host "Run scripts"
c:\autologin.bat
c:\PsExec.exe \\$hostName -accepteula -h -i 0 -username `""$domain\$username"`" -password `""$password"`" c:\startup.bat


