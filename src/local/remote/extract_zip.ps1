# Exit if any command/function sees an error
$ErrorActionPreference = "Stop"

function Create-Dir-If-Not-Exist($fullPath) {
  if (!(Test-Path $fullPath)) {
    New-Item -ItemType Directory -Path $fullPath | Out-Null
  }
}

function Unzip($zipfile, $outdir)
{
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($zipfile)
    foreach ($entry in $zip.Entries)
    {
        $destFilePath = [System.IO.Path]::Combine($outdir, $entry.FullName)
        $isDir = ($destFilePath.EndsWith("\") -or $destFilePath.EndsWith("/"))

        if ($isDir) {
          Create-Dir-If-Not-Exist($destFilePath)
        } else {
          $parentDir = [System.IO.Path]::GetDirectoryName($destFilePath)

          # Sometimes its parent directory is not an entry in $zip.
          # Therefore, we need to make sure its parent dir exists.
          # Also, Create-Dir-If-Not-Exist(..) is an equivalent of `mkdir -p`.
          # Therefore, we don't need to worry about the parent's parent.
          Create-Dir-If-Not-Exist($parentDir)

          # DLLs need to be moved before being updated as they may be in use.
          if ($destFilePath.EndsWith(".dll") -Or $destFilePath.EndsWith(".pyd")) {
            $timestamp = Get-Date -UFormat %s
            Rename-Item -Path $destFilePath -NewName "$destFilePath.bak.$timestamp"
          }
          [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $destFilePath, $true) | Out-Null
        }
    }
    Write-Host "Extracted $($zip.Entries.Count) files."
}

$zip_file_path = [IO.Path]::GetFullPath("c:\clusterfuzz-source-stage.zip")
$dest_path = [IO.Path]::GetFullPath("c:\")

Unzip $zip_file_path $dest_path

