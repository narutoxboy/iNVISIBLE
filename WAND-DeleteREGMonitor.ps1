# Check if the script is running with administrative privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "This script requires administrative privileges. Please run as Administrator."
    exit
}

# Define the registry path to delete
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\DISPLAY"

# Function to recursively enumerate and delete registry keys
function Remove-RegistryKeyRecursively {
    param (
        [string]$Path
    )
    try {
        # Check if the path exists
        if (Test-Path $Path) {
            # Get all subkeys under the current path
            $subKeys = Get-ChildItem -Path $Path -ErrorAction SilentlyContinue
            foreach ($subKey in $subKeys) {
                # Recursively process each subkey
                Remove-RegistryKeyRecursively -Path "$Path\$($subKey.PSChildName)"
            }
            # Attempt to delete the current key
            try {
                Write-Host "Attempting to delete registry key: $Path"
                Remove-Item -Path $Path -Force -Recurse -ErrorAction Stop
                Write-Host "Successfully deleted registry key: $Path"
            }
            catch {
                Write-Host "Failed to delete registry key: $Path. Error: $_"
                # Continue to the next key if deletion fails
            }
        }
    }
    catch {
        Write-Host "Error processing registry path: $Path. Error: $_"
        # Continue processing other keys despite errors
    }
}

# Main execution
Write-Host "Starting deletion of registry keys under $registryPath"

# Check if the registry path exists
if (Test-Path $registryPath) {
    # Get all top-level subkeys under DISPLAY
    $topLevelKeys = Get-ChildItem -Path $registryPath -ErrorAction SilentlyContinue
    if ($topLevelKeys) {
        foreach ($key in $topLevelKeys) {
            # Process each top-level key recursively
            Remove-RegistryKeyRecursively -Path "$registryPath\$($key.PSChildName)"
        }
        # Attempt to delete the DISPLAY key itself if empty
        try {
            if (-not (Get-ChildItem -Path $registryPath -ErrorAction SilentlyContinue)) {
                Write-Host "Attempting to delete root registry key: $registryPath"
                Remove-Item -Path $registryPath -Force -ErrorAction Stop
                Write-Host "Successfully deleted root registry key: $registryPath"
            }
            else {
                Write-Host "Root registry key $registryPath still contains subkeys and was not deleted."
            }
        }
        catch {
            Write-Host "Failed to delete root registry key: $registryPath. Error: $_"
        }
    }
    else {
        Write-Host "No subkeys found under $registryPath"
    }
    Write-Host "Completed deletion process for registry keys under $registryPath"
}
else {
    Write-Host "Registry path $registryPath does not exist."
}