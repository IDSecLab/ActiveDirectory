<#
.SYNOPSIS
    Detects circular group nesting and excessive nesting depth in Active Directory.

.DESCRIPTION
    This script scans all Active Directory security groups and recursively evaluates their nested group structure.
    It identifies:
        - Circular nested groups
        - Excessively deep group nesting chains (based on a configurable max depth, default in script is 5)
        - Groups that failed to resolve due to permissions or directory issues

    It logs failed group lookups and processing errors to a CSV file for further analysis.

.AUTHOR
    Albert Steenkamp

.VERSION
    1.0

.REQUIREMENTS
    - PowerShell (v5 or later recommended)
    - ActiveDirectory PowerShell module (RSAT or equivalent)
    - Domain-joined system with read access to AD

.OUTPUT
    - Warnings for circular nesting and depth limit
    - Errors logged to Unresolvable_Groups.csv in the script directory

.NOTES
    This script does not modify any groups or permissions. It is safe to run in read-only environments.
    As always, dont blindly Trust. Test in Lab.
#>

# -------------------------------------------
# Initialize error collection globally
# This will store any group names that fail to process
# Useful for auditing and reporting issues after the scan
# -------------------------------------------
$global:Errors = @()

# -------------------------------------------
# Function: Get-NestedGroups
# Recursively checks group nesting
# Detects circular nesting and depth limits
# Tracks visited groups and path history
# -------------------------------------------
function Get-NestedGroups {
    param (
        # Name of the AD group to check
        [string]$GroupName,

        # HashSet to track visited groups and avoid circular loops
        [System.Collections.Generic.HashSet[string]]$VisitedGroups = $(New-Object 'System.Collections.Generic.HashSet[string]'),

        # Stack to keep track of the current recursion path
        [System.Collections.Generic.List[string]]$PathStack = $(New-Object 'System.Collections.Generic.List[string]'),

        # Max nesting depth allowed before considering it too deep
        [int]$MaxDepth = 5
    )

    # -------------------------------------------
    # Check if this group has already been visited (loop detected)
    # -------------------------------------------
    if ($VisitedGroups.Contains($GroupName)) {
        $fullPath = ($PathStack + $GroupName) -join ' -> '
        Write-Warning "Circular nesting detected: $fullPath"
        return
    }

    # -------------------------------------------
    # Check if nesting depth limit is exceeded
    # Prevents runaway recursion and complexity
    # -------------------------------------------
    if ($PathStack.Count -ge $MaxDepth) {
        $depthPath = ($PathStack + $GroupName) -join ' -> '
        Write-Warning "Nesting depth exceeded $MaxDepth ($depthPath)"
        return
    }

    # -------------------------------------------
    # Track this group in visited groups and path stack
    # -------------------------------------------
    $VisitedGroups.Add($GroupName) | Out-Null
    $PathStack.Add($GroupName)

    try {
        # -------------------------------------------
        # Get direct group members (non-recursive)
        # Only return group objects (skip users/devices/etc.)
        # -------------------------------------------
        $members = Get-ADGroupMember -Identity $GroupName -Recursive:$false -ErrorAction Stop |
                   Where-Object { $_.objectClass -eq 'group' }

        # -------------------------------------------
        # Recursively process each nested group
        # Use cloned VisitedGroups and PathStack to isolate recursion paths
        # -------------------------------------------
        foreach ($member in $members) {
            Get-NestedGroups -GroupName $member.SamAccountName `
                             -VisitedGroups ($VisitedGroups.Clone()) `
                             -PathStack ([System.Collections.Generic.List[string]]::new($PathStack)) `
                             -MaxDepth $MaxDepth
        }
    }
    catch {
        # -------------------------------------------
        # If any error occurs (e.g., group not found), log it to $Errors
        # This includes group name, nesting path, and the error message
        # -------------------------------------------
        $errorEntry = [PSCustomObject]@{
            GroupName  = $GroupName
            FullPath   = ($PathStack + $GroupName) -join ' -> '
            Error      = $_.Exception.Message
        }
        $global:Errors += $errorEntry
        Write-Warning "Failed to process $GroupName : $($errorEntry.Error)"
    }
}

# -------------------------------------------
# Get all AD groups in the domain
# -------------------------------------------
$AllGroups = Get-ADGroup -Filter *
$total = $AllGroups.Count
$index = 0

# -------------------------------------------
# Loop through every group and process it
# Show progress using Write-Progress
# -------------------------------------------
foreach ($group in $AllGroups) {
    $index++
    $status = "Processing Group $index of $total ($($group.Name))"
    Write-Progress -Activity "Checking AD Groups for nested groups." `
                   -Status $status `
                   -PercentComplete (($index / $total) * 100)

    # Start recursive scan from this group
    Get-NestedGroups -GroupName $group.SamAccountName
}

# -------------------------------------------
# Export any processing errors to a CSV file
# Useful for follow-up review and fixing broken groups
# -------------------------------------------
if ($Errors.Count -gt 0) {
    $Errors | Export-Csv -Path "Unresolvable_Groups.csv" -NoTypeInformation -Encoding UTF8
    Write-Output "$($Errors.Count) group(s) failed to process. Logged to 'Unresolvable_Groups.csv'."
} else {
    Write-Output "All groups processed without error."
}
