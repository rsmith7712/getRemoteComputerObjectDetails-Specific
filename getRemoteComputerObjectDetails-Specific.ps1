﻿<#
.LICENSE
    MIT License, Copyright 2024 Richard Smith

    Permission is hereby granted, free of charge, to any person obtaining a
    copy of this software and associated documentation files (the “Software”),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the
    Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included
    in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
    IN THE SOFTWARE.

.NAME
    getRemoteComputerObjectDetails-Specific-v1.ps1

.DESCRIPTION
    Script takes user input for a computer object name, adds
        a trailing $, queries the specified computer object,
        and retrieves details such as the current user, OS
        version, computer name, and object SID. The output
        is formatted as a table and displayed on the console.

.FUNCTIONALITY
    User Input: Prompts the user for a computer object name
        using Read-Host.
    Add Trailing $: Appends a $ to the input to match
        naming conventions for computer objects.
    Query Computer Details:
        -Win32_ComputerSystem retrieves the computer name
            and current logged-in user.
        -Win32_OperatingSystem retrieves the OS version.
        -Get-ADComputer retrieves the ObjectSID of the
            computer object from Active Directory.
    Error Handling: Catches and displays errors if the
        query fails.

.NOTES

#>

# Prompt user for computer object name
$computerName = Read-Host -Prompt "Enter the computer object name"

# Add a trailing $ to the input
$computerObject = "$computerName$"

# Use Get-WmiObject to query the computer for details
try {
    $computerInfo = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $computerName
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $computerName
    $objectSID = (Get-ADComputer -Identity $computerName -Properties ObjectSID).ObjectSID

    if ($computerInfo -and $osInfo) {
        # Construct an output object
        $output = [PSCustomObject]@{
            ComputerName = $computerInfo.Name
            CurrentUser  = $computerInfo.UserName
            OSVersion    = $osInfo.Caption
            ObjectSID    = $objectSID
        }

        # Output as a formatted table
        $output | Format-Table -AutoSize
    } else {
        Write-Host "Failed to retrieve computer information." -ForegroundColor Red
    }
} catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
}