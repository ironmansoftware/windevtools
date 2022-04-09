﻿$Nav = @(
    New-UDListItem -Label 'Development' -Icon (New-UDIcon -Icon FileCode) -Children {
        New-UDListItem -Label "Encoding" -Icon (New-UDIcon -Icon 'FileAlt') -OnClick { Invoke-UDRedirect '/encoding' } -Nested
        New-UDListItem -Label "File Diff" -Icon (New-UDIcon -Icon 'FileAlt') -OnClick { Invoke-UDRedirect '/diff' } -Nested
        New-UDListItem -Label "Random" -Icon (New-UDIcon -Icon 'FileAlt') -OnClick { Invoke-UDRedirect '/random' } -Nested
    }
    New-UDListItem -Label 'Disk' -Icon (New-UDIcon -Icon Server) -Children {
        New-UDListItem -Label "Locked Files" -Icon (New-UDIcon -Icon 'Lock') -OnClick { Invoke-UDRedirect '/locked-files' } -Nested
        New-UDListItem -Label "Disk Usage" -Icon (New-UDIcon -Icon 'ChartPie') -OnClick { Invoke-UDRedirect '/disk-usage' } -Nested
    }
    New-UDListItem -Label "Networking" -Icon (New-UDIcon -Icon 'NetworkWired') -Children {
        New-UDListItem -Label "Adapters" -Icon (New-UDIcon -Icon 'SdCard') -OnClick { Invoke-UDRedirect '/adapters' } -Nested
        New-UDListItem -Label "Ports" -Icon (New-UDIcon -Icon 'Plug') -OnClick { Invoke-UDRedirect '/ports' } -Nested
    }
)

New-UDDashboard -Pages @(
    New-UDPage -Name 'Adapters' -Content {
        $Adapters = Get-NetAdapter 
        New-UDTable -Data $Adapters -Columns @(
            New-UDTableColumn -Title 'Name' -Property 'Name' -ShowFilter
            New-UDTableColumn -Title 'Description' -Property 'InterfaceDescription' -ShowFilter
            New-UDTableColumn -Title 'Mac Address' -Property 'MacAddress' -ShowFilter
            New-UDTableColumn -Title 'Speed' -Property 'LinkSpeed' -ShowFilter
        ) -ShowPagination -ShowSort -Title 'Adapters'
    } -Navigation $Nav
    New-UDPage -Name 'Disk Usage' -Content {

        if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            New-UDAlert -Severity 'error' -Text 'This feature requires PowerShell Universal to be running elevated.' 
            return
        }

        New-UDForm -Children {
            New-UDSelect -Label 'Drive' -Id 'Drive' -Option {
                Get-PSDrive -PSProvider 'FileSystem' | Where-Object Name -NE 'Temp' | ForEach-Object {
                    New-UDSelectOption -Name $_.Name -Value $_.Name
                }
            }
        } -OnSubmit {
            $Path = Join-Path $Repository 'WizTree64.exe'
            $FilePath = [IO.Path]::GetTempFileName() + ".csv"
            Show-UDToast 'Running WizTree...' -Persistent -Id 'wiz'
            $Process = Start-Process $Path -ArgumentList "$($EventData.Drive): /export=$FilePath" -PassThru
            $Process.WaitForExit()

            if ($Process.ExitCode -ne 0) {
                New-UDTypography 'Failed to run WizTree'
            }
            else {
                $retries = 0
                while (-not (Test-Path $FilePath)) {
                    Start-Sleep 10
                    $retries++;
                    if ($retries -eq 12) {
                        New-UDTypography 'Failed to run WizTree'
                        return 
                    }
                }

                Hide-UDToast -Id 'wiz'
                Show-UDToast 'Updating file...' -Persistent -Id 'update'

                $Lines = [IO.File]::ReadAllLines($FilePath) | Select-Object -Skip 1
                [IO.File]::WriteAllLines($FilePath, $Lines)

                Hide-UDToast -Id 'update'
                Show-UDToast 'Reading CSV...' -Persistent -Id 'read'
                $Session:Csv = Import-Csv $FilePath  | ForEach-Object { [PSCustomObject]@{ Size = [long]$_.Size; 'File Name' = $_.'File Name'; Files = [long]$_.Files; Folders = [long]$_.Folders } }

                New-UDTable -PageSize 20 -ShowPagination -ShowSort -Title 'Disk Usage' -Columns @(
                    New-UDTableColumn -Title 'File Name' -Property 'File Name'  
                    New-UDTableColumn -Title 'Size' -Property 'Size' -Render {
                        $mbs = $EventData.Size / 1MB
                        New-UDTypography "$($mbs.ToString('0.00')) MB"
                    }
                    New-UDTableColumn -Title 'Files' -Property 'Files' 
                    New-UDTableColumn -Title 'Folders' -Property 'Folders' 
                ) -LoadData {
                    $Skip = $EventData.Page * $EventData.pageSize 

                    $descending = $EventData.orderDirection -ne 'asc'

                    Show-UDToast $Body

                    $Data = $Session:Csv
                    if ($EventData.orderBy.field) {
                        $Data = $Data | Sort-Object -Property $EventData.orderBy.field -Descending:$descending
                    }
                    
                    $Data = $Data | Select-Object -Skip $Skip -First $EventData.PageSize 
                    $Data | ForEach-Object { [HashTable]@{ Size = [long]$_.Size; 'File Name' = $_.'File Name'; Files = [long]$_.Files; Folders = [long]$_.Folders } } | Out-UDTableData -Properties $EventData.Properties -TotalCount $Session:CSV.Length -Page $EventData.page
                    Hide-UDToast -Id 'read'
                }
                Remove-Item $FilePath
            }

        } -SubmitText 'Calculate Disk Usage'
    } -Navigation $Nav
    New-UDPage -Name 'Encoding' -Content {
        New-UDTabs -Tabs {
            New-UDTab -Text 'Text Encoding' -Content {
                New-UDCard -Title 'Convert text between code pages.' -Content {
                    New-UDForm -Children {
                        $Options = ([System.Text.Encoding]::GetEncodings() | ForEach-Object {
                                New-UDSelectOption -Name $_.DisplayName -Value $_.DisplayName
                            })
                        New-UDSelect -Id 'sourceEncoding' -Label 'Source Encoding' -Option { $Options } -FullWidth
                        New-UDSelect -Id 'targetEncoding' -Label 'Target Encoding' -Option { $Options } -FullWidth
                        New-UDTextbox -Id 'text' -Multiline -FullWidth
                    } -OnSubmit {
                        $source = [System.Text.Encoding]::GetEncoding($EventData.sourceEncoding)
                        $target = [System.Text.Encoding]::GetEncoding($EventData.targetEncoding)
                        $text = $target.GetString($source.GetBytes($EventData.text))

                        New-UDCodeEditor -Code $text -ReadOnly -Height 500  
                    }
                }
            }
            New-UDTab -Text 'Hashing' -Content {
                New-UDCard -Title 'Hash text with various algorithms.' -Content {
                    New-UDForm -Children {
                        New-UDSelect -Id 'hash' -Label 'Algorithm' -Option { 
                            New-UDSelectOption -Name 'SHA1' -Value 'SHA1'
                            New-UDSelectOption -Name 'SHA256' -Value 'SHA256'
                            New-UDSelectOption -Name 'SHA512' -Value 'SHA512'
                            New-UDSelectOption -Name 'MD5' -Value 'MD5'
                        } -FullWidth
                        New-UDTextbox -Id 'text' -Multiline -FullWidth
                    } -OnSubmit {
                        if ($EventData.hash -eq 'SHA1') {
                            $algo = [System.Security.Cryptography.SHA1]::Create()
                        }
                        if ($EventData.hash -eq 'SHA256') {
                            $algo = [System.Security.Cryptography.SHA256]::Create()
                        }
                        if ($EventData.hash -eq 'SHA512') {
                            $algo = [System.Security.Cryptography.SHA512]::Create()
                        }
                        if ($EventData.hash -eq 'MD5') {
                            $algo = [System.Security.Cryptography.MD5]::Create()
                        }

                        try {
                            $bytes = $algo.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($EventData.Text))
                            $sb = [System.Text.StringBuilder]::new()
                            $bytes | ForEach-Object {
                                $sb.Append($_.ToString('x2')) | Out-Null
                            }

                            New-UDTextbox -Value ($sb.ToString()) -Multiline -FullWidth
                        }
                        finally {
                            $algo.Dispose()
                        }
                    }
                }
            }
            New-UDTab -Text 'File Hashing' -Content {
                New-UDCard -Title 'Hash files with various algorithms.' -Content {
                    New-UDForm -Children {
                        New-UDUpload -Id 'file' -Text 'Upload File'
                        New-UDSelect -Id 'hash' -Label 'Algorithm' -Option { 
                            New-UDSelectOption -Name 'SHA1' -Value 'SHA1'
                            New-UDSelectOption -Name 'SHA256' -Value 'SHA256'
                            New-UDSelectOption -Name 'SHA512' -Value 'SHA512'
                            New-UDSelectOption -Name 'MD5' -Value 'MD5'
                        } -FullWidth
                    } -OnSubmit {
                        if ($EventData.hash -eq 'SHA1') {
                            $algo = [System.Security.Cryptography.SHA1]::Create()
                        }
                        if ($EventData.hash -eq 'SHA256') {
                            $algo = [System.Security.Cryptography.SHA256]::Create()
                        }
                        if ($EventData.hash -eq 'SHA512') {
                            $algo = [System.Security.Cryptography.SHA512]::Create()
                        }
                        if ($EventData.hash -eq 'MD5') {
                            $algo = [System.Security.Cryptography.MD5]::Create()
                        }

                        try {
                            $Bytes = [IO.File]::ReadAllBytes($EventData.file.FileName)
                            $bytes = $algo.ComputeHash($bytes)
                            $sb = [System.Text.StringBuilder]::new()
                            $bytes | ForEach-Object {
                                $sb.Append($_.ToString('x2')) | Out-Null
                            }

                            New-UDTextbox -Value ($sb.ToString()) -Multiline -FullWidth
                        }
                        finally {
                            $algo.Dispose()
                        }
                    }
                }
            }
            New-UDTab -Text 'URL Encoding' -Content {
                New-UDCard -Title 'Encode and decode text for URLs.' -Content {
                    New-UDForm -Children {
                        New-UDSwitch -Id 'encode' -Label 'Direction' -CheckedLabel 'Encode' -UncheckedLabel 'Decode'
                        New-UDTextbox -Id 'text' -Multiline -FullWidth
                    } -OnSubmit {
                        if ($EventData.encode) {
                            $text = [System.Web.HttpUtility]::UrlEncode($EventData.Text)
                        }
                        else {
                            $text = [System.Web.HttpUtility]::UrlDecode($EventData.Text)
                        }
                
                        New-UDCodeEditor -Code $text -ReadOnly -Height 500  
                    }
                }
            }
            New-UDTab -Text 'HTML Encoding' -Content {
                New-UDCard -Title 'Encode and decode text for HTML.' -Content {
                    New-UDForm -Children {
                        New-UDSwitch -Id 'encode' -Label 'Direction' -CheckedLabel 'Encode' -UncheckedLabel 'Decode'
                        New-UDTextbox -Id 'text' -Multiline -FullWidth
                    } -OnSubmit {
                        if ($EventData.encode) {
                            $text = [System.Web.HttpUtility]::HtmlEncode($EventData.Text)
                        }
                        else {
                            $text = [System.Web.HttpUtility]::HtmlDecode($EventData.Text)
                        }
                        New-UDCodeEditor -Code $text -ReadOnly -Height 500  
                    }
                }
            }
            New-UDTab -Text 'Hex' -Content {
                New-UDCard -Title 'View Text as Hexidecimal' -Content {
                    New-UDForm -Children {
                        New-UDTextbox -Id 'text' -Multiline -FullWidth
                    } -OnSubmit {
                        $text = $EventData.text | Format-Hex | Out-String
                        New-UDCodeEditor -Code $text -ReadOnly -Height 500  
                    }
                }
            }
            New-UDTab -Text 'File Hex' -Content {
                New-UDCard -Title 'View Text as Hexidecimal' -Content {
                    New-UDForm -Children {
                        New-UDUpload -Id 'file2' -Text 'Upload File'
                    } -OnSubmit {
                        Show-UDToast -Id 'hexing' -Message 'Generating hex....' -Persistent
                        $text = Format-Hex -Path $EventData.file2.FileName | Out-String
                        New-UDCodeEditor -Code $text -ReadOnly -Height 500
                        Hide-UDToast -Id 'hexing'
                    }
                }
            }
        }
    } -Navigation $Nav
    New-UDPage -Name 'File Diff' -Url '/diff' -Content {
        New-UDCard -Title 'File Diff' -Content {
            New-UDForm -Children {
                New-UDLayout -Columns 2 -Content {
                    New-UDUpload -Text 'Left' -Id 'left' 
                    New-UDUpload -Text 'Right' -Id 'right' 
                }
            } -OnSubmit {
                $Left = Get-Content $EventData.Left.FileName -Raw
                $Right = Get-Content $EventData.Right.FileName -Raw
                New-UDCodeEditor -Original $Left -Code $Right -Height 500
            }
        } 
    } -Navigation $Nav
    New-UDPage -Name 'Locked Files' -Url '/locked-files' -Content {
        New-UDCard -Title 'Find files that are locked by processes on this system.' -Content {
            New-UDForm -Children {
                New-UDTextbox -Label 'File Path'  -Id 'filePath' -FullWidth
            } -OnSubmit {
                Show-UDModal -Content {
                    $OpenFile = Find-OpenFile -FilePath $EventData.filePath 
                    if ($OpenFile -eq $null) {
                        New-UDTypography 'File not locked.'
                    }
                    else {
                        New-UDTypography "This file is locked by the following process:" -Variant h5
                        New-UDTypography $OpenFile.Name -Variant h5
                        New-UDTypography $OpenFile.Id -Variant h5
                        New-UDTypography $OpenFile.Path -Variant h5
                    }
                }
            } 
        }

    } -Navigation $Nav
    New-UDPage -Name 'Ports' -Content {
        $Connections = Get-NetTCPConnection 
        New-UDTable -Data $Connections -Columns @(
            New-UDTableColumn -Title 'Remote Port' -Property 'RemotePort' -ShowFilter
            New-UDTableColumn -Title 'Local Port' -Property 'LocalPort' -ShowFilter
            New-UDTableColumn -Title 'State' -Property 'State' -ShowFilter
            New-UDTableColumn -Title 'Owning Process' -Property 'OwningProcess'  -Render {
                try {
                    $Process = Get-Process -Id $EventData.OwningProcess 
                    New-UDTypography "$($Process.Name) ($($Process.Id))"
                }
                catch {
                    New-UDTypography $EventData.OwningProcess
                }
            }

        ) -ShowPagination -ShowSort -Title 'Ports'
    } -Navigation $nav
    New-UDPage -Name 'Random' -Content {
        New-UDButton -Text 'Random String' -OnClick {
            $Data = -join ((65..90) + (97..122) | Get-Random -Count 20 | % { [char]$_ })
            Show-UDToast "$Data copied to clipboard" -Duration 4000
            Set-UDClipboard -Data $Data
        }
        New-UDButton -Text 'Random GUID' -OnClick {
            $Guid = New-Guid
            Show-UDToast "$Guid copied to clipboard" -Duration 4000
            Set-UDClipboard -Data $Guid
        }
        New-UDButton -Text 'Random Number' -OnClick {
            $Data = Get-Random
            Show-UDToast "$Data copied to clipboard" -Duration 4000
            Set-UDClipboard -Data $Data
        }
  

        New-UDTabs -Tabs {
            New-UDTab -Text 'Random String' -Content {
                New-UDCard -Title 'Random String' -Content {
                    New-UDForm -Children {      
                        New-UDTypography 'Number of Characters'
                        New-UDSlider -Value 10 -Minimum 1 -Maximum 100 -Id 'characters'
                        New-UDSwitch -Checked $true -Label 'Numbers' -Id 'Numbers'
                        New-UDSwitch -Checked $true -Label 'Letters' -Id 'Letters'
                        New-UDSwitch -Checked $true -Label 'Symbols' -Id 'Symbols'
                    } -OnSubmit {
                        [int]$Chars = $EventData.characters
                        $selectedChars = @()
                        if ($EventData.Numbers) {
                            $selectedChars += (48..57)
                        }

                        if ($EventData.Letters) {
                            $selectedChars += (65..90) + (97..122)
                        }
                
                        if ($EventData.Symbols) {
                            $selectedChars += (33..47) + (58..64) + (91..96) + (123..126)
                        }
                
                        $Data = -join ($selectedChars | Get-Random -Count $Chars | % { [char]$_ })
                        Show-UDToast "$Data copied to clipboard" -Duration 4000
                        Set-UDClipboard -Data $Data
                    }
                }
            }
            New-UDTab -Text 'Random GUID' -Content {
                New-UDCard -Title 'Random GUID' -Content {
                    New-UDForm -Children {      
                        New-UDSelect -Label 'Format' -Id 'format' -Option {
                            New-UDSelectOption -Name 'No Hyphens' -Value 'plain'
                            New-UDSelectOption -Name 'Hyphens' -Value 'hyphens'
                            New-UDSelectOption -Name 'Braces' -Value 'braces'
                            New-UDSelectOption -Name 'Parentheses' -Value 'paren' 
                            New-UDSelectOption -Name 'Hexidecimal' -Value 'hex'
                        }
                    } -OnSubmit {
                        $Guid = New-Guid 

                        switch ($EventData.format) {
                            "plain" { $Data = $Guid.ToString('N') }
                            "hyphens" { $Data = $Guid.ToString('D') }
                            "braces" { $Data = $Guid.ToString('B') }
                            "paren" { $Data = $Guid.ToString('P') }
                            "hex" { $Data = $Guid.ToString('X') }
                        }

                        Show-UDToast "$Data copied to clipboard" -Duration 4000
                        Set-UDClipboard -Data $Data
                    }
                }
            }
            New-UDTab -Text 'Random Number' -Content {
                New-UDCard -Title 'Random Number' -Content {
                    New-UDForm -Children {      
                        New-UDTypography 'Minimum'
                        New-UDSlider -Value 0 -Minimum 1 -Maximum 1000000 -Id 'min'
                        New-UDTypography 'Maximum'
                        New-UDSlider -Value 1000 -Minimum 1 -Maximum 1000000 -Id 'max'
                    } -OnSubmit {
                        $Data = Get-Random -Minimum $EventData.min -Max $EventData.max
                        Show-UDToast "$Data copied to clipboard" -Duration 4000
                        Set-UDClipboard -Data $Data
                    }
                }
            }
        }


    } -Navigation $Nav
) 