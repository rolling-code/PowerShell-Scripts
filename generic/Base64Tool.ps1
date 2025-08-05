<#
Example Usage:

# Decode a base64‐encoded Unicode string
.\Base64Tool.ps1 -InputString 'SABlAGwAbABvACAAVwBvAHIAbABkACEA'

# Encode a text string to base64 (Unicode)
.\Base64Tool.ps1 -InputString 'Hello World!' -Encode

# Equivalent one-liners without this script:
# Decode:
#   [Text.Encoding]::Unicode.GetString(
#     [Convert]::FromBase64String('SABlAGwAbABvACAAVwBvAHIAbABkACEA')
#   )
# Encode:
#   [Convert]::ToBase64String(
#     [Text.Encoding]::Unicode.GetBytes('Hello World!')
#   )
#>

param(
    [Parameter(Mandatory)]
    [string]$InputString,

    [switch]$Encode
)

if ($Encode) {
    # Convert text to bytes, then to base64
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($InputString)
    [Convert]::ToBase64String($bytes)
}
else {
    # Convert base64 to bytes, then to text
    $bytes = [Convert]::FromBase64String($InputString)
    $text  = [System.Text.Encoding]::Unicode.GetString($bytes)

    # Remove any non-printable characters
    $text -replace '[^\u0020-\u007E\u00A0-\u00FF\u0100-\u017F]', ''
}
