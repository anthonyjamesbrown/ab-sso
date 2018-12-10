---
external help file: AB-SSO-help.xml
Module Name: AB-SSO
online version:
schema: 2.0.0
---

# Format-Json

## SYNOPSIS
Pass the output from ConvertTo-Json to prettify the output

## SYNTAX

```
Format-Json [-Json] <String> [<CommonParameters>]
```

## DESCRIPTION
The output from ConvertTo-Json is fairly ugly, pass the output to this
function to remove all of the un-needed whitespace

## EXAMPLES

### EXAMPLE 1
```
$Object | ConvertTo-Json -depth 5 | Format-Json
```

### EXAMPLE 2
```
$Json = $object | CovertTo-Json
```

Format-Json -Json $Json

## PARAMETERS

### -Json
Json string to format

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable.
For more information, see about_CommonParameters (http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
