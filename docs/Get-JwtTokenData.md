---
external help file: AB-SSO-help.xml
Module Name: AB-SSO
online version:
schema: 2.0.0
---

# Get-JwtTokenData

## SYNOPSIS
Convert a JWT to a PowerShell Object

## SYNTAX

```
Get-JwtTokenData [-Token] <String> [-Recurse] [<CommonParameters>]
```

## DESCRIPTION
Convert a JWT to a PowerShell Object containing attributes for headers and claims

## EXAMPLES

### EXAMPLE 1
```
Get-JWtTokenData -Token $JWT
```

headers                                  claims                                                                                                                                                                                          
 -------                                  ------                                                                                                                                                                                          
 @{alg=RS256; kid=IK0hKL7ARv_OTf1kTAKSlz} @{sub=188888; name=Brown, Anthony; groups=System.Object\[\]; e...

## PARAMETERS

### -Token
This should be a JWT token

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Recurse
{{Fill Recurse Description}}

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable.
For more information, see about_CommonParameters (http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
