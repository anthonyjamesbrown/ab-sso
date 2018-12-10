---
external help file: AB-SSO-help.xml
Module Name: AB-SSO
online version:
schema: 2.0.0
---

# Export-PFConnection

## SYNOPSIS
This function will generate configuration artifacts from an existing connection.

## SYNTAX

```
Export-PFConnection [-ClientID] <String> [-SSOServer] <String> [-Path] <String> [-Credential] <PSCredential>
 [<CommonParameters>]
```

## DESCRIPTION
This function will make a series of Admin API calls to generate the AccessTokenManager,
AccessTokenManagerMapping, OAuthClient, and OpenIDConnect JSON config files. 
The files
will be written to the location specified in the Path parameter.

## EXAMPLES

### EXAMPLE 1
```
Export-PFConnection
```

## PARAMETERS

### -ClientID
Json string to format

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

### -SSOServer
This parameter is the hostname of the SSO server you are targeting to pull the config from.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Path
This parameter specifies the path where the extracted configurations files will be written.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credential
This parameter is a PSCredential object containing credentials that have permission to access the PingFed Admin API.

```yaml
Type: PSCredential
Parameter Sets: (All)
Aliases:

Required: True
Position: 4
Default value: None
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
