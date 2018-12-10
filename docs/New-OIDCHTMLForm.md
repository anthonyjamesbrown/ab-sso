---
external help file: AB-SSO-help.xml
Module Name: AB-SSO
online version:
schema: 2.0.0
---

# New-OIDCHTMLForm

## SYNOPSIS
This function is used to create a simple html document that contains a test form for a connection.

## SYNTAX

```
New-OIDCHTMLForm [-ClientId] <String> [-SSOUrl] <String> [-GrantType] <String> [[-RedirectURI] <String>]
 [[-ConnectionPath] <String>] [<CommonParameters>]
```

## DESCRIPTION
This function was built to specifically work with PingFederate v7.x+ as well as with another internal module maintianed by the client.

This form will generate a test html document based on the values passed that can be used to test
an OIDC connection. 
This form is saved as one of the artifacts for a new connection in the pfconnections Git Repo.

Pass in a ClientId, SSOURL, GrantType, RedirectURI, and a folder path and a new html document will be created in that path.

## EXAMPLES

### EXAMPLE 1
```
New-OIDCHTMLForm -ClientId $ClientId -SSOUrl $SSOURL -GrantType $GrantType -RedirectURI 'http://ucsinfo.int.company.com/' -ConnectionPath $PFConnectionPath
```

## PARAMETERS

### -ClientId
This should be a valid OIDC connection name from the PingFederate environment specified in the SSOURL value.

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

### -SSOUrl
This will either be 'sso.company.com' for the PROD enviornment or 'ssodev.company.com' for the DEV enviornment.

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

### -GrantType
This will either be 'IMPLICIT' or 'AUTHORIZATION_CODE' depending on what granttype the connection is configured to use.

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

### -RedirectURI
This parameter is used to tell the OIDC connection where to redirect the web broswer to after completing authentication.
The value used here needs to be configured in the redirect URI whitelist for the connection in PingFederate.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ConnectionPath
This is the base folder path for where the file will be created. 
\<connectionPath\>\\\<ClientId\>_\<ssoURL (first part)\>_\<GrantType\>.html

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 5
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
