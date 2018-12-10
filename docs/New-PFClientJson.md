---
external help file: AB-SSO-help.xml
Module Name: AB-SSO
online version:
schema: 2.0.0
---

# New-PFClientJson

## SYNOPSIS
This function will generate a json string containing the configuration for a PingFederate Oauth Client object.

## SYNTAX

```
New-PFClientJson [-ClientId] <String> [-GrantType] <String> [[-ClientSecret] <String>]
 [[-RedirectURIs] <Array>] [<CommonParameters>]
```

## DESCRIPTION
This function was built to specifically work with PingFederate v7.x+ as well as with another internal module maintianed by the client.

This function will generate a json string containing the configuration for a PingFederate Oauth Client object.
The function sets the RedirectUris to two entries automatically ('http://localhost/login' and 'http://ucsinfo.int.company.com/'), any additional
values passed in the RedirectURIs parameter will be appended to the default entries.

If the GrantType is set to 'AUTHORIZATION_CODE' then a ClientSecret will be generated for you.

## EXAMPLES

### EXAMPLE 1
```
New-pfClientJson -ClientId TestThis -GrantType IMPLICIT -RedirectURIs 'http://localhost:8080'
```

{
   "clientId": "TestThis",
   "redirectUris": \[
     "http://localhost/login",
     "http://ucsinfo.int.company.com/",
     "http://localhost:8080"
   \],
   "grantTypes": \[
     "IMPLICIT",
     "ACCESS_TOKEN_VALIDATION"
   \],
 ...

## PARAMETERS

### -ClientId
This parameter is used to set the ClientId in the JSON config

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

### -GrantType
This parameter is used to set the GrantType. 
This value should either be 'IMPLICIT' or 'AUTHORIZATION_CODE'.
If the GrantType is set to 'AUTHORIZATION_CODE' then a ClientSecret will be generated for you.

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

### -ClientSecret
If you already have an existing client_secret you can optionally pass it in here and it will be used. 
If you leave this
blank and the GrantType is 'AUTHORIZATION_CODE' then a new client_secret will be generated for you.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RedirectURIs
This is a string array that should contain a list of RedirectURIs that will be whitelisted in the configuration for 
the OIDC client configuration.
'http://localhost/login' and 'http://ucsinfo.int.company.com/' are configured by default and anything passed in this
parameter will be appended to the list.

```yaml
Type: Array
Parameter Sets: (All)
Aliases:

Required: False
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
