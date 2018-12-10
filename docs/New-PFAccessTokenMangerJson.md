---
external help file: AB-SSO-help.xml
Module Name: AB-SSO
online version:
schema: 2.0.0
---

# New-PFAccessTokenMangerJson

## SYNOPSIS
This function will generate a json string containing the configuration for a PingFederate Access Token Manager object.

## SYNTAX

```
New-PFAccessTokenMangerJson [-ClientId] <String> [<CommonParameters>]
```

## DESCRIPTION
This function was built to specifically work with PingFederate v7.x+ as well as with another internal module maintianed by the client.

This function will generate a json string containing the configuration for a PingFederate Access Token Manager object.

## EXAMPLES

### EXAMPLE 1
```
New-pfAccessTokenMangerJson -clientId TestThis
```

{
    "id": "TestThis",
    "name": "TestThis",
    "pluginDescriptorRef": {
    "id": "com.pingidentity.pf.access.token.management.plugins.JwtBearerAccessTokenManagementPlugin"
    },
    "parentRef": {
    "id": "UPN"
    },
    "configuration": {
    "tables": \[
        {
        "name": "Symmetric Keys",
        "inherited": true,
        "rows": \[

        \]
        },
        {
        "name": "Certificates",
        "inherited": true
        }
    \],
...

## PARAMETERS

### -ClientId
This parameter is used to set the clientId in the JSON config

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable.
For more information, see about_CommonParameters (http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
