---
external help file: AB-SSO-help.xml
Module Name: AB-SSO
online version:
schema: 2.0.0
---

# Export-PFAccessTokenManager

## SYNOPSIS
Export the AccessTokenManager configuration for a given ClientID

## SYNTAX

```
Export-PFAccessTokenManager [-ClientID] <String> [-SSOServer] <String> [-Credential] <PSCredential>
 [<CommonParameters>]
```

## DESCRIPTION
This function pulls the AccessTokenManager configuration from the Admin API.
The output is sanitized to remove unneeded data and then converted to JSON.

## EXAMPLES

### EXAMPLE 1
```
Export-PFAccessTokenManager -ClientID ABTEST2 -SSOServer sodev1 -Credential $PFcred
```

{
   "id": "ABTest2",
   "name": "ABTest2",
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
 ...

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

### -Credential
This parameter is a PSCredential object containing credentials that have permission to access the PingFed Admin API.

```yaml
Type: PSCredential
Parameter Sets: (All)
Aliases:

Required: True
Position: 3
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
