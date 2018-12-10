---
external help file: AB-SSO-help.xml
Module Name: AB-SSO
online version:
schema: 2.0.0
---

# Export-PFAccessTokenManagerMapping

## SYNOPSIS
Export the AccessTokenManagerMapping configuration for a given ClientID

## SYNTAX

```
Export-PFAccessTokenManagerMapping [-ClientID] <String> [-SSOServer] <String> [-Credential] <PSCredential>
 [<CommonParameters>]
```

## DESCRIPTION
This function pulls the AccessTokenManagerMapping configuration from the Admin API.
The output is sanitized to remove unneeded data and then converted to JSON.

## EXAMPLES

### EXAMPLE 1
```
Export-PFAccessTokenManagerMapping -ClientID ABTEST2 -SSOServer sodev1 -Credential $PFcred
```

{
   "attributeSources": \[
     {
       "type": "LDAP",
       "dataStoreRef": {
         "id": "LDAP-9385858585890606049838238444"
       },
       "id": "VDS",
       "description": "VDS",
       "baseDn": "ou=users,o=company",
       "searchScope": "ONE_LEVEL",
     "searchFilter": "(\u0026(objectClass=user)(userPrincipalName=${USER_KEY}))",
       "binaryAttributeSettings": {
         "objectGUID": {
           "binaryEncoding": "BASE64"
         },
         "objectSid": {
           "binaryEncoding": "BASE64"
         }
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
