---
external help file: AB-SSO-help.xml
Module Name: AB-SSO
online version:
schema: 2.0.0
---

# New-PFOIDCPolicyJson

## SYNOPSIS
This function will generate a json string containing the configuration for a PingFederate OIDC Policy object.

## SYNTAX

```
New-PFOIDCPolicyJson [-ClientId] <String> [[-RestrictIPInternal] <Boolean>] [[-RestrictToGroup] <Boolean>]
 [[-RestrictedGroup] <String>] [<CommonParameters>]
```

## DESCRIPTION
This function was built to specifically work with PingFederate v7.x+ as well as with another internal module maintianed by the client.

This function will generate a json string containing the configuration for a PingFederate OIDC Policy object.
This function also contains built-in functionality for setting the two most commonly used conditionalCriteria 
for connections.

## EXAMPLES

### EXAMPLE 1
```
New-pfOIDCPolicyJson -ClientId TestThis
```

{
   "id": "TestThis",
   "name": "TestThis",
   "accessTokenManagerRef": {
     "id": "TestThis"
   },
   "includeSriInIdToken": true,
   "includeUserInfoInIdToken": true,
   "attributeContract": {
     "coreAttributes": \[
       {
         "name": "sub"
       }
     \],
     "extendedAttributes": \[
       {
         "name": "userPrincipalName"
       },
 ...

### EXAMPLE 2
```
New-pfOIDCPolicyJson -ClientId TestThis -RestrictIPInternal $true -RestrictToGroup $true -RestrictedGroup "SSO Admins"
```

...
    "issuanceCriteria": {
       "conditionalCriteria": \[

       \],
       "expressionCriteria": \[
         {
           "errorResult": "Access to this application is restricted to the Company network.
Please access this application from the Company network or VPN.",
           "expression": "#isClientIPInternal = @com.pingidentity.sdk.CIDROperations@isInRange(#this.get(\"context.ClientIp\"),\"10.0.0.0/8\") || @com.pingidentity.sdk.CIDROperations@isInRange(#this.get(\"context.ClientIp\"),\"172.16.0
                 .0/12\") || @com.pingidentity.sdk.CIDROperations@isInRange(#this.get(\"context.ClientIp\"),\"192.168.0.0/16\") || @com.pingidentity.sdk.CIDROperations@isInRange(#this.get(\"context.ClientIp\"),\"100.64.0.0/10\"), #isClientIPInternal"
         },
         {
           "errorResult": "Access to this application is retricted to members of the SSO Admins AD group.",
         "expression": "#groupString = "($RestrictedGroup|SSO Admins)", #authorized = false, #this.get("ds.VDS.memberOf") == null ?
null : ( #groups = #this.get("ds.VDS.memberOf").getValues(), #groups.{ #group = #this, #group = new javax.naming.ldap.LdapName(#group), #cn = #group.getRdn(#group.size() - 1).getValue().toString(), #authorized = #authorized or (#cn.matches("(?i).*"+#groupString+".*")) } ), #authorized"
         }
       \]

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

### -RestrictIPInternal
This parameter toggles whether a conditionalCriteria statement limiting a connection to use only internal IPs is added to the JSON config.

```yaml
Type: Boolean
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -RestrictToGroup
This parameter toggles whether a conditionalCriteria statement limiting a connection to only members of a certain group. 
If you use
this option you will need to also use the Restrictedgroup option to set which group access should be restricted to.

```yaml
Type: Boolean
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -RestrictedGroup
{{Fill RestrictedGroup Description}}

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable.
For more information, see about_CommonParameters (http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
