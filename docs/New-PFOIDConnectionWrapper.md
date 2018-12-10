---
external help file: AB-SSO-help.xml
Module Name: AB-SSO
online version:
schema: 2.0.0
---

# New-PFOIDConnectionWrapper

## SYNOPSIS
This function wraps the New-PFOIDCConnection function and adds end to end automation of the connection creation process.

## SYNTAX

```
New-PFOIDConnectionWrapper [-ClientID] <String> [-GrantType] <String> [-SSOServer] <String>
 [-RestrictIPInternal] <Boolean> [-RestrictToGroup] <Boolean> [[-RestrictedGroup] <String>]
 [[-ClientSecret] <String>] [[-AddToGit] <Boolean>] [[-AddToPim] <Boolean>] [[-PFPath] <String>]
 [[-RedirectURIs] <Array>] [-Credential] <PSCredential> [<CommonParameters>]
```

## DESCRIPTION
This function was built to specifically work with PingFederate v7.x+ as well as with another internal module maintianed by the client.

This function wraps the New-PFOIDCConnection function and adds end to end automation of the connection creation process.

This function handles the following tasks:
- Creates a feature branch in the local Git repo for pfConnections based on the develop branch
- Creates a new OIDC Connection folder in the pfConnections root based on clientId name
- Generates \<ClientId\> - AccessTokenManager.json file
- Generates \<ClientId\> - Client.json file
- Generates \<ClientId\> - OIDC Policy.json file
- Creates new OIDC connection in PingFed, via a call to New-PFOIDCConnection
- Tests the connection and validates the token
- Generates a \<ClientId\>_\<ssoenv\>_\<GrantType\>.html test form file
- If the GrantType was auth_code then the new clientSecret will be added to PIM
- Generates the body of the notification email
- Adds the four new files to the feature-\<ClientId\> branch
- Performs a Git commit -m and puts in a standard comment
- Merges the feature branch into the develop branch using the --no-ff switch
- Returns an object with ClientId, ClientSecret, PIMStatus, ValidatedToken, and Email body

The Git interactions can be turned off by using the AddToGit = $false parameter. 
If you use the AddToGit feature you will need
to have the posh-Git module installed. 
The script stops short of performing a git push and leaves that step up to you to ensure
you are comfortable pushing the new changes back to the origin.

## EXAMPLES

### EXAMPLE 1
```
$props = @{
```

'ClientID'             = "VisaPriorityPassDev"
        'GrantType'            = "IMPLICIT" #AUTHORIZATION_CODE or IMPLICIT
        'SSOServer'            = "ndcssodev1"
        'RestrictIPInternal'   = $false
        'RestrictToGroup'      = $false
        'RestrictedGroup'      = ""
        'AddToGit'             = $true
        'PFPath'               = 'C:\PS Script\dsa\pfconnections\Connections\'
        'Credential'           = $pfcred
        'RedirectURIs'         = @()
}

$NewConnection = New-PFOIDConnectionWrapper @props

## PARAMETERS

### -ClientID
This parameter represents the name of the application that the OIDC connection is being created for. 
No spaces are allowed.

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
This parameter sets the Grant Type for the OIDC connection. 
This value should be either 'IMPLICIT' or 'AUTHORIZATION_CODE'.

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

### -SSOServer
This parameter tells the script which PingFed server to connect to for Admin API calls.

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

### -RestrictIPInternal
This parameter toggles whether a conditionalCriteria statement limiting a connection to use only internal IPs is added to the JSON config.

```yaml
Type: Boolean
Parameter Sets: (All)
Aliases:

Required: True
Position: 4
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

Required: True
Position: 5
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
Position: 6
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ClientSecret
This parameter is used to specifiy an existing client_secrect to use when creating the connection.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 7
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AddToGit
This parameter toggles functionality to control adding the new connection to the local Git Repo as a new feature branch.
If you use the AddToGit 
feature you will need to have the posh-Git module installed. 
The script stops short of performing a git push and leaves that step up to you to
ensure you are comfortable pushing the new changes back to the origin.

```yaml
Type: Boolean
Parameter Sets: (All)
Aliases:

Required: False
Position: 8
Default value: True
Accept pipeline input: False
Accept wildcard characters: False
```

### -AddToPim
This paramater contols if you want new Auth_code connections to register the client_secret in PIM automatically. 
If you have already assigned
a client_secret and stored it in PIM then you would use this option.

```yaml
Type: Boolean
Parameter Sets: (All)
Aliases:

Required: False
Position: 9
Default value: True
Accept pipeline input: False
Accept wildcard characters: False
```

### -PFPath
This parameter is the folder path to the pfconnections folder. 
You can put this folder anywhere when you clone the pfConnections repo.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 10
Default value: C:\PS Script\dsa\pfconnections\Connections\
Accept pipeline input: False
Accept wildcard characters: False
```

### -RedirectURIs
This parameter is a string array used for specifiying additional Redirect URIs to add to the connection at create time.

```yaml
Type: Array
Parameter Sets: (All)
Aliases:

Required: False
Position: 11
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credential
This parameter is a PSCredential object set with a username and password of a user that is granted admin permissions in the PingFed console.
The username should not include any domain information.

```yaml
Type: PSCredential
Parameter Sets: (All)
Aliases:

Required: True
Position: 12
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
