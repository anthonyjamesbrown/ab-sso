---
external help file: AB-SSO-help.xml
Module Name: AB-SSO
online version:
schema: 2.0.0
---

# New-PIMPassword

## SYNOPSIS
This function makes an API call to the PIM server to register a new clientSecret for a connection.

## SYNTAX

```
New-PIMPassword [-ClientID] <String> [-ClientSecret] <String> [-SystemName] <String> [-PasswordList] <String>
 [-Credential] <PSCredential> [<CommonParameters>]
```

## DESCRIPTION
This function makes an API call to the PIM server to register a new clientSecret for a connection.

To use this function you must pass a credential that has the required permissions to create new
password entries for the specified shared credentials password list.

## EXAMPLES

### EXAMPLE 1
```
new-PIMPassword -ClientID 'TestThis' -ClientSecret 'ThisIsTheTestPassword' -PasswordList 'SSO-Connections' -Credential $pfCred
```

Success

## PARAMETERS

### -ClientID
The clientId will map to the AccountName in PIM

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

### -ClientSecret
The ClientSecret will map to the Password in PIM

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

### -SystemName
The SystemName will map to the SystemName in PIM, for PF connections this should be 'ssodev.\<company\>.com' or 'sso.\<company\>.com'.

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

### -PasswordList
This will determine which shared credential list this entry will be added to, for PF connections this should be 'SSO-Connections'.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 4
Default value: SSO-Connections
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credential
This will be a PSCredential object for an AD account that has create permissions to the specifed shared credentials list.

```yaml
Type: PSCredential
Parameter Sets: (All)
Aliases:

Required: True
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
