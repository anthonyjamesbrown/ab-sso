function Format-Json
{
    <#
        .SYNOPSIS
           Pass the output from ConvertTo-Json to prettify the output 
        .DESCRIPTION
           The output from ConvertTo-Json is fairly ugly, pass the output to this
           function to remove all of the un-needed whitespace
        .EXAMPLE
           $Object | ConvertTo-Json -depth 5 | Format-Json
        .EXAMPLE
            $Json = $object | CovertTo-Json
            Format-Json -Json $Json
        .PARAMETER Json
           Json string to format
    #>

    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline
        )]
        [String]
        $Json
    ) # end param

    $Indent = 0;
    ($Json -Split '\n' |
    ForEach-Object {
        if ($_ -match '[\}\]]') 
        {
            # This line contains  ] or }, decrement the indentation level
            $Indent--
        } # end if

        $Line = (' ' * $Indent * 2) + $_.TrimStart().Replace(':  ', ': ')

        if ($_ -match '[\{\[]')
        {
            # This line contains [ or {, increment the indentation level
            $Indent++
        } # end if

        $Line
    }) -Join "`n"
} # end function Format-Json

function Get-JwtTokenData
{
    <#
        .SYNOPSIS
           Convert a JWT to a PowerShell Object
        .DESCRIPTION
           Convert a JWT to a PowerShell Object containing attributes for headers and claims
        .EXAMPLE
           Get-JWtTokenData -Token $JWT

           headers                                  claims                                                                                                                                                                                          
            -------                                  ------                                                                                                                                                                                          
            @{alg=RS256; kid=IK0hKL7ARv_OTf1kTAKSlz} @{sub=188888; name=Brown, Anthony; groups=System.Object[]; e...

        .PARAMETER Token
           This should be a JWT token
    #>

    [CmdletBinding()]  
    param
    (
        [Parameter(
            Mandatory=$true
        )]
        [String]
        $Token,

        [Parameter(
        )]
        [Switch]
        $Recurse
    ) # end param
    
    if ($Recurse)
    {
        $Decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Token))
        $DecodedJwt = Invoke-DecodeJWT -RawToken $Decoded
    }
    else
    {
        $DecodedJwt = Invoke-DecodeJWT -RawToken $Token
    } # end if

    return $DecodedJwt
} # end function Get-JwtTokenData

function Convert-FromBase64StringWithNoPadding
{
    <#
        .SYNOPSIS
           This is a helper function used to convert from Base 64 encoding strings with no padding.
    #>
    [CmdletBinding()]  
    param
    (
        [Parameter(
            Mandatory=$true
        )]
        [String]
        $Data    
    ) # end param

    $Data = $Data.Replace('-', '+').Replace('_', '/')
    switch ($Data.Length % 4)
    {
        0 { break }
        2 { $Data += '==' }
        3 { $Data += '=' }
        default { throw New-Object ArgumentException('data') }
    } # end switch

    return [System.Convert]::FromBase64String($Data)
} # end function Convert-FromBase64StringWithNoPadding

function Invoke-DecodeJWT
{
    <#
        .SYNOPSIS
           This is a helper function to convert data in a JWT token to a readable format.
    #>
    [CmdletBinding()]  
    param
    (
        [Parameter(
            Mandatory=$true
        )]
        [String]
        $RawToken    
    ) # end param

    $Parts = $RawToken.Split('.');
    $Headers = [System.Text.Encoding]::UTF8.GetString((Convert-FromBase64StringWithNoPadding $Parts[0]))
    $Claims = [System.Text.Encoding]::UTF8.GetString((Convert-FromBase64StringWithNoPadding $Parts[1]))
    $Signature = (Convert-FromBase64StringWithNoPadding $Parts[2])

    $CustomObject = [PSCustomObject]@{
        'Headers'   = ($Headers | ConvertFrom-Json)
        'claims'    = ($Claims | ConvertFrom-Json)
        'Signature' = $Signature
    } # end custom object

    Write-Verbose -Message ("JWT`r`n.headers: {0}`r`n.claims: {1}`r`n.signature: {2}`r`n" -f $Headers,$Claims,[System.BitConverter]::ToString($Signature))
    return $CustomObject
} # end function Invoke-DecodeJWT

function Test-OIDCConnection
{
    <#
        .SYNOPSIS
            This function will test a OIDC connection and perform token validation on the JWT returned
        .DESCRIPTION
            This function was built to specifically work with PingFederate v7.x+ as well as with another internal module maintianed by the client.

            This function makes a call to the OIDC AS endpoint to retrieve a token and perform token validation,
            this function can handle both Implicit and Auth_code Grant Types.
        .EXAMPLE
            Test-OIDCConnection -ClientId AtlasPortal -SSOUrl 'ssodev.company.com' -GrantType 'IMPLICIT' -RedirectURI 'http://ucsinfo.int.company.com/'

            Claims                                                                                                                                                                   Identities Identity                             
            ------                                                                                                                                                                   ---------- --------                             
            {http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier: 188888, name: anthony brown, groups: COMPANY_CM_Full_Admins, groups: COMPANY_ARS_FullAdmins...} {}         System.Security.Claims.ClaimsIdentity
            {sub: 188888, name: anthony brown, groups: COMPANY_CM_Full_Admins, groups: COMPANY_ARS_FullAdmins...} 

        .PARAMETER clientId
            This is the OIDC connection name that you are going to test
        .PARAMETER SSOUrl
            This will either be 'sso.company.com' for the PROD enviornment or 'ssodev.company.com' for the DEV enviornment.
        .PARAMETER GrantType
            This will either be 'IMPLICIT' or 'AUTHORIZATION_CODE' depending on what granttype the connection is configured to use.
        .PATAMETER clientSecret
            This parameter is only needed if the grantType is 'AUTHORIZATION_CODE'.
        .PARAMETER RedirectURI
            This parameter is used to tell the OIDC connection where to redirect the web broswer to after completing authentication.
            The value used here needs to be configured in the redirect URI whitelist for the connection in PingFederate
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true
        )]
        [String]
        $ClientId,

        [Parameter(
            Mandatory = $true
        )]
        [String]
        $SSOUrl,

        [Parameter(
            Mandatory = $true
        )]
        [String]
        $GrantType,

        [Parameter(
        )]
        [String]
        $ClientSecret,

        [Parameter(
            Mandatory = $true
        )]
        [String]
        $RedirectURI
    ) # end param

    # Test if we can load assemblies from a UNC path
    $Null = [System.Reflection.Assembly]::LoadFrom("\\<unc path>\SharedDLLs\Microsoft.IdentityModel.Tokens.dll")
    $Null = [System.Reflection.Assembly]::LoadFrom("\\<unc path>\SharedDLLs\System.IdentityModel.Tokens.Jwt.dll")
    [Net.ServicePointManager]::SecurityProtocol = 'Tls11','Tls12'
    
    $AuthURI  = "https://$($SSOUrl):9031/as/authorization.oauth2"
    $TokenURI = "https://$($SSOUrl):9031/as/token.oauth2"
    $JwksURI  = "https://$($SSOUrl):9031/pf/JWKS"

    if($GrantType.ToUpper() -eq 'IMPLICIT') {$GrantType = 'Implicit'}
    if($GrantType.ToUpper() -eq 'AUTHORIZATION_CODE') {$GrantType = 'Auth_Code'}

    if($GrantType -eq "Implicit"){$ResponseType = "id_token"}
    if($GrantType -eq "Auth_Code"){$ResponseType = "code"}

    $PostParams = @{
        client_id     = "$ClientId"
        response_type = "$ResponseType"
        scope         = 'openid profile'
        nonce         = 'abcdefghijklmnopqrstuvwxyz'
        redirect_uri  = "$RedirectURI"
        state         = ''
    }

    $Response = Invoke-WebRequest -Uri $AuthURI -Method POST -Body $PostParams -UseDefaultCredentials

    if($GrantType -eq 'Implicit') 
    {
        $Token = $Response.BaseResponse.ResponseUri.Fragment.Split("=")[1].Split("&")[0]
    }
    else
    {
        $Code = $Response.BaseResponse.ResponseUri.Query.Split("=")[1].Split("&")[0]
        $PostParams = @{
            grant_type    = 'authorization_code'
            client_id     = "$ClientId"
            client_secret = "$ClientSecret"
            response_type = 'id_token'
            redirect_uri  = "$RedirectURI"
            code          = "$Code"
        } # end hash
        $Response = Invoke-RestMethod -Method POST -Uri $TokenURI -Body $PostParams 
        $Token = $Response.id_token
    } # end if

    $TokenData = Get-JwtTokenData -Token $Token

    $Kid =  $TokenData.headers.kid

    $Jwks = Invoke-RestMethod -Method Get -Uri $JwksURI
    $Modulus = ($Jwks.keys | ? kid -eq $Kid).n
    $Exponent = ($Jwks.keys | ? kid -eq $Kid).e

    [System.Security.Cryptography.RSAParameters]$ImportParams = [System.Security.Cryptography.RSAParameters]::new() 
    $ImportParams.Exponent = Convert-FromBase64StringWithNoPadding $Exponent
    $ImportParams.Modulus = Convert-FromBase64StringWithNoPadding $Modulus

    $Rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
    $Rsa.ImportParameters($ImportParams)

    $RsaKey = [Microsoft.IdentityModel.Tokens.RsaSecurityKey]::new($Rsa)

    $ValidationParameters = [Microsoft.IdentityModel.Tokens.TokenValidationParameters]::new()
    $ValidationParameters.RequireExpirationTime = $false
    $ValidationParameters.RequireSignedTokens = $true
    $ValidationParameters.ValidateAudience = $false
    $ValidationParameters.ValidateIssuer = $false
    $ValidationParameters.ValidateLifetime = $false
    $ValidationParameters.IssuerSigningKey = $RSAKey

    [System.IdentityModel.Tokens.Jwt.JwtSecurityToken]$ValidatedSecurityToken = $null
    $Handler = [System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler]::new()
    $Handler.ValidateToken($token, $validationParameters, [ref]$validatedSecurityToken)

    $ValidatedSecurityToken
} # end function Test-OIDCConnection

function New-OIDCHTMLForm
{
    <#
        .SYNOPSIS
            This function is used to create a simple html document that contains a test form for a connection.
        .DESCRIPTION
            This function was built to specifically work with PingFederate v7.x+ as well as with another internal module maintianed by the client.

            This form will generate a test html document based on the values passed that can be used to test
            an OIDC connection.  This form is saved as one of the artifacts for a new connection in the pfconnections Git Repo.

           Pass in a ClientId, SSOURL, GrantType, RedirectURI, and a folder path and a new html document will be created in that path.

        .EXAMPLE
           New-OIDCHTMLForm -ClientId $ClientId -SSOUrl $SSOURL -GrantType $GrantType -RedirectURI 'http://ucsinfo.int.company.com/' -ConnectionPath $PFConnectionPath

        .PARAMETER ClientId
           This should be a valid OIDC connection name from the PingFederate environment specified in the SSOURL value.
        .PARAMETER SSOUrl
            This will either be 'sso.company.com' for the PROD enviornment or 'ssodev.company.com' for the DEV enviornment.
        .PARAMETER GrantType
            This will either be 'IMPLICIT' or 'AUTHORIZATION_CODE' depending on what granttype the connection is configured to use.
        .PARAMETER RedirectURI
            This parameter is used to tell the OIDC connection where to redirect the web broswer to after completing authentication.
            The value used here needs to be configured in the redirect URI whitelist for the connection in PingFederate.
        .PARAMETER ConnectionPath
            This is the base folder path for where the file will be created. 
            <connectionPath>\<ClientId>_<ssoURL (first part)>_<GrantType>.html
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$true
        )]
        [String]
        $ClientId,

        [Parameter(
            Mandatory=$true
        )]
        [String]
        $SSOUrl,

        [Parameter(
            Mandatory=$true
        )]
        [String]
        $GrantType,

        [Parameter(
        )]
        [String]
        $RedirectURI,

        [Parameter(
        )]
        [String]
        $ConnectionPath
    ) # end param
    
    if($GrantType.ToUpper() -eq 'IMPLICIT') {$GrantType = 'Implicit'}
    if($GrantType.ToUpper() -eq 'AUTHORIZATION_CODE') {$GrantType = 'Auth_Code'}

    if($GrantType -eq "Implicit"){$ResponseType = "id_token"}
    if($GrantType -eq "Auth_Code"){$ResponseType = "code"}

    $Body = @" 
<body>
    <form method="POST" action="https://$($SSOUrl):9031/as/authorization.oauth2">
        client id:<br/><input type="text" name="client_id" value="$ClientId"><br />
        response type:<br/><input type="text" name="response_type" value="$ResponseType"><br/>
        scope:<br/><input type="text" name="scope" value="openid profile email"><br />
        nonce:<br/><input type="text" name="nonce" value="abcdefghijklmnopqrstuvwxyz"><br />
        redirect url:<br/><input type="text" name="redirect_uri" value="$RedirectURI"><br />
        state:<br /><input type="text" name="state" value=""><br />
        <br />
        <input type="submit" name="submit">
    </form>
</body>
"@
    $Body | Out-File -FilePath "$ConnectionPath\$($ClientId)_$(($SSOURL).Split('.')[0])_$GrantType.html"
} # end function New-OIDCHTMLForm

function New-ClientSecret
{
    <#
        .SYNOPSIS
           Generate a randam 64 character string only using Alpha-Numeric characters
        .DESCRIPTION
           Generate a randam 64 character string only using Alpha-Numeric characters suitable to be used as a clientSecret.
        .EXAMPLE
           New-ClientSecret
           N6pbPyr12kS3qjHZsEwGQidCefuhv5zJVxF0WTm4D8tYKoInAlMgBX7ULa9cRO

    #>
    [CmdletBinding()]
    param()

    $ClientSecret = (-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 64 | % {[char]$_}))
    $ClientSecret
} # end function New-ClientSecret

function New-PFAccessTokenMangerJson
{
    <#
        .SYNOPSIS
            This function will generate a json string containing the configuration for a PingFederate Access Token Manager object.
        .DESCRIPTION
            This function was built to specifically work with PingFederate v7.x+ as well as with another internal module maintianed by the client.

            This function will generate a json string containing the configuration for a PingFederate Access Token Manager object.

        .EXAMPLE
            New-pfAccessTokenMangerJson -clientId TestThis

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
                "tables": [
                    {
                    "name": "Symmetric Keys",
                    "inherited": true,
                    "rows": [
            
                    ]
                    },
                    {
                    "name": "Certificates",
                    "inherited": true
                    }
                ],
            ...

        .PARAMETER ClientId
           This parameter is used to set the clientId in the JSON config
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$true
        )]
        [String]
        $ClientId
    ) # end param

    $AccessTokenManagerObject = [PSCustomObject]@{
        'id' = $ClientId
        'name' = $clientId
        'pluginDescriptorRef' = [PSCustomObject]@{
            'id' = "com.pingidentity.pf.access.token.management.plugins.JwtBearerAccessTokenManagementPlugin"
        } # end custom object
        'parentRef' = [PSCustomObject]@{
            'id' = "UPN"
        } # end custom object
        'configuration' = [PSCustomObject]@{
            'tables' = @(
                [PSCustomObject]@{
                    'name' = "Symmetric Keys"
                    'inherited' = $true
                    'rows' = @()
                },
                [PSCustomObject]@{
                    'name' = "Certificates"
                    'inherited' = $true
                }
            ) # end array
            'fields' = @(
                [PSCustomObject]@{
                    'name' = "Audience Claim Value"
                    'value' = $ClientId
                    'inherited' = $false
                },
                [PSCustomObject]@{
                    'name' = "JWKS Endpoint Path"
                    'value' = "/oauth/jwks"
                    'inherited' = $false
                }
            ) # end array
        } # end custom object
        'attributeContract' = [PSCustomObject]@{
            'inherited' = $true
        } # end custom object
        'selectionSettings' = [PSCustomObject]@{
            'inherited' = $true
        } # end custom object
        'accessControlSettings' = @{
            'inherited' = $false
            'restrictClients' = $true
            'allowedClients' = @(
                @{
                    'id' = $ClientId
                }
            )
        } # end hash
    } # end custom object
    $ATMJson = $AccessTokenManagerObject | ConvertTo-Json -Depth 4 | Format-Json
    $ATMJson
} # end function New-PFAccessTokenMangerJson

function New-PFClientJson
{
    <#
        .SYNOPSIS
            This function will generate a json string containing the configuration for a PingFederate Oauth Client object.
        .DESCRIPTION
            This function was built to specifically work with PingFederate v7.x+ as well as with another internal module maintianed by the client.

            This function will generate a json string containing the configuration for a PingFederate Oauth Client object.
            The function sets the RedirectUris to two entries automatically ('http://localhost/login' and 'http://ucsinfo.int.company.com/'), any additional
            values passed in the RedirectURIs parameter will be appended to the default entries.

            If the GrantType is set to 'AUTHORIZATION_CODE' then a ClientSecret will be generated for you.

        .EXAMPLE
           New-pfClientJson -ClientId TestThis -GrantType IMPLICIT -RedirectURIs 'http://localhost:8080'
           {
              "clientId": "TestThis",
              "redirectUris": [
                "http://localhost/login",
                "http://ucsinfo.int.company.com/",
                "http://localhost:8080"
              ],
              "grantTypes": [
                "IMPLICIT",
                "ACCESS_TOKEN_VALIDATION"
              ],
            ...

        .PARAMETER ClientId
           This parameter is used to set the ClientId in the JSON config
        .PARAMETER GrantType
           This parameter is used to set the GrantType.  This value should either be 'IMPLICIT' or 'AUTHORIZATION_CODE'.
           If the GrantType is set to 'AUTHORIZATION_CODE' then a ClientSecret will be generated for you.
        .PARAMETER RedirectURIs
           This is a string array that should contain a list of RedirectURIs that will be whitelisted in the configuration for 
           the OIDC client configuration.
           'http://localhost/login' and 'http://ucsinfo.int.company.com/' are configured by default and anything passed in this
           parameter will be appended to the list.
        .PARAMETER ClientSecret
           If you already have an existing client_secret you can optionally pass it in here and it will be used.  If you leave this
           blank and the GrantType is 'AUTHORIZATION_CODE' then a new client_secret will be generated for you.

    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$true
        )]
        [String]
        $ClientId,

        [Parameter(
            Mandatory=$true
        )]
        [String]
        $GrantType,

        [Parameter(
            Mandatory=$false
        )]
        [String]
        $ClientSecret = "",

        [Parameter(
            Mandatory=$false
        )]
        [Array]
        $RedirectURIs
    ) # end param

    if($GrantType.ToUpper() -eq 'AUTHORIZATION_CODE')
    {
        if($ClientSecret -eq "")
        {
            $ClientSecret = New-ClientSecret
        } # end if
        
        $ClientAuth = [PSCustomObject]@{
            'type' = 'SECRET'
            'secret' = $ClientSecret
        } # end custom object
    } 
    else
    {
        $ClientAuth = @{}
    } # end if

    $RedirectURIList = @(
        'http://localhost/login'
        'http://ucsinfo.int.company.com/'
    ) # end array
    if($RedirectURIs.Count -gt 0) { $RedirectURIList += $RedirectURIs }

    $ClientObject = [PSCustomObject]@{
        'clientId' = $ClientId
        'redirectUris' = $RedirectURIList
        'grantTypes' = @(
            $GrantType
            'ACCESS_TOKEN_VALIDATION'
        ) # end array
        'name' = $ClientId
        'description' = ""
        'logoUrl' = ""
        'defaultAccessTokenManagerRef' = [PSCustomObject]@{
            'id' = $ClientId
        } # end custom object
        'refreshRolling' = "SERVER_DEFAULT"
        'persistentGrantExpirationType' = "SERVER_DEFAULT"
        'persistentGrantExpirationTime' =  0
        'persistentGrantExpirationTimeUnit' = "DAYS"
        'bypassApprovalPage' = $true
        'restrictScopes' = $true
        'restrictedScopes' = @(
            'email'
            'openid'
            'profile'
        ) # end array
        'oidcPolicy' = [PSCustomObject]@{
            'policyGroup' = [PSCustomObject]@{
                'id' = $ClientId
            } # end custom object
            'grantAccessSessionRevocationApi' = $false
            'pingAccessLogoutCapable' = $false
        } # end custom object
        'clientAuth' = $ClientAuth
    }
    $ClientJson = $ClientObject | ConvertTo-Json -Depth 4 | Format-Json
    $ClientJson
} # end function New-PFClientJson

function New-PFOIDCPolicyJson
{
    <#
        .SYNOPSIS
           This function will generate a json string containing the configuration for a PingFederate OIDC Policy object.
        .DESCRIPTION
            This function was built to specifically work with PingFederate v7.x+ as well as with another internal module maintianed by the client.

            This function will generate a json string containing the configuration for a PingFederate OIDC Policy object.
            This function also contains built-in functionality for setting the two most commonly used conditionalCriteria 
            for connections.

        .EXAMPLE
           New-pfOIDCPolicyJson -ClientId TestThis
           {
              "id": "TestThis",
              "name": "TestThis",
              "accessTokenManagerRef": {
                "id": "TestThis"
              },
              "includeSriInIdToken": true,
              "includeUserInfoInIdToken": true,
              "attributeContract": {
                "coreAttributes": [
                  {
                    "name": "sub"
                  }
                ],
                "extendedAttributes": [
                  {
                    "name": "userPrincipalName"
                  },
            ...

        .EXAMPLE
           New-pfOIDCPolicyJson -ClientId TestThis -RestrictIPInternal $true -RestrictToGroup $true -RestrictedGroup "SSO Admins"

           ...
               "issuanceCriteria": {
                  "conditionalCriteria": [
        
                  ],
                  "expressionCriteria": [
                    {
                      "errorResult": "Access to this application is restricted to the Company network. Please access this application from the Company network or VPN.",
                      "expression": "#isClientIPInternal = @com.pingidentity.sdk.CIDROperations@isInRange(#this.get(\"context.ClientIp\"),\"10.0.0.0/8\") || @com.pingidentity.sdk.CIDROperations@isInRange(#this.get(\"context.ClientIp\"),\"172.16.0
                            .0/12\") || @com.pingidentity.sdk.CIDROperations@isInRange(#this.get(\"context.ClientIp\"),\"192.168.0.0/16\") || @com.pingidentity.sdk.CIDROperations@isInRange(#this.get(\"context.ClientIp\"),\"100.64.0.0/10\"), #isClientIPInternal"
                    },
                    {
                      "errorResult": "Access to this application is retricted to members of the SSO Admins AD group.",
                    "expression": "#groupString = "($RestrictedGroup|SSO Admins)", #authorized = false, #this.get("ds.VDS.memberOf") == null ? null : ( #groups = #this.get("ds.VDS.memberOf").getValues(), #groups.{ #group = #this, #group = new javax.naming.ldap.LdapName(#group), #cn = #group.getRdn(#group.size() - 1).getValue().toString(), #authorized = #authorized or (#cn.matches("(?i).*"+#groupString+".*")) } ), #authorized"
                    }
                  ]

           ...

        .PARAMETER ClientId
           This parameter is used to set the ClientId in the JSON config
        .PARAMETER RestrictIPInternal
           This parameter toggles whether a conditionalCriteria statement limiting a connection to use only internal IPs is added to the JSON config.
        .PARAMETER RestrictToGroup
           This parameter toggles whether a conditionalCriteria statement limiting a connection to only members of a certain group.  If you use
           this option you will need to also use the Restrictedgroup option to set which group access should be restricted to.
        .PARAMETER RestrcitedGroup
           This parameter is used with the RestrictToGroup option.  It specifies what group access to a connection should be restricted to.
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$true
        )]
        [String]
        $ClientId,

        [Parameter(
        )]
        [Boolean]
        $RestrictIPInternal = $false,

        [Parameter(
        )]
        [Boolean]
        $RestrictToGroup = $false,

        [Parameter(
        )]
        [String]
        $RestrictedGroup = ""
    ) # end param

    if($RestrictIPInternal -or $RestrictToGroup)
    {
        $ExpressionCriteria = @()
        if($RestrictIPInternal)
        {
            $ExpressionCriteria += [PSCustomObject]@{
                'errorResult' = "Access to this application is restricted to the Company network. Please access this application from the Company network or VPN."
                'expression' = '#isClientIPInternal = @com.pingidentity.sdk.CIDROperations@isInRange(#this.get("context.ClientIp"),"10.0.0.0/8") || @com.pingidentity.sdk.CIDROperations@isInRange(#this.get("context.ClientIp"),"172.16.0.0/12") || @com.pingidentity.sdk.CIDROperations@isInRange(#this.get("context.ClientIp"),"192.168.0.0/16") || @com.pingidentity.sdk.CIDROperations@isInRange(#this.get("context.ClientIp"),"100.64.0.0/10"), #isClientIPInternal'
            } # end custom object
        } # end if

        if($RestrictToGroup -and $RestrictedGroup -ne "")
        {
            $ExpressionCriteria += [PSCustomObject]@{
                'errorResult' = "Access to this application is retricted to members of the $RestrictedGroup AD group."
                'expression' = '#groupString = "($RestrictedGroup|SSO Admins)", #authorized = false, #this.get("ds.VDS.memberOf") == null ? null : ( #groups = #this.get("ds.VDS.memberOf").getValues(), #groups.{ #group = #this, #group = new javax.naming.ldap.LdapName(#group), #cn = #group.getRdn(#group.size() - 1).getValue().toString(), #authorized = #authorized or (#cn.matches("(?i).*"+#groupString+".*")) } ), #authorized'
            } # end custom object
        } # end if

        $IssuanceCriteria = [PSCustomObject]@{
            'conditionalCriteria' = @()
            'expressionCriteria' = $ExpressionCriteria
        } # end custom object
    } 
    else
    {
        $IssuanceCriteria = [PSCustomObject]@{
            'conditionalCriteria' = @()
        } # end custom object
    } # end if

    $OIDCPolicyObject = [PSCustomObject]@{
        'id' = $ClientId
        'name' = $ClientId
        'accessTokenManagerRef' = [PSCustomObject]@{
            'id' = $ClientId
        } # end custom object
        'includeSriInIdToken' = $true
        'includeUserInfoInIdToken' = $true
        'attributeContract' = [PSCustomObject]@{
            'coreAttributes' = @(
                [PSCustomObject]@{
                    'name' = 'sub'
                }
            )
            'extendedAttributes' = @(
                [PSCustomObject]@{
                    'name' = 'userPrincipalName'
                }
                [PSCustomObject]@{
                    'name' = 'employeeID'
                }
                [PSCustomObject]@{
                    'name' = 'given_name'
                }
                [PSCustomObject]@{
                    'name' = 'family_name'
                }
                [PSCustomObject]@{
                    'name' = 'groups'
                }
                [PSCustomObject]@{
                    'name' = 'name'
                }
                [PSCustomObject]@{
                    'name' = 'email'
                }
            )
        } # end custom object
        'attributeMapping' = [PSCustomObject]@{
            'attributeSources' = @(
                [PSCustomObject]@{
                    'type' = 'LDAP'
                    'dataStoreRef' = [PSCustomObject]@{
                        'id' = "{{pfVDSDataStoreId}}"
                    }
                    'id' = "VDS"
                    'description' = "VDS"
                    'baseDn' = "ou=users,o=company"
                    'searchScope' = "ONE_LEVEL"
                    'searchFilter' = '(&(objectClass=user)(userPrincipalName=${user_principal_name}))'
                    'binaryAttributeSettings' = @{}
                    'memberOfNestedGroup' = $false 
                } # end custom object
            )
            'attributeContractFulfillment' = [PSCustomObject]@{
                'sub' = [PSCustomObject]@{
                    'source' = [PSCustomObject]@{
                        'type' = "LDAP_DATA_STORE"
                        'id' = "VDS"
                    } # end custom object
                    'value' = "employeeID"
                } # end attribute
                'userPrincipalName' = [PSCustomObject]@{
                    'source' = [PSCustomObject]@{
                        'type' = "LDAP_DATA_STORE"
                        'id' = "VDS"
                    } # end custom object
                    'value' = "userPrincipalName"
                } # end attribute
                'employeeID' = [PSCustomObject]@{
                    'source' = [PSCustomObject]@{
                        'type' = "LDAP_DATA_STORE"
                        'id' = "VDS"
                    } # end custom object
                    'value' = "employeeID"
                } # end attribute
                'given_name' = [PSCustomObject]@{
                    'source' = [PSCustomObject]@{
                        'type' = "LDAP_DATA_STORE"
                        'id' = "VDS"
                    } # end custom object
                    'value' = "givenName"
                } # end attribute
                'family_name' = [PSCustomObject]@{
                    'source' = [PSCustomObject]@{
                        'type' = "LDAP_DATA_STORE"
                        'id' = "VDS"
                    } # end custom object
                    'value' = "sn"
                } # end attribute
                'groups' = [PSCustomObject]@{
                    'source' = [PSCustomObject]@{
                        'type' = "EXPRESSION"                    
                    } # end custom object
                    'value' = '#UserGroups = new java.util.ArrayList(), #groups = #this.get("ds.VDS.memberOf") != null ? #this.get("ds.VDS.memberOf").getValues() : {}, #groups.{ #group = #this,  #group = new javax.naming.ldap.LdapName(#group),  #cn = #group.getRdn(#group.size() - 1).getValue().toString(), #UserGroups.add(#cn) }, #UserGroups != null ? new org.sourceid.saml20.adapter.attribute.AttributeValue(#UserGroups) : null'
                } # end attribute
                'name' = [PSCustomObject]@{
                    'source' = [PSCustomObject]@{
                        'type' = "LDAP_DATA_STORE"
                        'id' = "VDS"
                    } # end custom object
                    'value' = "displayName"
                } # end attribute
                'email' = [PSCustomObject]@{
                    'source' = [PSCustomObject]@{
                        'type' = "LDAP_DATA_STORE"
                        'id' = "VDS"
                    } # end custom object
                    'value' = "mail"
                } # end attribute
            } # end custom object
            'issuanceCriteria' = $IssuanceCriteria
        } # end custom object
    } # end custom object
    $OIDCPolicyJson = $OIDCPolicyObject  | ConvertTo-Json -Depth 5 | Format-Json
    $OIDCPolicyJson = $OIDCPolicyJson.Replace('\u0026', '&')
    $OIDCPolicyJson
} # end function New-PFOIDCPolicyJson

function New-PIMPassword
{
    <#
        .SYNOPSIS
           This function makes an API call to the PIM server to register a new clientSecret for a connection.
        .DESCRIPTION
           This function makes an API call to the PIM server to register a new clientSecret for a connection.

           To use this function you must pass a credential that has the required permissions to create new
           password entries for the specified shared credentials password list.
        .EXAMPLE
           new-PIMPassword -ClientID 'TestThis' -ClientSecret 'ThisIsTheTestPassword' -PasswordList 'SSO-Connections' -Credential $pfCred
           Success
        .PARAMETER ClientId
           The clientId will map to the AccountName in PIM
        .PARAMETER ClientSecret
           The ClientSecret will map to the Password in PIM
        .PARAMETER SystemName
           The SystemName will map to the SystemName in PIM, for PF connections this should be 'ssodev.<company>.com' or 'sso.<company>.com'.
        .PARAMETER PasswordList
           This will determine which shared credential list this entry will be added to, for PF connections this should be 'SSO-Connections'.
        .PARAMETER Credential
           This will be a PSCredential object for an AD account that has create permissions to the specifed shared credentials list.
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true
        )]
        [string]
        $ClientID,

        [Parameter(
            Mandatory = $true
        )]
        [string]
        $ClientSecret,

        [Parameter(
            Mandatory = $true
        )]
        [string]
        $SystemName,

        [Parameter(
            Mandatory = $true
        )]
        [string]
        $PasswordList = 'SSO-Connections',

        [Parameter(
            Mandatory = $true
        )]
        [System.Management.Automation.PSCredential]
        $Credential
    ) # end param

    $UserName = $Credential.UserName

    $BaseURI = "https://pim/PWCWeb/ClientAgentRequests.asp?"

    $Command = "Command=Login&Authenticator=<domain>&LoginUsername=$($Credential.UserName)&LoginPassword=$($Credential.GetNetworkCredential().password)"

    $URI = "$($BaseURI)$($Command)"
    $Response = Invoke-WebRequest -Uri $URI -Method Get

    $ResponseContent = $Response.Content
    $ResponseStatus = ($ResponseContent.Split(";")[0]).Trim()
    $Auth = ""

    if($ResponseStatus -eq 'Success') 
    { 
        $Auth = ($ResponseContent.Split(";")[1]).Trim()
        $Command = "Command=SetPasswordListPassword&AuthenticationToken=$Auth&SystemName=$($SystemName)&AccountName=$($ClientID)&Password=$($Clientsecret)&Comment=client_id: $($ClientID)&PasswordList=$($PasswordList)"

        $URI = "$($BaseURI)$($Command)"
        $Response = Invoke-WebRequest -Uri $URI -Method Get
        $ResponseContent = $Response.Content
        $ResponseStatus = ($ResponseContent.Split(";")[0]).Trim()
        $ResponseStatus
    } # end if
} # end function New-PIMPassword

function Export-PFAccessTokenManager
{
    <#
        .SYNOPSIS
           Export the AccessTokenManager configuration for a given ClientID 
        .DESCRIPTION
           This function pulls the AccessTokenManager configuration from the Admin API.
           The output is sanitized to remove unneeded data and then converted to JSON.
        .EXAMPLE
           Export-PFAccessTokenManager -ClientID ABTEST2 -SSOServer sodev1 -Credential $PFcred

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
                "tables": [
                  {
                    "name": "Symmetric Keys",
                    "inherited": true,
                    "rows": [
          
                    ]
                  },
            ...

        .PARAMETER ClientID
           Json string to format
        .PARAMETER SSOServer
           This parameter is the hostname of the SSO server you are targeting to pull the config from.
        .PARAMETER Credential
           This parameter is a PSCredential object containing credentials that have permission to access the PingFed Admin API.

    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true
        )]
        [String]
        $ClientID,

        [Parameter(
            Mandatory = $true
        )]
        [String]
        $SSOServer,

        [Parameter(
            Mandatory = $true
        )]
        [System.Management.Automation.PSCredential]
        $Credential
    ) # end if

    $ATMObject = Get-PFAccessTokenManager -ComputerName $SSOServer -Credential $Credential -Filter {$_.id -eq $ClientID}

    $ATMObject.pluginDescriptorRef.psobject.Properties.Remove('location')
    $ATMObject.parentRef.psobject.Properties.Remove('location')
    $ATMObject.accessControlSettings.allowedClients[0].psobject.Properties.Remove('location')
    $ATMObject.configuration.fields = ($ATMObject.configuration.fields | ? inherited -ne 'True')

    $ATMJson = $ATMObject | ConvertTo-Json -Depth 6 | Format-Json
    $ATMJson
} # end function Export-PFAccessTokenManager

function Export-PFAccessTokenManagerMapping
{
    <#
        .SYNOPSIS
           Export the AccessTokenManagerMapping configuration for a given ClientID 
        .DESCRIPTION
           This function pulls the AccessTokenManagerMapping configuration from the Admin API.
           The output is sanitized to remove unneeded data and then converted to JSON.
        .EXAMPLE
           Export-PFAccessTokenManagerMapping -ClientID ABTEST2 -SSOServer sodev1 -Credential $PFcred

            {
              "attributeSources": [
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

        .PARAMETER ClientID
           Json string to format
        .PARAMETER SSOServer
           This parameter is the hostname of the SSO server you are targeting to pull the config from.
        .PARAMETER Credential
           This parameter is a PSCredential object containing credentials that have permission to access the PingFed Admin API.
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true
        )]
        [String]
        $ClientID,

        [Parameter(
            Mandatory = $true
        )]
        [String]
        $SSOServer,

        [Parameter(
            Mandatory = $true
        )]
        [System.Management.Automation.PSCredential]
        $Credential
    ) # end param

    $ATMMObject = Get-PFAccessTokenManagerMapping -ComputerName sodev1 -Credential $Credential -Filter {$_.id -like "*$ClientID"} 

    $ATMMObject.attributeSources.dataStoreRef.psobject.Properties.Remove('location')
    $ATMMObject.context.contextRef.psobject.Properties.Remove('location')
    $ATMMObject.accessTokenManagerRef.psobject.Properties.Remove('location')

    $ATMMJson = $ATMMObject | ConvertTo-Json -Depth 6 | Format-Json
    $ATMMJson
} # end function Export-PFAccessTokenManagerMapping

function Export-PFOAuthClient
{
    <#
        .SYNOPSIS
           Export the AccessTokenManagerMapping configuration for a given ClientID 
        .DESCRIPTION
           This function pulls the OAuthClient configuration from the Admin API.
           The output is sanitized to remove unneeded data and then converted to JSON.
        .EXAMPLE
           Export-PFOAuthClient -ClientID ABTEST2 -SSOServer sodev1 -Credential $PFcred

            {
              "clientId": "ABTest2",
              "redirectUris": [
                "http://localhost/login",
                "http://ucsinfo.int.company.com/",
                "http://yahoo.com"
              ],
              "grantTypes": [
                "AUTHORIZATION_CODE",
                "ACCESS_TOKEN_VALIDATION"
              ],
              "name": "ABTest2",
              "description": "",
              "logoUrl": "",
            ...

        .PARAMETER ClientID
           Json string to format
        .PARAMETER SSOServer
           This parameter is the hostname of the SSO server you are targeting to pull the config from.
        .PARAMETER Credential
           This parameter is a PSCredential object containing credentials that have permission to access the PingFed Admin API.
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true
        )]
        [String]
        $ClientID,

        [Parameter(
            Mandatory = $true
        )]
        [String]
        $SSOServer,

        [Parameter(
            Mandatory = $true
        )]
        [System.Management.Automation.PSCredential]
        $Credential
    ) # end param

    $ClientObject = Get-PFOAuthClient -ComputerName $SSOServer -Credential $Credential -Filter {$_.clientId -eq $ClientID}

    $GrantType = $ClientObject.grantTypes[0]

    if($GrantType -eq 'AUTHORIZATION_CODE')
    {
        # Remove encryptedSecret from $ClientObject.clientAuth
        # Add secret with empty string
        $ClientObject.clientAuth.psobject.Properties.Remove('encryptedSecret')
        $ClientObject.clientAuth.psobject.Properties.Remove('enforceReplayPrevention')
        $ClientObject.psobject.Properties.Remove('requireSignedRequests')
        $ClientObject.clientAuth | Add-Member -MemberType NoteProperty -Name 'secret' -Value ""
    } # end if

    $ClientObject.defaultAccessTokenManagerRef.psObject.Properties.Remove('location')
    $ClientObject.oidcPolicy.policyGroup.psobject.Properties.Remove('location')

    $ClientJson = $ClientObject | ConvertTo-Json -Depth 6 | Format-Json
    $ClientJson
} # end function Export-PFOAuthClient

function Export-PFOpenIDConnectPolicy
{
    <#
        .SYNOPSIS
           Export the OpenIDConnectPolicy configuration for a given ClientID 
        .DESCRIPTION
           This function pulls the OpenIDConnectPolicy configuration from the Admin API.
           The output is sanitized to remove unneeded data and then converted to JSON.
        .EXAMPLE
           Export-PFOpenIDConnectPolicy -ClientID ABTEST2 -SSOServer ndcssodev1 -Credential $PFcred

            {
              "id": "ABTest2",
              "name": "ABTest2",
              "idTokenLifetime": 5,
              "attributeContract": {
                "coreAttributes": [
                  {
                    "name": "sub"
                  }
                ],
                "extendedAttributes": [
                  {
                    "name": "name"
                  },
                  {
                    "name": "groups"
                  },
                  {
                    "name": "employeeID"
                  },
            ...

        .PARAMETER ClientID
           Json string to format
        .PARAMETER SSOServer
           This parameter is the hostname of the SSO server you are targeting to pull the config from.
        .PARAMETER Credential
           This parameter is a PSCredential object containing credentials that have permission to access the PingFed Admin API.
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true
        )]
        [String]
        $ClientID,

        [Parameter(
            Mandatory = $true
        )]
        [String]
        $SSOServer,

        [Parameter(
            Mandatory = $true
        )]
        [System.Management.Automation.PSCredential]
        $Credential
    ) # end param

    $OIDCPolicyObject = Get-PFOpenIDConnectPolicy -ComputerName $SSOServer -Credential $Credential -Filter {$_.id -eq $ClientID}

    $OIDCPolicyObject.attributeMapping.attributeSources[0].dataStoreRef.psobject.Properties.Remove('location')
    $OIDCPolicyObject.accessTokenManagerRef.psobject.Properties.Remove('location')

    $OIDCPolicyJson = ($OIDCPolicyObject | ConvertTo-Json -Depth 6 | Format-Json).Replace("\u0026","&")
    $OIDCPolicyJson
} # end function Export-PFOpenIDConnectPolicy

function Export-PFConnection
{
    <#
        .SYNOPSIS
           This function will generate configuration artifacts from an existing connection.
        .DESCRIPTION
           This function will make a series of Admin API calls to generate the AccessTokenManager,
           AccessTokenManagerMapping, OAuthClient, and OpenIDConnect JSON config files.  The files
           will be written to the location specified in the Path parameter.
        .EXAMPLE
            Export-PFConnection

        .PARAMETER ClientID
           Json string to format
        .PARAMETER SSOServer
           This parameter is the hostname of the SSO server you are targeting to pull the config from.
        .PARAMETER Path
           This parameter specifies the path where the extracted configurations files will be written. 
        .PARAMETER Credential
           This parameter is a PSCredential object containing credentials that have permission to access the PingFed Admin API.
    #>      
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true
        )]
        [String]
        $ClientID,

        [Parameter(
            Mandatory = $true
        )]
        [String]
        $SSOServer,

        [Parameter(
            Mandatory = $true
        )]
        [String]
        $Path,

        [Parameter(
            Mandatory = $true
        )]
        [System.Management.Automation.PSCredential]
        $Credential
    ) # end param

    if($SSOServer -eq 'ssodev1')
    {
        $SSOURL = 'ssodev.company.com'
    }
    else
    {
        $SSOURL = 'sso.compay.com'
    } # end if

    if(-not $Path.EndsWith('\')){ $Path += '\'}

    $FullPath = "$Path$clientId"
    if(-not (Test-Path -Path $FullPath)) { $null = new-item -Path $Path -Name $ClientId -ItemType Directory }
    
    $ATMJson        = Export-PFAccessTokenManager -ClientID $ClientID -SSOServer $SSOServer -Credential $Credential
    $ATMMJson       = Export-PFAccessTokenManagerMapping -ClientID $ClientID -SSOServer $SSOServer -Credential $Credential
    $ClientJson     = Export-PFOAuthClient -ClientID $ClientID -SSOServer $SSOServer -Credential $Credential
    $OIDCPolicyJson = Export-PFOpenIDConnectPolicy -ClientID $ClientID -SSOServer $SSOServer -Credential $Credential


    $ATMJson        | Out-File -FilePath "$FullPath\$ClientId - AccessTokenManager.json" -Encoding utf8
    $ATTMJson       | Out-File -FilePath "$FullPath\$ClientId - AccessTokenManagerMapping.json" -Encoding utf8
    $ClientJson     | Out-File -FilePath "$FullPath\$ClientId - Client.json" -Encoding utf8
    $OIDCPolicyJson | Out-File -FilePath "$FullPath\$ClientId - OIDC Policy.json" -Encoding utf8    

    $null = New-OIDCHTMLForm -ClientId $ClientId -SSOUrl $SSOURL -GrantType $GrantType -RedirectURI 'http://ucsinfo.int.company.com/' -ConnectionPath $FullPath

} # end function Export-PFConnection

function New-PFOIDConnectionWrapper
{
    <#
        .SYNOPSIS
           This function wraps the New-PFOIDCConnection function and adds end to end automation of the connection creation process.
        .DESCRIPTION
            This function was built to specifically work with PingFederate v7.x+ as well as with another internal module maintianed by the client.

            This function wraps the New-PFOIDCConnection function and adds end to end automation of the connection creation process.

            This function handles the following tasks:
            - Creates a feature branch in the local Git repo for pfConnections based on the develop branch
            - Creates a new OIDC Connection folder in the pfConnections root based on clientId name
            - Generates <ClientId> - AccessTokenManager.json file
            - Generates <ClientId> - Client.json file
            - Generates <ClientId> - OIDC Policy.json file
            - Creates new OIDC connection in PingFed, via a call to New-PFOIDCConnection
            - Tests the connection and validates the token
            - Generates a <ClientId>_<ssoenv>_<GrantType>.html test form file
            - If the GrantType was auth_code then the new clientSecret will be added to PIM
            - Generates the body of the notification email
            - Adds the four new files to the feature-<ClientId> branch
            - Performs a Git commit -m and puts in a standard comment
            - Merges the feature branch into the develop branch using the --no-ff switch
            - Returns an object with ClientId, ClientSecret, PIMStatus, ValidatedToken, and Email body

            The Git interactions can be turned off by using the AddToGit = $false parameter.  If you use the AddToGit feature you will need
            to have the posh-Git module installed.  The script stops short of performing a git push and leaves that step up to you to ensure
            you are comfortable pushing the new changes back to the origin.

        .EXAMPLE

           $props = @{
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

        .PARAMETER ClientId
           This parameter represents the name of the application that the OIDC connection is being created for.  No spaces are allowed.
        .PARAMETER GrantType
           This parameter sets the Grant Type for the OIDC connection.  This value should be either 'IMPLICIT' or 'AUTHORIZATION_CODE'.
        .PARAMETER SSOServer
           This parameter tells the script which PingFed server to connect to for Admin API calls.  
        .PARAMETER RestrictIPInternal
           This parameter toggles whether a conditionalCriteria statement limiting a connection to use only internal IPs is added to the JSON config.
        .PARAMETER RestrictToGroup
           This parameter toggles whether a conditionalCriteria statement limiting a connection to only members of a certain group.  If you use
           this option you will need to also use the Restrictedgroup option to set which group access should be restricted to.
        .PARAMETER RestrcitedGroup
           This parameter is used with the RestrictToGroup option.  It specifies what group access to a connection should be restricted to.
        .PARAMETER ClientSecret
           This parameter is used to specifiy an existing client_secrect to use when creating the connection.
        .PARAMETER AddToGit
           This parameter toggles functionality to control adding the new connection to the local Git Repo as a new feature branch. If you use the AddToGit 
           feature you will need to have the posh-Git module installed.  The script stops short of performing a git push and leaves that step up to you to
           ensure you are comfortable pushing the new changes back to the origin.
        .PARAMETER AddToPim
           This paramater contols if you want new Auth_code connections to register the client_secret in PIM automatically.  If you have already assigned
           a client_secret and stored it in PIM then you would use this option.
        .PARAMETER PFPath
           This parameter is the folder path to the pfconnections folder.  You can put this folder anywhere when you clone the pfConnections repo.
        .PARAMETER RedirectURIs
           This parameter is a string array used for specifiying additional Redirect URIs to add to the connection at create time.
        .PARAMETER Credential
           This parameter is a PSCredential object set with a username and password of a user that is granted admin permissions in the PingFed console.
           The username should not include any domain information.       
    #>
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true
        )]
        [String]
        $ClientID,

        [Parameter(
            Mandatory = $true
        )]
        [ValidateSet("AUTHORIZATION_CODE","IMPLICIT")]
        [String]
        $GrantType,

        [Parameter(
            Mandatory = $true
        )]
        [String]
        $SSOServer,

        [Parameter(
            Mandatory=$true
        )]
        [Boolean]
        $RestrictIPInternal = $false,

        [Parameter(
            Mandatory=$true
        )]
        [Boolean]
        $RestrictToGroup = $false,

        [Parameter(
            Mandatory=$false
        )]
        [String]
        $RestrictedGroup = "",

        [Parameter(
            Mandatory=$false
        )]
        [string]
        $ClientSecret = "",

        [Parameter(
            Mandatory=$false
        )]
        [Boolean]
        $AddToGit = $true,

        [Parameter(
            Mandatory=$false
        )]
        [Boolean]
        $AddToPim = $true,

        [Parameter(
            Mandatory = $false
        )]
        [String]
        $PFPath = 'C:\PS Script\dsa\pfconnections\Connections\',

        [Parameter(
            Mandatory=$false
        )]
        [Array]
        $RedirectURIs,

        [Parameter(
            Mandatory = $true
        )]
        [System.Management.Automation.PSCredential]
        $Credential
    )

    Import-Module 'C:\PS Script\dsa\pspingfederate\PingFederate'
    Import-Module posh-git


    if($SSOServer -eq 'ndcssodev1')
    {
        $SSOURL = 'ssodev.company.com'
    }
    else
    {
        $SSOURL = 'sso.company.com'
    } # end if

    if($AddToGit)
    {
        $GitStatus = Get-GitStatus
        if($GitStatus.Branch -ne 'develop') { $null = git checkout develop }
        $GitStatus = Get-GitStatus
        if($GitStatus.BehindBy -ne 0) { $null = git pull }
        $null = git checkout -b feature-$ClientId develop
    } # end if

    $PFConnectionPath = "$PFPath$clientId"
    if(-not (Test-Path -Path $PFConnectionPath)) { $null = new-item -Path $PFPath -Name $ClientId -ItemType Directory }

    $AccessTokenManagerJson = New-PFAccessTokenMangerJson -ClientId $ClientId
    $OIDCPolicyJson         = New-PFOIDCPolicyJson -ClientId $ClientId -RestrictIPInternal $RestrictIPInternal -RestrictToGroup $RestrictToGroup -RestrictedGroup $RestrictedGroup

    if($RedirectURIs.Count -gt 0) 
    {
        $ClientJson = New-PFClientJson -ClientId $ClientId -GrantType $GrantType -RedirectURIs $RedirectURIs
    }
    else
    {
        $ClientJson = New-PFClientJson -ClientId $ClientId -GrantType $GrantType
    } # end if

    $AccessTokenManagerJson | Out-File -FilePath "$PFConnectionPath\$ClientId - AccessTokenManager.json" -Encoding utf8
    $ClientJson             | Out-File -FilePath "$PFConnectionPath\$ClientId - Client.json" -Encoding utf8
    $OIDCPolicyJson         | Out-File -FilePath "$PFConnectionPath\$ClientId - OIDC Policy.json" -Encoding utf8

    if($GrantType -eq 'AUTHORIZATION_CODE')
    {
        $ClientObject = $ClientJson| ConvertFrom-Json
        $ClientSecret = $ClientObject.clientAuth.secret
    }
    else
    {
        $ClientSecret = ""
    } # end if

    if(!$PFCred) { $PFCred = Get-Credential}

    $null = Set-Location -Path (Split-Path -Path $PFPath)
    $null = New-PFOIDCConnection -ComputerName $SSOServer -Credential $PFCred -ApplicationName $ClientId -NewAccessTokenManagerTemplate "Templates\Template_Create AccessTokenManager - Inherit.json" -AccessTokenManagerMappingTemplate "Templates\Template_Create AccessTokenMapping - IWA.json"

    try
    {
        $ValidateToken = Test-OIDCConnection -Clientid $ClientId -SSOUrl $SSOURL -GrantType $GrantType -ClientSecret $ClientSecret -RedirectURI 'http://ucsinfo.int.company.com/'
    }
    catch
    {
        Write-Warning $_.Exception.Message
    } # end try

    $null = New-OIDCHTMLForm -ClientId $ClientId -SSOUrl $SSOURL -GrantType $GrantType -RedirectURI 'http://ucsinfo.int.company.com/' -ConnectionPath $PFConnectionPath

    if($GrantType -eq 'AUTHORIZATION_CODE')
    {
        if($AddToPim)
        {
            $PimStatus = New-PIMPassword -Clientid $ClientId -clientsecret $ClientSecret -systemName $SSOURL -Credential $PFCred -PasswordList "SSO-Connections"
        } # end if
        # Sanitize client secret from client.json file.
        (Get-Content -Path "$PFConnectionPath\$ClientId - Client.json") | ForEach-Object {$_ -replace "$ClientSecret", ""} | Set-Content -Path "$PFConnectionPath\$ClientId - Client.json" -Encoding UTF8
    } # end if

    if($AddToGit)
    {
        $null = git add $PFConnectionPath
        $null = git commit -m "$ClientId - Created new OIDC Connection in $SSOURL."
        $null = git checkout develop
        $null = git merge --no-ff feature-$ClientId
    } # end if

    if($GrantType -eq 'AUTHORIZATION_CODE')
    {
        $Form = get-content -path 'C:\PS Script\dsa\emailTemplateAuth.txt' -raw
        $NewForm = $Form.Replace('{{cliend ID}}',$ClientId).Replace('{{client secret}}',$ClientSecret)
    }
    else
    {
        $Form = get-content -path 'C:\PS Script\dsa\emailTemplateImplicit.txt' -raw
        $NewForm = $Form.Replace('{{cliend ID}}',$ClientId)
    } # end if

    $ReturnObject = [PSCustomObject]@{
        'ClientID' = $ClientID
        'ClientSecret' = $ClientSecret
        'EmailForm' = $NewForm
        'Validation' = $validateToken
        'Payload' = $validateToken.Payload
    } # end custom object
    $ReturnObject | Write-Output
} # end function New-PFOIDConnectionWrapper
