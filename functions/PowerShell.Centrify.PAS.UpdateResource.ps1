# Copyright 2016 Centrify Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

function UpdateResource {
    param(
        [Parameter(Mandatory=$true)]
        $endpoint,
        [Parameter(Mandatory=$true)]
        $bearerToken,
        [Parameter(Mandatory=$true)]
        $ID,
        [Parameter(Mandatory=$true)]
        $Name,
        [Parameter(Mandatory=$true)]
        $FQDN,
        [Parameter(Mandatory=$true)]
        $ComputerClass,
        $SessionType = "",
        $Port = $null,
        $Description = "",
        $ProxyUser = "",
        $ProxyUserPassword = "",
        $ProxyUserIsManaged = "",
        $ManagementMode = "",
        $ManagementPort = $null
    )

    $restArg = @{}
    $restArg.ID = $ID
    $restArg.Name = $Name
    $restArg.FQDN = $FQDN
    $restArg.ComputerClass = $ComputerClass
    if ($SessionType -ne "")
    {
        $restArg.SessionType = $SessionType
    }

    if ($Port -ne $null)
    {
        $restArg.Port = $Port
    }

    if ($Description -ne "")
    {
        $restArg.Description = $Description
    }

    if ($ProxyUser -ne "")
    {
        if ($ProxyUserPassword -ne "")
        {
            if ($ProxyUserIsManaged -ne ""){
                $restArg.ProxyUser = $ProxyUser
                $restArg.ProxyUserPassword = $ProxyUserPassword
                $restArg.ProxyUserIsManaged = $ProxyUserIsManaged
            }else{
                throw "You must enter a management state for the proxy user"
            }
        }else{
            throw "You must enter a password for the proxy user"
        }
    }

    if ($ManagementMode -ne "")
    {
        $restArg.ManagementMode = $ManagementMode
    }

    if ($ManagementPort -ne $null)
    {
        $restArg.ManagementPort = $ManagementPort
    }

    $restResult = Centrify-InvokeREST -Method "/ServerManage/UpdateResource" -Endpoint $endpoint -Token $bearerToken -ObjectContent $restArg -Verbose:$enableVerbose
    if($restResult.success -ne $true)
    {
        throw "Server error: $($restResult.Message)"
    }

    return $restResult.Result
}
