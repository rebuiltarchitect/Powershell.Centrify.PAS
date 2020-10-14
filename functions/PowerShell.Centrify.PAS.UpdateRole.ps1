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

function UpdateRole {
    param(
        [Parameter(Mandatory=$true)]
        $endpoint,
        [Parameter(Mandatory=$true)]
        $bearerToken,
        [Parameter(Mandatory=$true)]
        $name,
        [Parameter(Mandatory=$false)]
        $description,
        [Parameter(Mandatory=$false)]
        $roles,
        [Parameter(Mandatory=$false)]
        $users,
        [Parameter(Mandatory=$false)]
        $groups
                  
    )
    
    $restArg = @{}
    $restArg.Name = $name
    $restArg.Description = $description
    $restArg.Roles = @{}
    $restArg.Roles.Add = $roles
    $restArg.Users = @{}
    $restArg.Users.Add = $users
    $restArg.Groups = @{}
    $restArg.Groups.Add = $groups
    
    $restResult = Centrify-InvokeREST -Method "/SaasManage/UpdateRole" -Endpoint $endpoint -Token $bearerToken -ObjectContent $restArg -Verbose:$enableVerbose
    if($restResult.success -ne $true)
    {
        throw "Server error: $($restResult.Message)"
    }     
    
    return $restResult.Result
}
