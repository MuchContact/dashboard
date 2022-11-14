// Copyright 2017 The Kubernetes Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"encoding/base64"
	"encoding/json"
	authApi "github.com/kubernetes/dashboard/src/app/backend/auth/api"
	"k8s.io/client-go/tools/clientcmd/api"
	"strings"
)

// Implements Authenticator interface
type tokenAuthenticator struct {
	token string
	user string
	group string
}

// GetAuthInfo implements Authenticator interface. See Authenticator for more information.
func (self tokenAuthenticator) GetAuthInfo() (api.AuthInfo, error) {
	return api.AuthInfo{
		Token: self.token,
		Impersonate: self.user,
		ImpersonateGroups: []string{self.group},
	}, nil
}

// NewTokenAuthenticator returns Authenticator based on LoginSpec.
func NewTokenAuthenticator(spec *authApi.LoginSpec) authApi.Authenticator {
	token, user, group := parseTokenAndUserInfo(spec.Token)
	return &tokenAuthenticator{
		token: token,
		user:  user,
		group: group,
	}
}

func parseTokenAndUserInfo(token string) (string, string, string) {
	if len(strings.Split(token, ".")) < 4 {
		return token, "", ""
	}
	n := strings.SplitN(token, ".", 2)
	decodeString, err := base64.StdEncoding.DecodeString(n[0])
	if err != nil {
		return token, "", ""
	}
	var user map[string]string
	if err = json.Unmarshal(decodeString, &user); err != nil {
		return token, "", ""
	}
	return n[1], user["user"], user["group"]
}
