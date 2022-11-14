package common

import (
	"fmt"
	"github.com/kubernetes/dashboard/src/app/backend/api"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	api2 "k8s.io/client-go/tools/clientcmd/api"
)

const MEC_USER_GROUP = "mec.user.group"
func AuthFilter(user api2.AuthInfo) metaV1.ListOptions {
	if user.Impersonate != "" && len(user.ImpersonateGroups) > 0 {
		usergroup := user.ImpersonateGroups[0]
		return metaV1.ListOptions{
			LabelSelector: fmt.Sprintf("%s=%s",MEC_USER_GROUP,usergroup),
		}
	}
	return api.ListEverything
}
