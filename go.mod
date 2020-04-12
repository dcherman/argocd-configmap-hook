module github.com/dcherman/argocd-configmap-hook

go 1.14

require (
	github.com/Masterminds/semver v1.5.0 // indirect
	github.com/argoproj/argo-cd v1.5.1
	github.com/argoproj/pkg v0.0.0-20200319004004-f46beff7cd54 // indirect
	github.com/ghodss/yaml v1.0.0
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/imdario/mergo v0.3.9
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/mattbaird/jsonpatch v0.0.0-20171005235357-81af80346b1a
	github.com/robfig/cron v1.2.0 // indirect
	github.com/sirupsen/logrus v1.5.0 // indirect
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0 // indirect
	google.golang.org/grpc v1.28.1 // indirect
	gopkg.in/src-d/go-git.v4 v4.13.1 // indirect
	k8s.io/api v0.18.1
	k8s.io/apimachinery v0.18.1
	k8s.io/client-go v11.0.0+incompatible
	k8s.io/utils v0.0.0-20200411171748-3d5a2fe318e4 // indirect
)

replace k8s.io/client-go => k8s.io/client-go v0.18.1
