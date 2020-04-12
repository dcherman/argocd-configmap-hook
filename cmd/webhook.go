package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/ghodss/yaml"
	"github.com/golang/glog"
	"github.com/imdario/mergo"
	"github.com/mattbaird/jsonpatch"
	"k8s.io/api/admission/v1beta1"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	v1 "k8s.io/api/apps/v1"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	applicationv1alpha1 "github.com/argoproj/argo-cd/pkg/apis/application/v1alpha1"
)

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()

	// (https://github.com/kubernetes/kubernetes/issues/57982)
	defaulter = runtime.ObjectDefaulter(runtimeScheme)
)

var ignoredNamespaces = []string{
	metav1.NamespaceSystem,
	metav1.NamespacePublic,
}

const (
	admissionWebhookAnnotationInjectKey = "argoproj.labs/argocd/config-injector"

	admissionWebhookAnnotationStatusKey = "sidecar-injector-webhook.morven.me/status"
)

type WebhookServer struct {
	sidecarConfig *Config
	server        *http.Server
}

// Webhook Server parameters
type WhSvrParameters struct {
	port           int    // webhook server port
	certFile       string // path to the x509 certificate for https
	keyFile        string // path to the x509 private key matching `CertFile`
	sidecarCfgFile string // path to sidecar injector configuration file
}

type ConfigMapKeySelector struct {
	// The ConfigMap to select from.
	Name string `json:"name"`
	// The key to select.
	Key string `json:"key,omitempty"`
	// Specify whether the ConfigMap/Secret must be defined
	Optional bool `json:"optional,omitempty"`
}

// ValuesFromSource represents a source of values.
// Only one of its fields may be set.
type ValuesFromSource struct {
	// Selects a key of a ConfigMap.
	ConfigMapKeyRef *ConfigMapKeySelector `json:"configMapKeyRef,omitempty"`
}

type Config struct {
}

type ValuesRefs struct {
	ValuesFrom []ValuesFromSource `json:"valuesFrom`
}

func init() {
	//_ = corev1.AddToScheme(runtimeScheme)
	_ = admissionregistrationv1beta1.AddToScheme(runtimeScheme)
	// defaulting with webhooks:
	// https://github.com/kubernetes/kubernetes/issues/57982
	_ = v1.AddToScheme(runtimeScheme)
}

func loadConfig(configFile string) (*Config, error) {
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	glog.Infof("New configuration: sha256sum %x", sha256.Sum256(data))

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Check whether the target resoured need to be mutated
func mutationRequired(ignoredList []string, application *applicationv1alpha1.Application) bool {
	// skip special kubernete system namespaces
	for _, namespace := range ignoredList {
		if application.ObjectMeta.Namespace == namespace {
			glog.Infof("Skip mutation for %v for it's in special namespace:%v", application.ObjectMeta.Name, application.ObjectMeta.Namespace)
			return false
		}
	}

	if !application.Spec.Source.IsHelm() {
		glog.Infof("Skip mutation for %v, only Helm is currently supported", application.ObjectMeta.Name, application.ObjectMeta.Namespace)
		return false
	}

	annotations := application.ObjectMeta.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}

	_, required := annotations[admissionWebhookAnnotationInjectKey]

	glog.Infof("Mutation policy for %v/%v: required:%v", application.ObjectMeta.Namespace, application.ObjectMeta.Name, required)
	return required
}

// create mutation patch for resoures
func createPatch(application *applicationv1alpha1.Application) ([]jsonpatch.JsonPatchOperation, error) {
	modifiedApplication := application.DeepCopy()

	annotations := application.ObjectMeta.GetAnnotations()
	injectAnnotation := annotations[admissionWebhookAnnotationInjectKey]

	var valueRefs ValuesRefs

	if err := json.Unmarshal([]byte(injectAnnotation), &valueRefs); err != nil {
		return nil, err
	}

	// FIXME:  Don't make these here since it's wasteful, init this in main.go and inject it into the webhook server
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)

	if err != nil {
		return nil, err
	}

	var targetValues map[string]interface{}

	if application.Spec.Source.Helm.Values != "" {
		if err := yaml.Unmarshal([]byte(application.Spec.Source.Helm.Values), &targetValues); err != nil {
			return nil, err
		}
	}

	for _, ref := range valueRefs.ValuesFrom {
		// Right now we only support ConfigMaps, however the nil check allows support for Secrets to be added in the future
		if ref.ConfigMapKeyRef == nil {
			continue
		}

		cm, err := clientset.CoreV1().ConfigMaps("default").Get(context.TODO(), ref.ConfigMapKeyRef.Name, metav1.GetOptions{})

		if err != nil {
			if errors.IsNotFound(err) {
				if ref.ConfigMapKeyRef.Optional {
					continue
				}

				return nil, fmt.Errorf("missing required configmap %s", ref.ConfigMapKeyRef.Name)
			}
		}

		configmapKey := ref.ConfigMapKeyRef.Key

		if configmapKey == "" {
			configmapKey = "values.yaml"
		}

		valuesSource, ok := cm.Data[configmapKey]

		if !ok {
			if ref.ConfigMapKeyRef.Optional {
				continue
			}

			return nil, fmt.Errorf("missing required key (%s) in configmap %s", configmapKey, ref.ConfigMapKeyRef.Name)
		}

		var values map[string]interface{}

		if err := yaml.Unmarshal([]byte(valuesSource), &values); err != nil {
			return nil, err
		}

		if err := mergo.Merge(&targetValues, &values, mergo.WithOverride); err != nil {
			return nil, err
		}
	}

	targetValuesBytes, err := yaml.Marshal(targetValues)

	if err != nil {
		return nil, err
	}

	modifiedApplication.Spec.Source.Helm.Values = string(targetValuesBytes)

	sourceApplicationBytes, err := json.Marshal(&application)

	if err != nil {
		return nil, err
	}

	targetApplicationBytes, err := json.Marshal(&modifiedApplication)

	if err != nil {
		return nil, err
	}

	return jsonpatch.CreatePatch(sourceApplicationBytes, targetApplicationBytes)
}

// main mutation process
func (whsvr *WebhookServer) mutate(ar *v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
	req := ar.Request
	var application applicationv1alpha1.Application

	if err := json.Unmarshal(req.Object.Raw, &application); err != nil {
		glog.Errorf("Could not unmarshal raw object: %v", err)
		return &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	glog.Infof("AdmissionReview for Kind=%v, Namespace=%v Name=%v (%v) UID=%v patchOperation=%v UserInfo=%v",
		req.Kind, req.Namespace, req.Name, application.ObjectMeta.Name, req.UID, req.Operation, req.UserInfo)

	// determine whether to perform mutation
	if !mutationRequired(ignoredNamespaces, &application) {
		glog.Infof("Skipping mutation for %s/%s due to policy check", application.ObjectMeta.Namespace, application.ObjectMeta.Name)
		return &v1beta1.AdmissionResponse{
			Allowed: true,
		}
	}

	patches, err := createPatch(&application)

	if err != nil {
		return &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	if len(patches) == 0 {
		glog.Infof("No patches required for %s/%s", application.ObjectMeta.Namespace, application.ObjectMeta.Name)
		return &v1beta1.AdmissionResponse{
			Allowed: true,
		}
	}

	patchBytes, err := json.Marshal(&patches)

	if err != nil {
		return &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	glog.Infof("AdmissionResponse: patch=%v\n", string(patchBytes))
	return &v1beta1.AdmissionResponse{
		Allowed: true,
		Patch:   patchBytes,
		PatchType: func() *v1beta1.PatchType {
			pt := v1beta1.PatchTypeJSONPatch
			return &pt
		}(),
	}
}

// Serve method for webhook server
func (whsvr *WebhookServer) serve(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		glog.Error("empty body")
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		glog.Errorf("Content-Type=%s, expect application/json", contentType)
		http.Error(w, "invalid Content-Type, expect `application/json`", http.StatusUnsupportedMediaType)
		return
	}

	var admissionResponse *v1beta1.AdmissionResponse
	ar := v1beta1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, &ar); err != nil {
		glog.Errorf("Can't decode body: %v", err)
		admissionResponse = &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	} else {
		admissionResponse = whsvr.mutate(&ar)
	}

	admissionReview := v1beta1.AdmissionReview{}
	if admissionResponse != nil {
		admissionReview.Response = admissionResponse
		if ar.Request != nil {
			admissionReview.Response.UID = ar.Request.UID
		}
	}

	resp, err := json.Marshal(admissionReview)
	if err != nil {
		glog.Errorf("Can't encode response: %v", err)
		http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
	}
	glog.Infof("Ready to write reponse ...")
	if _, err := w.Write(resp); err != nil {
		glog.Errorf("Can't write response: %v", err)
		http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
	}
}
