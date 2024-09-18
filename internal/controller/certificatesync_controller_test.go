package controller

import (
	"context"
	"os"
	"testing"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestMain(m *testing.M) {
	testEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{
			"testdata/crds", // Path to dynamically downloaded CRDs
		},
	}

	cfg, err := testEnv.Start()
	if err != nil {
		panic(err)
	}

	// Add Cert Manager's scheme
	err = certmanagerv1.AddToScheme(scheme.Scheme)
	if err != nil {
		panic(err)
	}

	// Create a Kubernetes client for tests
	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	if err != nil {
		panic(err)
	}

	// Run the tests
	code := m.Run()

	// Tear down the test environment after tests
	err = testEnv.Stop()
	if err != nil {
		panic(err)
	}

	// Exit with the test run result code
	os.Exit(code)
}

func TestCertManagerCertificateReconciler_Reconcile(t *testing.T) {
	os.Setenv("WATCHED_NAMESPACES", "default")
	os.Setenv("DOMAIN_PATTERNS", "*.example.com")
	// Create the reconciler
	reconciler := &CertManagerCertificateReconciler{
		Client: k8sClient,
		Log:    zap.New(zap.UseDevMode(true)),
	}

	// Setup: Create a test Certificate resource and Secret
	certificate := &certmanagerv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cert",
			Namespace: "default",
		},
		Spec: certmanagerv1.CertificateSpec{
			SecretName: "test-secret",
			DNSNames:   []string{"example.com"},
		},
		Status: certmanagerv1.CertificateStatus{
			Conditions: []certmanagerv1.CertificateCondition{
				{
					Type:   certmanagerv1.CertificateConditionReady,
					Status: "True",
				},
			},
		},
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"tls.crt":   []byte("fake-cert-data"),
			"tls.key":   []byte("fake-key-data"),
			"tls.chain": []byte("fake-chain-data"),
		},
	}

	err := k8sClient.Create(context.TODO(), certificate)
	assert.NoError(t, err)

	err = k8sClient.Create(context.TODO(), secret)
	assert.NoError(t, err)

	// Reconcile request for the certificate
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-cert",
			Namespace: "default",
		},
	}

	res, err := reconciler.Reconcile(context.TODO(), req)
	assert.NoError(t, err)
	assert.False(t, res.Requeue)

	// Assert that the certificate was processed correctly
}

func TestCertManagerCertificateReconciler_CertificateNotReady(t *testing.T) {
	// Test for when the certificate is not ready
	certificate := &certmanagerv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "not-ready-cert",
			Namespace: "default",
		},
		Spec: certmanagerv1.CertificateSpec{
			SecretName: "not-ready-secret",
			DNSNames:   []string{"example.com"},
		},
		Status: certmanagerv1.CertificateStatus{
			Conditions: []certmanagerv1.CertificateCondition{
				{
					Type:   certmanagerv1.CertificateConditionReady,
					Status: "False", // Not ready
				},
			},
		},
	}

	err := k8sClient.Create(context.TODO(), certificate)
	assert.NoError(t, err)

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "not-ready-cert",
			Namespace: "default",
		},
	}

	reconciler := &CertManagerCertificateReconciler{
		Client: k8sClient,
		Log:    zap.New(zap.UseDevMode(true)),
	}

	res, err := reconciler.Reconcile(context.TODO(), req)
	assert.NoError(t, err)
	assert.False(t, res.Requeue)

	// Assert that the certificate was skipped because it's not ready
}
