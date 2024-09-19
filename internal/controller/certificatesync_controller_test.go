package controller

import (
	"context"
	"os"
	"testing"

	services "github.com/NicolasEspiau-stilll/acm-cmcertificate-sync.git/internal/services"

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

var (
	validcertname        = "test-cert"
	validcertnamespace   = "default"
	validsecretname      = "test-secret"
	validsecretnamespace = "default"
	validcertificate     = &certmanagerv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      validcertname,
			Namespace: validcertnamespace,
		},
		Spec: certmanagerv1.CertificateSpec{
			SecretName: validsecretname,
			DNSNames:   []string{"example.com"},
		},
	}
	validsecret = &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      validsecretname,
			Namespace: validsecretnamespace,
		},
		Data: map[string][]byte{
			"tls.crt":   []byte("fake-cert-data"),
			"tls.key":   []byte("fake-key-data"),
			"tls.chain": []byte("fake-chain-data"),
		},
	}

	certnotreadyname        = "test-cert-not-ready"
	certnotreadynamespace   = "default"
	secretnotreadyname      = "secret-not-ready"
	secretnotreadynamespace = "default"
	certificatenotready     = &certmanagerv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      certnotreadyname,
			Namespace: certnotreadynamespace,
		},
		Spec: certmanagerv1.CertificateSpec{
			SecretName: secretnotreadyname,
			DNSNames:   []string{"example.com"},
		},
	}
	secretnotready = &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretnotreadyname,
			Namespace: secretnotreadynamespace,
		},
		Data: map[string][]byte{
			"tls.crt":   []byte("fake-cert-data"),
			"tls.key":   []byte("fake-key-data"),
			"tls.chain": []byte("fake-chain-data"),
		},
	}
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

	os.Setenv("WATCHED_NAMESPACES", "default")
	os.Setenv("DOMAIN_PATTERNS", "*.example.com")

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
	err := k8sClient.Create(context.TODO(), validcertificate)
	assert.NoError(t, err)

	// Update the status of the Certificate resource
	validcertificate.Status = certmanagerv1.CertificateStatus{
		Conditions: []certmanagerv1.CertificateCondition{
			{
				Type:   certmanagerv1.CertificateConditionReady,
				Status: "True",
			},
		},
	}

	err = k8sClient.Status().Update(context.TODO(), validcertificate)
	assert.NoError(t, err)

	err = k8sClient.Create(context.TODO(), validsecret)
	assert.NoError(t, err)

	// Instantiate the AWSACMServiceMock
	awsACMServiceMock := new(services.AWSACMServiceMock)
	awsACMServiceMock.On("ImportOrUpdateCertificate", "example.com", "fake-cert-data", "fake-key-data").Return(nil)

	// Create the reconciler
	reconciler := &CertManagerCertificateReconciler{
		AWSACMService: awsACMServiceMock,
		Client:        k8sClient,
		Log:           zap.New(zap.UseDevMode(true)),
	}

	// Reconcile request for the certificate
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      validcertname,
			Namespace: validcertnamespace,
		},
	}

	res, err := reconciler.Reconcile(context.TODO(), req)
	assert.NoError(t, err)
	assert.False(t, res.Requeue)

	// Assert that the certificate was processed correctly
	awsACMServiceMock.AssertCalled(t, "ImportOrUpdateCertificate", "example.com", "fake-cert-data", "fake-key-data")
	awsACMServiceMock.AssertExpectations(t)
}

func TestCertManagerCertificateReconciler_CertificateNotReady(t *testing.T) {
	err := k8sClient.Create(context.TODO(), certificatenotready)
	assert.NoError(t, err)

	// Update the status of the Certificate resource
	certificatenotready.Status = certmanagerv1.CertificateStatus{
		Conditions: []certmanagerv1.CertificateCondition{
			{
				Type:   certmanagerv1.CertificateConditionReady,
				Status: "False",
			},
		},
	}

	err = k8sClient.Status().Update(context.TODO(), certificatenotready)
	assert.NoError(t, err)

	err = k8sClient.Create(context.TODO(), secretnotready)
	assert.NoError(t, err)

	// Instantiate the AWSACMServiceMock
	awsACMServiceMock := new(services.AWSACMServiceMock)

	// Create the reconciler
	reconciler := &CertManagerCertificateReconciler{
		AWSACMService: awsACMServiceMock,
		Client:        k8sClient,
		Log:           zap.New(zap.UseDevMode(true)),
	}

	// Reconcile request for the certificate
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      certnotreadyname,
			Namespace: certnotreadynamespace,
		},
	}

	res, err := reconciler.Reconcile(context.TODO(), req)
	assert.NoError(t, err)
	assert.False(t, res.Requeue)

	// Assert that the certificate wasn't processed
	awsACMServiceMock.AssertNotCalled(t, "ImportOrUpdateCertificate")
	awsACMServiceMock.AssertExpectations(t)
}

func TestCertManagerCertificateReconciler_CertificateDeleted(t *testing.T) {
	err := k8sClient.Delete(context.TODO(), validcertificate)
	assert.NoError(t, err)

	// Instantiate the AWSACMServiceMock
	awsACMServiceMock := new(services.AWSACMServiceMock)
	awsACMServiceMock.On("DeleteCertificateByCommonName", "example.com").Return(nil)

	// Create the reconciler
	reconciler := &CertManagerCertificateReconciler{
		AWSACMService: awsACMServiceMock,
		Client:        k8sClient,
		Log:           zap.New(zap.UseDevMode(true)),
	}

	// Reconcile request for the certificate
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      validcertname,
			Namespace: validcertnamespace,
		},
	}

	res, err := reconciler.Reconcile(context.TODO(), req)
	assert.NoError(t, err)
	assert.False(t, res.Requeue)

	// Assert that the certificate was deleted
	awsACMServiceMock.AssertCalled(t, "DeleteCertificateByCommonName", "example.com")
	awsACMServiceMock.AssertExpectations(t)
}
