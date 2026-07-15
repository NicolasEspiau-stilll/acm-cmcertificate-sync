package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/go-logr/logr"

	awsacm "github.com/NicolasEspiau-stilll/acm-cmcertificate-sync/internal/services"
)

// fakeACM records the calls the reconciler makes to AWS.
type fakeACM struct {
	importCalls []awsacm.ImportRequest
	importARN   string
	importErr   error

	deleteCalls []string
	deleteErr   error

	findCalls  [][]string
	findResult string
	findErr    error
}

func (f *fakeACM) ImportCertificate(_ context.Context, req awsacm.ImportRequest) (string, error) {
	f.importCalls = append(f.importCalls, req)
	if f.importErr != nil {
		return "", f.importErr
	}
	if req.ARN != "" {
		return req.ARN, nil
	}
	return f.importARN, nil
}

func (f *fakeACM) DeleteCertificate(_ context.Context, arn string) error {
	f.deleteCalls = append(f.deleteCalls, arn)
	return f.deleteErr
}

func (f *fakeACM) FindCertificateByDomains(_ context.Context, domains []string) (string, error) {
	f.findCalls = append(f.findCalls, domains)
	return f.findResult, f.findErr
}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, certmanagerv1.AddToScheme(scheme))
	return scheme
}

func newReconciler(t *testing.T, acm *fakeACM, cfg Config, objs ...client.Object) (*CertManagerCertificateReconciler, client.Client) {
	t.Helper()
	k8sClient := fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithObjects(objs...).
		Build()
	return &CertManagerCertificateReconciler{
		Client: k8sClient,
		Log:    logr.Discard(),
		ACM:    acm,
		Config: cfg,
	}, k8sClient
}

// generateLeafPEM builds a self-signed certificate for the given domains.
func generateLeafPEM(t *testing.T, serial int64, dnsNames ...string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func readyCertificate(name string, dnsNames ...string) *certmanagerv1.Certificate {
	return &certmanagerv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Spec: certmanagerv1.CertificateSpec{
			SecretName: name + "-tls",
			DNSNames:   dnsNames,
		},
		Status: certmanagerv1.CertificateStatus{
			Conditions: []certmanagerv1.CertificateCondition{
				{Type: certmanagerv1.CertificateConditionReady, Status: cmmeta.ConditionTrue},
			},
		},
	}
}

func tlsSecret(name, certPEM, keyPEM string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Data: map[string][]byte{
			corev1.TLSCertKey:       []byte(certPEM),
			corev1.TLSPrivateKeyKey: []byte(keyPEM),
		},
	}
}

func requestFor(cert *certmanagerv1.Certificate) reconcile.Request {
	return reconcile.Request{
		NamespacedName: types.NamespacedName{Namespace: cert.Namespace, Name: cert.Name},
	}
}

func TestReconcile_ImportsOnceForMultipleDNSNames(t *testing.T) {
	certPEM := generateLeafPEM(t, 1, "example.com", "www.example.com", "api.example.com")
	cert := readyCertificate("multi", "example.com", "www.example.com", "api.example.com")
	secret := tlsSecret("multi-tls", certPEM, "KEY")

	acm := &fakeACM{importARN: "arn:aws:acm:eu-west-3:123:certificate/abc"}
	r, k8sClient := newReconciler(t, acm, Config{}, cert, secret)

	res, err := r.Reconcile(log.IntoContext(context.Background(), logr.Discard()), requestFor(cert))
	require.NoError(t, err)
	assert.Zero(t, res.RequeueAfter)

	// One ACM certificate per k8s Certificate, never one per DNS name.
	require.Len(t, acm.importCalls, 1)
	assert.Empty(t, acm.importCalls[0].ARN)
	assert.Equal(t, certPEM, acm.importCalls[0].CertificatePEM)
	assert.Equal(t, "KEY", acm.importCalls[0].PrivateKeyPEM)
	assert.Equal(t, awsacm.ManagedByTagValue, acm.importCalls[0].Tags[awsacm.ManagedByTagKey])

	var updated certmanagerv1.Certificate
	require.NoError(t, k8sClient.Get(context.Background(), requestFor(cert).NamespacedName, &updated))
	assert.Equal(t, "arn:aws:acm:eu-west-3:123:certificate/abc", updated.Annotations[annotationARN])
	assert.Equal(t, hashCertificate([]byte(certPEM)), updated.Annotations[annotationHash])
	assert.Contains(t, updated.Finalizers, certificateFinalizer)
}

func TestReconcile_SkipsWhenCertificateUnchanged(t *testing.T) {
	certPEM := generateLeafPEM(t, 1, "example.com")
	cert := readyCertificate("stable", "example.com")
	cert.Annotations = map[string]string{
		annotationARN:  "arn:existing",
		annotationHash: hashCertificate([]byte(certPEM)),
	}
	cert.Finalizers = []string{certificateFinalizer}
	secret := tlsSecret("stable-tls", certPEM, "KEY")

	acm := &fakeACM{}
	r, _ := newReconciler(t, acm, Config{}, cert, secret)

	_, err := r.Reconcile(context.Background(), requestFor(cert))
	require.NoError(t, err)
	assert.Empty(t, acm.importCalls, "an unchanged certificate must not be re-imported")
	assert.Empty(t, acm.findCalls)
}

func TestReconcile_RenewalReimportsOnSameARN(t *testing.T) {
	oldPEM := generateLeafPEM(t, 1, "example.com")
	newPEM := generateLeafPEM(t, 2, "example.com")
	cert := readyCertificate("renewed", "example.com")
	cert.Annotations = map[string]string{
		annotationARN:  "arn:existing",
		annotationHash: hashCertificate([]byte(oldPEM)),
	}
	cert.Finalizers = []string{certificateFinalizer}
	secret := tlsSecret("renewed-tls", newPEM, "KEY")

	acm := &fakeACM{}
	r, k8sClient := newReconciler(t, acm, Config{}, cert, secret)

	_, err := r.Reconcile(context.Background(), requestFor(cert))
	require.NoError(t, err)

	require.Len(t, acm.importCalls, 1)
	assert.Equal(t, "arn:existing", acm.importCalls[0].ARN, "renewal must re-import onto the same ARN")
	assert.Empty(t, acm.findCalls, "no adoption lookup needed when the ARN is already known")

	var updated certmanagerv1.Certificate
	require.NoError(t, k8sClient.Get(context.Background(), requestFor(cert).NamespacedName, &updated))
	assert.Equal(t, hashCertificate([]byte(newPEM)), updated.Annotations[annotationHash])
}

func TestReconcile_AdoptsExistingACMCertificate(t *testing.T) {
	certPEM := generateLeafPEM(t, 1, "example.com")
	cert := readyCertificate("adopted", "example.com")
	secret := tlsSecret("adopted-tls", certPEM, "KEY")

	acm := &fakeACM{findResult: "arn:pre-existing"}
	r, k8sClient := newReconciler(t, acm, Config{}, cert, secret)

	_, err := r.Reconcile(context.Background(), requestFor(cert))
	require.NoError(t, err)

	require.Len(t, acm.findCalls, 1)
	assert.Equal(t, []string{"example.com"}, acm.findCalls[0])
	require.Len(t, acm.importCalls, 1)
	assert.Equal(t, "arn:pre-existing", acm.importCalls[0].ARN, "must reuse the found certificate instead of duplicating it")

	var updated certmanagerv1.Certificate
	require.NoError(t, k8sClient.Get(context.Background(), requestFor(cert).NamespacedName, &updated))
	assert.Equal(t, "arn:pre-existing", updated.Annotations[annotationARN])
}

func TestReconcile_NotReadyCertificateIsSkipped(t *testing.T) {
	cert := readyCertificate("pending", "example.com")
	cert.Status.Conditions[0].Status = cmmeta.ConditionFalse

	acm := &fakeACM{}
	r, _ := newReconciler(t, acm, Config{}, cert)

	_, err := r.Reconcile(context.Background(), requestFor(cert))
	require.NoError(t, err)
	assert.Empty(t, acm.importCalls)
}

func TestReconcile_SecretMissingKeyIsSkipped(t *testing.T) {
	cert := readyCertificate("broken", "example.com")
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "broken-tls", Namespace: "default"},
		Data:       map[string][]byte{corev1.TLSCertKey: []byte("cert-without-key")},
	}

	acm := &fakeACM{}
	r, _ := newReconciler(t, acm, Config{}, cert, secret)

	_, err := r.Reconcile(context.Background(), requestFor(cert))
	require.NoError(t, err, "an incomplete secret is not retryable, it must not error")
	assert.Empty(t, acm.importCalls)
}

func TestReconcile_ImportErrorIsReturnedForBackoff(t *testing.T) {
	certPEM := generateLeafPEM(t, 1, "example.com")
	cert := readyCertificate("failing", "example.com")
	secret := tlsSecret("failing-tls", certPEM, "KEY")

	acm := &fakeACM{importErr: fmt.Errorf("throttled")}
	r, _ := newReconciler(t, acm, Config{}, cert, secret)

	_, err := r.Reconcile(context.Background(), requestFor(cert))
	assert.Error(t, err, "AWS failures must surface as errors to get exponential backoff")
}

func TestReconcile_DeleteRemovesACMCertificateAndFinalizer(t *testing.T) {
	now := metav1.Now()
	cert := readyCertificate("doomed", "example.com")
	cert.DeletionTimestamp = &now
	cert.Finalizers = []string{certificateFinalizer}
	cert.Annotations = map[string]string{annotationARN: "arn:doomed"}

	acm := &fakeACM{}
	r, k8sClient := newReconciler(t, acm, Config{}, cert)

	_, err := r.Reconcile(context.Background(), requestFor(cert))
	require.NoError(t, err)
	assert.Equal(t, []string{"arn:doomed"}, acm.deleteCalls)

	// With the finalizer gone the fake client completes the deletion.
	var gone certmanagerv1.Certificate
	err = k8sClient.Get(context.Background(), requestFor(cert).NamespacedName, &gone)
	assert.True(t, apierrors.IsNotFound(err), "certificate must be fully deleted once the finalizer is released")
}

func TestReconcile_DeleteInUseRequeuesAndKeepsFinalizer(t *testing.T) {
	now := metav1.Now()
	cert := readyCertificate("attached", "example.com")
	cert.DeletionTimestamp = &now
	cert.Finalizers = []string{certificateFinalizer}
	cert.Annotations = map[string]string{annotationARN: "arn:attached"}

	acm := &fakeACM{
		deleteErr: fmt.Errorf("wrapped: %w", &acmtypes.ResourceInUseException{}),
	}
	r, k8sClient := newReconciler(t, acm, Config{}, cert)

	res, err := r.Reconcile(context.Background(), requestFor(cert))
	require.NoError(t, err)
	assert.Equal(t, requeueDeleteInUse, res.RequeueAfter)

	var still certmanagerv1.Certificate
	require.NoError(t, k8sClient.Get(context.Background(), requestFor(cert).NamespacedName, &still))
	assert.Contains(t, still.Finalizers, certificateFinalizer, "finalizer must stay until ACM deletion succeeds")
}

func TestReconcile_DeleteWithoutARNJustReleasesFinalizer(t *testing.T) {
	now := metav1.Now()
	cert := readyCertificate("untracked", "example.com")
	cert.DeletionTimestamp = &now
	cert.Finalizers = []string{certificateFinalizer}

	acm := &fakeACM{}
	r, k8sClient := newReconciler(t, acm, Config{}, cert)

	_, err := r.Reconcile(context.Background(), requestFor(cert))
	require.NoError(t, err)
	assert.Empty(t, acm.deleteCalls, "without a recorded ARN nothing must be deleted in ACM")

	var gone certmanagerv1.Certificate
	err = k8sClient.Get(context.Background(), requestFor(cert).NamespacedName, &gone)
	assert.True(t, apierrors.IsNotFound(err))
}

func TestReconcile_UnmanagedCertificateIsIgnored(t *testing.T) {
	cert := readyCertificate("elsewhere", "example.org")

	acm := &fakeACM{}
	r, _ := newReconciler(t, acm, Config{DomainPatterns: []string{"*.example.com"}}, cert)

	_, err := r.Reconcile(context.Background(), requestFor(cert))
	require.NoError(t, err)
	assert.Empty(t, acm.importCalls)
	assert.Empty(t, acm.findCalls)
}

func TestIsManaged(t *testing.T) {
	r := &CertManagerCertificateReconciler{
		Config: Config{
			WatchedNamespaces: []string{"prod"},
			DomainPatterns:    []string{"*.example.com"},
		},
	}

	matching := readyCertificate("ok", "app.example.com")
	matching.Namespace = "prod"
	assert.True(t, r.isManaged(matching))

	wrongNamespace := readyCertificate("wrong-ns", "app.example.com")
	wrongNamespace.Namespace = "staging"
	assert.False(t, r.isManaged(wrongNamespace))

	wrongDomain := readyCertificate("wrong-domain", "app.example.org")
	wrongDomain.Namespace = "prod"
	assert.False(t, r.isManaged(wrongDomain))

	// A certificate we already own must keep being reconciled even when the
	// filters no longer match, otherwise its finalizer would deadlock deletion.
	owned := readyCertificate("owned", "app.example.org")
	owned.Namespace = "staging"
	owned.Finalizers = []string{certificateFinalizer}
	assert.True(t, r.isManaged(owned))

	assert.False(t, r.isManaged(&corev1.Secret{}), "non-Certificate objects are never managed")
}

func TestMatchDomainPattern(t *testing.T) {
	assert.True(t, matchDomainPattern("a.example.com", "*.example.com"))
	assert.True(t, matchDomainPattern("example.com", "example.com"))
	assert.True(t, matchDomainPattern("a.b.example.com", "*.example.com"), "* crosses dots, all subdomain levels match")
	assert.False(t, matchDomainPattern("example.com", "*.example.com"), "the apex domain needs its own pattern")
	assert.False(t, matchDomainPattern("aexample.com", ".example.com"))
}

func TestCertificateDomains(t *testing.T) {
	cert := readyCertificate("cn", "www.example.com")
	cert.Spec.CommonName = "example.com"
	assert.ElementsMatch(t, []string{"www.example.com", "example.com"}, certificateDomains(cert))

	cert.Spec.CommonName = "www.example.com"
	assert.ElementsMatch(t, []string{"www.example.com"}, certificateDomains(cert), "common name already in DNS names must not duplicate")
}

func TestParseListEnv(t *testing.T) {
	assert.Nil(t, parseListEnv("", "all-namespaces"))
	assert.Nil(t, parseListEnv("all-namespaces", "all-namespaces"))
	assert.Nil(t, parseListEnv("*", "*"))
	assert.Equal(t, []string{"a", "b"}, parseListEnv(" a , b ,", "all-namespaces"))
}
