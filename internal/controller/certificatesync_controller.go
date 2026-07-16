package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	awsacm "github.com/NicolasEspiau-stilll/acm-cmcertificate-sync/internal/services"
)

const (
	// certificateFinalizer blocks Certificate deletion until the ACM copy is removed.
	certificateFinalizer = "acm-cmcertificate-sync.stilll.fr/finalizer"
	// annotationARN tracks the ACM certificate this Certificate is synced to.
	annotationARN = "acm-cmcertificate-sync.stilll.fr/certificate-arn"
	// annotationHash stores a digest of the last imported certificate, so
	// unchanged certificates are not re-imported on every reconcile.
	annotationHash = "acm-cmcertificate-sync.stilll.fr/certificate-hash"

	// requeueDeleteInUse is how long to wait before retrying deletion of an
	// ACM certificate that is still attached to another AWS resource.
	requeueDeleteInUse = time.Minute
)

// ACMSyncer is the ACM surface the reconciler needs; *awsacm.AWSACMService
// implements it, tests provide a mock.
type ACMSyncer interface {
	ImportCertificate(ctx context.Context, req awsacm.ImportRequest) (string, error)
	DeleteCertificate(ctx context.Context, arn string) error
	FindCertificateByDomains(ctx context.Context, domains []string) (string, error)
}

// Config holds the controller filtering options.
type Config struct {
	// WatchedNamespaces limits reconciliation to these namespaces. Empty means all.
	WatchedNamespaces []string
	// DomainPatterns limits reconciliation to Certificates whose domains match
	// at least one pattern (filepath.Match syntax). Empty means all.
	DomainPatterns []string
}

// ConfigFromEnv reads the controller configuration from the environment
// variables set by the Helm chart (WATCHED_NAMESPACES, DOMAIN_PATTERNS).
func ConfigFromEnv() Config {
	return Config{
		WatchedNamespaces: parseListEnv(os.Getenv("WATCHED_NAMESPACES"), "all-namespaces"),
		DomainPatterns:    parseListEnv(os.Getenv("DOMAIN_PATTERNS"), "*"),
	}
}

// parseListEnv splits a comma-separated env value, trimming blanks. The
// allValue sentinel (and an empty value) both mean "no filtering" → nil.
func parseListEnv(value, allValue string) []string {
	value = strings.TrimSpace(value)
	if value == "" || value == allValue {
		return nil
	}
	var items []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			items = append(items, item)
		}
	}
	return items
}

type CertManagerCertificateReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
	ACM    ACMSyncer
	Config Config
}

// SetupWithManager sets up the controller with the Manager.
func (r *CertManagerCertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Events for Certificates we do not manage are dropped here. Certificates
	// carrying our finalizer always pass so cleanup keeps working even after a
	// configuration change narrows the filters.
	managedPredicate := predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return r.isManaged(e.Object)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			return r.isManaged(e.ObjectNew)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			// Actual cleanup happens through the finalizer (an update event);
			// by the time the delete event fires there is nothing left to do.
			return false
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return r.isManaged(e.Object)
		},
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&certmanagerv1.Certificate{}).
		WithEventFilter(managedPredicate).
		Complete(r)
}

// isManaged reports whether this controller is responsible for the object.
func (r *CertManagerCertificateReconciler) isManaged(obj client.Object) bool {
	cert, ok := obj.(*certmanagerv1.Certificate)
	if !ok {
		return false
	}
	if controllerutil.ContainsFinalizer(cert, certificateFinalizer) {
		return true
	}
	return r.namespaceMatches(cert.Namespace) && r.domainsMatch(certificateDomains(cert))
}

func (r *CertManagerCertificateReconciler) namespaceMatches(namespace string) bool {
	if len(r.Config.WatchedNamespaces) == 0 {
		return true
	}
	for _, watched := range r.Config.WatchedNamespaces {
		if watched == namespace {
			return true
		}
	}
	return false
}

// domainsMatch reports whether at least one domain matches one configured pattern.
func (r *CertManagerCertificateReconciler) domainsMatch(domains []string) bool {
	if len(r.Config.DomainPatterns) == 0 {
		return len(domains) > 0
	}
	for _, domain := range domains {
		for _, pattern := range r.Config.DomainPatterns {
			if matchDomainPattern(domain, pattern) {
				return true
			}
		}
	}
	return false
}

// matchDomainPattern checks a single domain against a wildcard pattern.
// filepath.Match semantics: "*" crosses dots, so "*.example.com" matches
// "a.example.com" and "a.b.example.com", but not the apex "example.com".
func matchDomainPattern(domain, pattern string) bool {
	matched, err := filepath.Match(pattern, domain)
	return err == nil && matched
}

// certificateDomains returns the full domain set of a Certificate: its
// DNS names plus the common name when it is not already listed.
func certificateDomains(cert *certmanagerv1.Certificate) []string {
	domains := make([]string, 0, len(cert.Spec.DNSNames)+1)
	domains = append(domains, cert.Spec.DNSNames...)
	if cn := cert.Spec.CommonName; cn != "" {
		found := false
		for _, domain := range domains {
			if domain == cn {
				found = true
				break
			}
		}
		if !found {
			domains = append(domains, cn)
		}
	}
	return domains
}

func (r *CertManagerCertificateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("certificate", req.NamespacedName)

	var certificate certmanagerv1.Certificate
	if err := r.Get(ctx, req.NamespacedName, &certificate); err != nil {
		if apierrors.IsNotFound(err) {
			// Already gone: ACM cleanup happened through the finalizer.
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get Certificate")
		return ctrl.Result{}, err
	}

	if !certificate.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, log, &certificate)
	}

	// Defense in depth: the event filter already checks this, but Reconcile can
	// be invoked outside the filtered path.
	if !r.isManaged(&certificate) {
		log.V(1).Info("Certificate does not match namespace/domain filters, ignoring")
		return ctrl.Result{}, nil
	}

	if !isCertificateReady(&certificate) {
		// A status update will trigger a new reconcile once the cert is issued.
		log.Info("Certificate is not ready yet, skipping")
		return ctrl.Result{}, nil
	}

	var secret corev1.Secret
	secretKey := client.ObjectKey{Namespace: certificate.Namespace, Name: certificate.Spec.SecretName}
	if err := r.Get(ctx, secretKey, &secret); err != nil {
		log.Error(err, "Failed to get Secret containing certificate data", "secret", secretKey)
		return ctrl.Result{}, err
	}

	certData, certExists := secret.Data[corev1.TLSCertKey]
	keyData, keyExists := secret.Data[corev1.TLSPrivateKeyKey]
	if !certExists || !keyExists || len(certData) == 0 || len(keyData) == 0 {
		// Not retryable until the secret changes, which will trigger a reconcile
		// of the Certificate through its status update.
		log.Info("Secret is missing tls.crt or tls.key, skipping", "secret", secretKey)
		return ctrl.Result{}, nil
	}

	// Skip when the exact same certificate was already imported.
	hash := hashCertificate(certData)
	arn := certificate.Annotations[annotationARN]
	if arn != "" && certificate.Annotations[annotationHash] == hash {
		return ctrl.Result{}, nil
	}

	// Take ownership before touching AWS so nothing leaks if we crash between
	// the import and the annotation update.
	if controllerutil.AddFinalizer(&certificate, certificateFinalizer) {
		if err := r.Update(ctx, &certificate); err != nil {
			log.Error(err, "Failed to add finalizer")
			return ctrl.Result{}, err
		}
	}

	leafPEM, chainPEM, err := awsacm.SplitCertificateAndChain(string(certData))
	if err != nil {
		log.Error(err, "Secret contains invalid certificate data", "secret", secretKey)
		return ctrl.Result{}, nil
	}

	// No ARN recorded yet: adopt an existing ACM certificate with the same
	// domain set if there is one, instead of creating a duplicate.
	if arn == "" {
		arn, err = r.ACM.FindCertificateByDomains(ctx, certificateDomains(&certificate))
		if err != nil {
			log.Error(err, "Failed to look up existing ACM certificate")
			return ctrl.Result{}, err
		}
		if arn != "" {
			log.Info("Adopting existing ACM certificate", "certificateArn", arn)
		}
	}

	importedARN, err := r.ACM.ImportCertificate(ctx, awsacm.ImportRequest{
		ARN:            arn,
		CertificatePEM: leafPEM,
		ChainPEM:       chainPEM,
		PrivateKeyPEM:  string(keyData),
		Tags: map[string]string{
			awsacm.ManagedByTagKey: awsacm.ManagedByTagValue,
			"KubernetesNamespace":  certificate.Namespace,
			"KubernetesName":       certificate.Name,
		},
	})
	if err != nil {
		log.Error(err, "Failed to import certificate into AWS ACM")
		// Returning the error gives us exponential backoff on retries.
		return ctrl.Result{}, err
	}

	patch := client.MergeFrom(certificate.DeepCopy())
	if certificate.Annotations == nil {
		certificate.Annotations = map[string]string{}
	}
	certificate.Annotations[annotationARN] = importedARN
	certificate.Annotations[annotationHash] = hash
	if err := r.Patch(ctx, &certificate, patch); err != nil {
		log.Error(err, "Failed to record ACM ARN on Certificate")
		return ctrl.Result{}, err
	}

	log.Info("Synced certificate to AWS ACM", "certificateArn", importedARN)
	return ctrl.Result{}, nil
}

// reconcileDelete removes the ACM copy of a Certificate being deleted, then
// releases the finalizer.
func (r *CertManagerCertificateReconciler) reconcileDelete(ctx context.Context, log logr.Logger, certificate *certmanagerv1.Certificate) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(certificate, certificateFinalizer) {
		// Nothing to clean up on our side. Stale finalizers from other (or
		// older) controllers can hold the object in Terminating forever, and
		// such objects otherwise look healthy in kubectl: say so out loud.
		if others := certificate.GetFinalizers(); len(others) > 0 {
			log.Info("Certificate is being deleted but is held by foreign finalizers, ignoring", "finalizers", others)
		}
		return ctrl.Result{}, nil
	}

	if arn := certificate.Annotations[annotationARN]; arn != "" {
		if err := r.ACM.DeleteCertificate(ctx, arn); err != nil {
			if awsacm.IsInUse(err) {
				// Still attached to an ALB/CloudFront/... — retry until the
				// user detaches it. The Certificate stays in Terminating.
				log.Info("ACM certificate still in use, retrying later", "certificateArn", arn)
				return ctrl.Result{RequeueAfter: requeueDeleteInUse}, nil
			}
			log.Error(err, "Failed to delete certificate from AWS ACM", "certificateArn", arn)
			return ctrl.Result{}, err
		}
	} else {
		log.Info("No ACM ARN recorded on Certificate, nothing to delete in ACM")
	}

	controllerutil.RemoveFinalizer(certificate, certificateFinalizer)
	if err := r.Update(ctx, certificate); err != nil {
		log.Error(err, "Failed to remove finalizer")
		return ctrl.Result{}, err
	}
	log.Info("Finalizer removed, Certificate deletion can complete")
	return ctrl.Result{}, nil
}

func isCertificateReady(cert *certmanagerv1.Certificate) bool {
	for _, cond := range cert.Status.Conditions {
		if cond.Type == certmanagerv1.CertificateConditionReady {
			return cond.Status == cmmeta.ConditionTrue
		}
	}
	return false
}

// hashCertificate returns a stable digest of the certificate material used to
// detect renewals.
func hashCertificate(certData []byte) string {
	sum := sha256.Sum256(certData)
	return fmt.Sprintf("sha256:%s", hex.EncodeToString(sum[:]))
}
