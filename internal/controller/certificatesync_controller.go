package controller

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	services "github.com/NicolasEspiau-stilll/acm-cmcertificate-sync.git/internal/services"
)

type CertManagerCertificateReconciler struct {
	client.Client
	Log           logr.Logger
	Scheme        *runtime.Scheme
	AWSACMService services.AWSACMServiceInterface
}

// SetupWithManager sets up the controller with the Manager.
func (r *CertManagerCertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Fetch namespaces and domain patterns from environment variables
	watchedNamespaces := os.Getenv("WATCHED_NAMESPACES")
	domainPatterns := strings.Split(os.Getenv("DOMAIN_PATTERNS"), ",")

	// Create a predicate to filter by namespace
	namespacePredicate := predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return r.namespaceFilter(e.Object.GetNamespace(), watchedNamespaces)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			return r.namespaceFilter(e.ObjectNew.GetNamespace(), watchedNamespaces)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return r.namespaceFilter(e.Object.GetNamespace(), watchedNamespaces)
		},
	}

	// Create a predicate to filter by domain patterns
	domainPredicate := predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			cert := e.Object.(*certmanagerv1.Certificate)
			return r.domainPatternFilter(cert.Spec.DNSNames, domainPatterns)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			cert := e.ObjectNew.(*certmanagerv1.Certificate)
			return r.domainPatternFilter(cert.Spec.DNSNames, domainPatterns)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			cert := e.Object.(*certmanagerv1.Certificate)
			return r.domainPatternFilter(cert.Spec.DNSNames, domainPatterns)
		},
	}

	// Combine both predicates: namespace and domain pattern
	combinedPredicate := predicate.And(namespacePredicate, domainPredicate)

	return ctrl.NewControllerManagedBy(mgr).
		For(&certmanagerv1.Certificate{}).
		WithEventFilter(combinedPredicate). // Apply the combined filter
		Complete(r)
}

// Helper method to filter namespaces
func (r *CertManagerCertificateReconciler) namespaceFilter(namespace, watchedNamespaces string) bool {
	if watchedNamespaces == "" || watchedNamespaces == "all-namespaces" {
		return true
	}
	namespaces := strings.Split(watchedNamespaces, ",")
	for _, ns := range namespaces {
		if ns == namespace {
			return true
		}
	}
	return false
}

// Helper method to filter by domain patterns
func (r *CertManagerCertificateReconciler) domainPatternFilter(dnsNames []string, patterns []string) bool {
	for _, dnsName := range dnsNames {
		for _, pattern := range patterns {
			if matchDomainPattern(dnsName, pattern) {
				return true
			}
		}
	}
	return false
}

// Helper function to check if a domain matches the pattern
func matchDomainPattern(domain, pattern string) bool {
	// Implement pattern matching (wildcards, etc.) as necessary
	matched, _ := filepath.Match(pattern, domain)
	return matched
}

func (r *CertManagerCertificateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("certificate", req.NamespacedName)

	// Fetch the Certificate resource from Cert Manager
	var certificate certmanagerv1.Certificate
	if err := r.Get(ctx, req.NamespacedName, &certificate); err != nil {
		if errors.IsNotFound(err) {
			log.Info("Certificate resource not found in cluster. Deleting from AWS Certificate Manager.")
			// Loop over the DNS names in the certificate and delete the certificate for each domain
			for _, dnsName := range certificate.Spec.DNSNames {
				err := r.AWSACMService.DeleteCertificateByCommonName(dnsName)
				if err != nil {
					log.Error(err, "Failed to delete certificate from AWS ACM")
					return ctrl.Result{}, err
				}
				log.Info("Successfully deleted certificate from AWS ACM for domain", "domain", dnsName)
			}

			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get Certificate")
		return ctrl.Result{}, err
	}

	// Check if the certificate is marked for deletion
	if certificate.GetDeletionTimestamp() != nil {
		log.Info("Certificate is marked for deletion. Deleting from AWS Certificate Manager.")
		// Loop over the DNS names in the certificate and delete the certificate for each domain
		for _, dnsName := range certificate.Spec.DNSNames {
			err := r.AWSACMService.DeleteCertificateByCommonName(dnsName)
			if err != nil {
				log.Error(err, "Failed to delete certificate from AWS ACM")
				return ctrl.Result{}, err
			}
			log.Info("Successfully deleted certificate from AWS ACM for domain", "domain", dnsName)
		}

		// Remove the finalizer after cleanup
		if err := r.removeFinalizer(&certificate); err != nil {
			return reconcile.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// Add the finalizer if it doesn't exist
	if err := r.addFinalizer(&certificate); err != nil {
		return reconcile.Result{}, err
	}

	// Check if the certificate is ready by looking at its conditions
	isReady := false
	for _, cond := range certificate.Status.Conditions {
		if cond.Type == certmanagerv1.CertificateConditionReady && cond.Status == "True" {
			log.Info("Certificate is ready, proceeding with reconciliation.")
			isReady = true
			break
		}
	}

	if !isReady {
		log.Info("Certificate is not ready yet, skipping reconciliation.")
		return ctrl.Result{}, nil
	}

	// Fetch the secret that contains the certificate
	secretName := certificate.Spec.SecretName
	var secret corev1.Secret
	if err := r.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: secretName}, &secret); err != nil {
		log.Error(err, "Failed to get Secret containing certificate data")
		return ctrl.Result{}, err
	}

	// Extract the certificate, private key, and certificate chain from the secret
	certData, certExists := secret.Data["tls.crt"]
	keyData, keyExists := secret.Data["tls.key"]

	if !certExists || !keyExists {
		log.Error(fmt.Errorf("secret data missing required fields"), "Secret does not contain required certificate data")
		return ctrl.Result{}, nil
	}

	// Import the certificate into AWS ACM
	// Loop over the DNS names in the certificate and import the certificate for each domain
	for _, dnsName := range certificate.Spec.DNSNames {
		if err := r.AWSACMService.ImportOrUpdateCertificate(dnsName, string(certData), string(keyData)); err != nil {
			log.Error(err, "Failed to import certificate to AWS ACM")
			return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
		}
	}

	log.Info("Successfully imported certificate to AWS ACM")
	return ctrl.Result{}, nil
}

const certificateFinalizer = "acm-cmcertificate-sync/finalizer"

// Add the finalizer to the certificate if it doesn't exist
func (r *CertManagerCertificateReconciler) addFinalizer(cert *certmanagerv1.Certificate) error {
	if !containsString(cert.GetFinalizers(), certificateFinalizer) {
		cert.SetFinalizers(append(cert.GetFinalizers(), certificateFinalizer))
		if err := r.Update(context.TODO(), cert); err != nil {
			return err
		}
	}
	return nil
}

// Remove the finalizer from the certificate
func (r *CertManagerCertificateReconciler) removeFinalizer(cert *certmanagerv1.Certificate) error {
	if containsString(cert.GetFinalizers(), certificateFinalizer) {
		cert.SetFinalizers(removeString(cert.GetFinalizers(), certificateFinalizer))
		if err := r.Update(context.TODO(), cert); err != nil {
			return err
		}
	}
	return nil
}

// Helper functions for handling finalizers
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func removeString(slice []string, s string) []string {
	var result []string
	for _, item := range slice {
		if item != s {
			result = append(result, item)
		}
	}
	return result
}
