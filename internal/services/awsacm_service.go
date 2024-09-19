package services

import (
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/acm"
	"github.com/go-logr/logr"

	helpers "github.com/NicolasEspiau-stilll/acm-cmcertificate-sync.git/internal/helpers"
)

type AWSACMService struct {
	client *acm.ACM
	Log    logr.Logger
}

func NewAWSACMService(region string) (*AWSACMService, error) {
	// Initialize AWS session with the region from environment variable
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS session: %w", err)
	}

	client := acm.New(sess)

	return &AWSACMService{
		client: client,
		Log:    ctrl.Log.WithName("AWSACMService"),
	}, nil
}

// FindCertificateForDomain checks if a certificate exists for a given domain in ACM
func (svc *AWSACMService) FindCertificateForDomain(domain string) (*acm.CertificateSummary, error) {
	input := &acm.ListCertificatesInput{}
	result, err := svc.client.ListCertificates(input)
	if err != nil {
		svc.Log.Error(err, "failed to list certificates in ACM")
		return nil, err
	}

	// Loop through the certificates and find one that matches the domain
	for _, certSummary := range result.CertificateSummaryList {
		if aws.StringValue(certSummary.DomainName) == domain {
			return certSummary, nil
		}
	}
	return nil, nil
}

// Function to import or update a certificate in ACM
func (svc *AWSACMService) ImportOrUpdateCertificate(domain string, certData string, privateKey string) error {
	// Check if the certificate already exists in ACM
	certSummary, err := svc.FindCertificateForDomain(domain)
	if err != nil {
		svc.Log.Error(err, "failed to find certificate in ACM")
		return err
	}

	// Split the certificate into leaf certificate and certificate chain
	leafCert, certChain, err := helpers.SplitCertificateAndChain(certData)
	if err != nil {
		svc.Log.Error(err, "failed to split certificate and chain")
		return err
	}

	// If the certificate exists, update it
	if certSummary != nil {
		// Import the new certificate
		importInput := &acm.ImportCertificateInput{
			CertificateArn:   certSummary.CertificateArn,
			Certificate:      []byte(leafCert),
			CertificateChain: []byte(certChain),
			PrivateKey:       []byte(privateKey),
		}
		_, err := svc.client.ImportCertificate(importInput)
		if err != nil {
			svc.Log.Error(err, "failed to update ACM certificate")
			return err
		}
		fmt.Printf("Updated ACM certificate `%s` for domain: %s", *certSummary.CertificateArn, domain)
	} else {
		// If no certificate exists, import a new one
		importInput := &acm.ImportCertificateInput{
			Certificate:      []byte(leafCert),
			CertificateChain: []byte(certChain),
			PrivateKey:       []byte(privateKey),
		}
		_, err := svc.client.ImportCertificate(importInput)
		if err != nil {
			svc.Log.Error(err, "failed to import ACM certificate")
			return err
		}
		svc.Log.Info("Imported new ACM certificate for domain", "domain", domain)
	}

	return nil
}

// Function to delete a certificate from ACM by its domain
func (svc *AWSACMService) DeleteCertificateByCommonName(domain string) error {
	// Check if the certificate exists in ACM
	certSummary, err := svc.FindCertificateForDomain(domain)
	if err != nil {
		svc.Log.Error(err, "failed to find certificate in ACM")
		return err
	}

	if certSummary == nil {
		svc.Log.Info("Certificate not found in ACM")
		return nil
	}

	// Delete the certificate
	deleteInput := &acm.DeleteCertificateInput{
		CertificateArn: certSummary.CertificateArn,
	}
	_, err = svc.client.DeleteCertificate(deleteInput)
	if err != nil {
		svc.Log.Error(err, "failed to delete ACM certificate")
		return err
	}

	svc.Log.Info("Deleted ACM certificate", "certificateArn", *certSummary.CertificateArn, "domain", domain)

	return nil
}
