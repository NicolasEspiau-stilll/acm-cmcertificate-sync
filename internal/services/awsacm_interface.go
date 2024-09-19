package services

import "github.com/aws/aws-sdk-go/service/acm"

type AWSACMServiceInterface interface {
	FindCertificateForDomain(domain string) (*acm.CertificateSummary, error)
	ImportOrUpdateCertificate(domain string, certData string, privateKey string) error
	DeleteCertificateByCommonName(commonName string) error
}
