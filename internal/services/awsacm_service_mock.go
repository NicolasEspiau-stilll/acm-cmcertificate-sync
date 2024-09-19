package services

import (
	"github.com/aws/aws-sdk-go/service/acm"
	"github.com/stretchr/testify/mock"
)

type AWSACMServiceMock struct {
	mock.Mock
}

// Mock method for FindCertificateForDomain
func (m *AWSACMServiceMock) FindCertificateForDomain(domain string) (*acm.CertificateSummary, error) {
	args := m.Called(domain)
	if result := args.Get(0); result != nil {
		return result.(*acm.CertificateSummary), args.Error(1)
	}
	return nil, args.Error(1)
}

// Function to import or update a certificate in ACM
func (m *AWSACMServiceMock) ImportOrUpdateCertificate(domain string, certData string, privateKey string) error {
	args := m.Called(domain, certData, privateKey)
	return args.Error(0)
}

// Function to delete a certificate from ACM by its domain
func (m *AWSACMServiceMock) DeleteCertificateByCommonName(domain string) error {
	args := m.Called(domain)
	return args.Error(0)
}
