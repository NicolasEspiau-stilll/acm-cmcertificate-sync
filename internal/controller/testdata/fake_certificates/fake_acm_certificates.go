package fakecertificates

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/acm"
)

var FakeACMCertificates = map[string]*acm.CertificateSummary{
	"example.com": {
		DomainName:     aws.String("example.com"),
		CertificateArn: aws.String("arn:aws:acm:region:account:certificate/12345678"),
	},
	"sub.example.com": {
		DomainName:     aws.String("sub.example.com"),
		CertificateArn: aws.String("arn:aws:acm:region:account:certificate/12344321"),
	},
	"test.com": {
		DomainName:     aws.String("test.com"),
		CertificateArn: aws.String("arn:aws:acm:region:account:certificate/87654321"),
	},
	"another.com": {
		DomainName:     aws.String("another.com"),
		CertificateArn: aws.String("arn:aws:acm:region:account:certificate/11223344"),
	},
}
