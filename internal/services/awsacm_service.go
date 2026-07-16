package awsacm

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"
)

// ManagedByTagKey and ManagedByTagValue identify certificates imported by this controller.
const (
	ManagedByTagKey   = "ManagedBy"
	ManagedByTagValue = "acm-cmcertificate-sync"
)

// awsCallTimeout bounds every individual AWS API call. Without it a wedged
// connection blocks the reconcile queue forever: the manager runs reconciles
// sequentially, so one hung call silently starves every other Certificate.
const awsCallTimeout = 30 * time.Second

// ACMAPI is the subset of the AWS ACM client used by this service.
// It exists so tests can substitute a mock for the real client.
type ACMAPI interface {
	ImportCertificate(ctx context.Context, params *acm.ImportCertificateInput, optFns ...func(*acm.Options)) (*acm.ImportCertificateOutput, error)
	DeleteCertificate(ctx context.Context, params *acm.DeleteCertificateInput, optFns ...func(*acm.Options)) (*acm.DeleteCertificateOutput, error)
	ListCertificates(ctx context.Context, params *acm.ListCertificatesInput, optFns ...func(*acm.Options)) (*acm.ListCertificatesOutput, error)
	DescribeCertificate(ctx context.Context, params *acm.DescribeCertificateInput, optFns ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error)
}

// ImportRequest carries everything needed to create or update a certificate in ACM.
type ImportRequest struct {
	// ARN of the existing ACM certificate to re-import onto. Empty means create a new one.
	ARN string
	// CertificatePEM is the leaf certificate, PEM encoded.
	CertificatePEM string
	// ChainPEM is the intermediate chain, PEM encoded. May be empty.
	ChainPEM string
	// PrivateKeyPEM is the private key, PEM encoded.
	PrivateKeyPEM string
	// Tags are applied on initial import only: ACM rejects tags on re-import.
	Tags map[string]string
}

type AWSACMService struct {
	Client ACMAPI
	Log    logr.Logger
}

// NewAWSACMService builds a service using the default AWS credential chain
// (env vars, IRSA web identity token, instance profile, ...).
// region is optional: when empty, the region is resolved from the environment.
func NewAWSACMService(ctx context.Context, region string) (*AWSACMService, error) {
	var optFns []func(*config.LoadOptions) error
	if region != "" {
		optFns = append(optFns, config.WithRegion(region))
	}
	cfg, err := config.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS configuration: %w", err)
	}

	return &AWSACMService{
		Client: acm.NewFromConfig(cfg),
		Log:    ctrl.Log.WithName("AWSACMService"),
	}, nil
}

// ImportCertificate creates the certificate in ACM, or updates it in place when
// req.ARN is set. Re-importing onto an existing ARN is the supported ACM rotation
// flow: the ARN is stable, so consumers (ALB, CloudFront, ...) keep working.
// Returns the ARN of the imported certificate.
func (svc *AWSACMService) ImportCertificate(ctx context.Context, req ImportRequest) (string, error) {
	input := &acm.ImportCertificateInput{
		Certificate: []byte(req.CertificatePEM),
		PrivateKey:  []byte(req.PrivateKeyPEM),
	}
	// ACM rejects an empty CertificateChain field: only set it when there is a chain.
	if req.ChainPEM != "" {
		input.CertificateChain = []byte(req.ChainPEM)
	}
	if req.ARN != "" {
		input.CertificateArn = aws.String(req.ARN)
	} else {
		for key, value := range req.Tags {
			input.Tags = append(input.Tags, acmtypes.Tag{Key: aws.String(key), Value: aws.String(value)})
		}
		sort.Slice(input.Tags, func(i, j int) bool {
			return aws.ToString(input.Tags[i].Key) < aws.ToString(input.Tags[j].Key)
		})
	}

	callCtx, cancel := context.WithTimeout(ctx, awsCallTimeout)
	defer cancel()
	output, err := svc.Client.ImportCertificate(callCtx, input)
	if err != nil {
		return "", fmt.Errorf("failed to import certificate into ACM: %w", err)
	}
	arn := aws.ToString(output.CertificateArn)
	svc.Log.Info("Imported certificate into ACM", "certificateArn", arn, "update", req.ARN != "")
	return arn, nil
}

// FindCertificateByDomains looks for an imported ACM certificate covering exactly
// the given domain set. It is used to adopt certificates imported by a previous
// run of the controller (e.g. when the tracking annotation was lost).
func (svc *AWSACMService) FindCertificateByDomains(ctx context.Context, domains []string) (string, error) {
	if len(domains) == 0 {
		return "", nil
	}
	wanted := normalizeDomainSet(domains)

	input := &acm.ListCertificatesInput{
		// Imported certificates may use key algorithms outside the default
		// filter (which only lists RSA_2048); ask for everything.
		Includes: &acmtypes.Filters{
			KeyTypes: acmtypes.KeyAlgorithm("").Values(),
		},
	}
	paginator := acm.NewListCertificatesPaginator(svc.Client, input)
	for paginator.HasMorePages() {
		page, err := func() (*acm.ListCertificatesOutput, error) {
			pageCtx, cancel := context.WithTimeout(ctx, awsCallTimeout)
			defer cancel()
			return paginator.NextPage(pageCtx)
		}()
		if err != nil {
			return "", fmt.Errorf("failed to list ACM certificates: %w", err)
		}
		for _, summary := range page.CertificateSummaryList {
			if summary.Type != acmtypes.CertificateTypeImported {
				continue
			}
			candidate, err := svc.certificateDomains(ctx, summary)
			if err != nil {
				return "", err
			}
			if candidate == wanted {
				return aws.ToString(summary.CertificateArn), nil
			}
		}
	}
	return "", nil
}

// certificateDomains returns the normalized SAN set of a certificate summary,
// falling back to DescribeCertificate when the summary is truncated.
func (svc *AWSACMService) certificateDomains(ctx context.Context, summary acmtypes.CertificateSummary) (string, error) {
	if !aws.ToBool(summary.HasAdditionalSubjectAlternativeNames) {
		return normalizeDomainSet(summary.SubjectAlternativeNameSummaries), nil
	}
	callCtx, cancel := context.WithTimeout(ctx, awsCallTimeout)
	defer cancel()
	described, err := svc.Client.DescribeCertificate(callCtx, &acm.DescribeCertificateInput{
		CertificateArn: summary.CertificateArn,
	})
	if err != nil {
		return "", fmt.Errorf("failed to describe ACM certificate %s: %w", aws.ToString(summary.CertificateArn), err)
	}
	return normalizeDomainSet(described.Certificate.SubjectAlternativeNames), nil
}

// DeleteCertificate removes the certificate from ACM. A certificate that is
// already gone is not an error. Use IsInUse to detect certificates that are
// still attached to another AWS resource.
func (svc *AWSACMService) DeleteCertificate(ctx context.Context, arn string) error {
	callCtx, cancel := context.WithTimeout(ctx, awsCallTimeout)
	defer cancel()
	_, err := svc.Client.DeleteCertificate(callCtx, &acm.DeleteCertificateInput{
		CertificateArn: aws.String(arn),
	})
	if err != nil {
		var notFound *acmtypes.ResourceNotFoundException
		if errors.As(err, &notFound) {
			svc.Log.Info("Certificate already absent from ACM", "certificateArn", arn)
			return nil
		}
		return fmt.Errorf("failed to delete ACM certificate %s: %w", arn, err)
	}
	svc.Log.Info("Deleted certificate from ACM", "certificateArn", arn)
	return nil
}

// IsInUse reports whether err means the ACM certificate is still attached to
// other AWS resources and therefore cannot be deleted yet.
func IsInUse(err error) bool {
	var inUse *acmtypes.ResourceInUseException
	return errors.As(err, &inUse)
}

// SplitCertificateAndChain splits a PEM bundle (as found in a cert-manager
// tls.crt) into the leaf certificate and the intermediate chain.
func SplitCertificateAndChain(certData string) (leafPEM string, chainPEM string, err error) {
	var pemBlocks []string
	rest := []byte(certData)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		pemBlocks = append(pemBlocks, string(pem.EncodeToMemory(block)))
	}

	if len(pemBlocks) == 0 {
		return "", "", fmt.Errorf("no valid PEM blocks found in certificate data")
	}

	// cert-manager writes the leaf first, followed by intermediates.
	return pemBlocks[0], strings.Join(pemBlocks[1:], ""), nil
}

// normalizeDomainSet turns a list of domains into a canonical comparable form:
// lower-cased, deduplicated, sorted, joined.
func normalizeDomainSet(domains []string) string {
	seen := make(map[string]struct{}, len(domains))
	normalized := make([]string, 0, len(domains))
	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" {
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		normalized = append(normalized, domain)
	}
	sort.Strings(normalized)
	return strings.Join(normalized, ",")
}
