package awsacm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockACM is a hand-rolled mock of the ACMAPI interface.
type mockACM struct {
	importFn   func(ctx context.Context, params *acm.ImportCertificateInput, optFns ...func(*acm.Options)) (*acm.ImportCertificateOutput, error)
	deleteFn   func(ctx context.Context, params *acm.DeleteCertificateInput, optFns ...func(*acm.Options)) (*acm.DeleteCertificateOutput, error)
	listFn     func(ctx context.Context, params *acm.ListCertificatesInput, optFns ...func(*acm.Options)) (*acm.ListCertificatesOutput, error)
	describeFn func(ctx context.Context, params *acm.DescribeCertificateInput, optFns ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error)
}

func (m *mockACM) ImportCertificate(ctx context.Context, params *acm.ImportCertificateInput, optFns ...func(*acm.Options)) (*acm.ImportCertificateOutput, error) {
	return m.importFn(ctx, params, optFns...)
}

func (m *mockACM) DeleteCertificate(ctx context.Context, params *acm.DeleteCertificateInput, optFns ...func(*acm.Options)) (*acm.DeleteCertificateOutput, error) {
	return m.deleteFn(ctx, params, optFns...)
}

func (m *mockACM) ListCertificates(ctx context.Context, params *acm.ListCertificatesInput, optFns ...func(*acm.Options)) (*acm.ListCertificatesOutput, error) {
	return m.listFn(ctx, params, optFns...)
}

func (m *mockACM) DescribeCertificate(ctx context.Context, params *acm.DescribeCertificateInput, optFns ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error) {
	return m.describeFn(ctx, params, optFns...)
}

func newTestService(mock *mockACM) *AWSACMService {
	return &AWSACMService{Client: mock, Log: logr.Discard()}
}

// generateCertChain builds a self-signed "intermediate" CA and a leaf signed
// by it, returning both as PEM.
func generateCertChain(t *testing.T, dnsNames []string) (leafPEM, chainPEM string) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Intermediate CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	leafPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))
	chainPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	return leafPEM, chainPEM
}

func TestSplitCertificateAndChain(t *testing.T) {
	leafPEM, chainPEM := generateCertChain(t, []string{"example.com"})

	t.Run("leaf with chain", func(t *testing.T) {
		leaf, chain, err := SplitCertificateAndChain(leafPEM + chainPEM)
		require.NoError(t, err)
		assert.Equal(t, leafPEM, leaf)
		assert.Equal(t, chainPEM, chain)
	})

	t.Run("leaf only", func(t *testing.T) {
		leaf, chain, err := SplitCertificateAndChain(leafPEM)
		require.NoError(t, err)
		assert.Equal(t, leafPEM, leaf)
		assert.Empty(t, chain)
	})

	t.Run("garbage input", func(t *testing.T) {
		_, _, err := SplitCertificateAndChain("not a pem at all")
		assert.Error(t, err)
	})
}

func TestImportCertificate_Create(t *testing.T) {
	var captured *acm.ImportCertificateInput
	mock := &mockACM{
		importFn: func(_ context.Context, params *acm.ImportCertificateInput, _ ...func(*acm.Options)) (*acm.ImportCertificateOutput, error) {
			captured = params
			return &acm.ImportCertificateOutput{CertificateArn: aws.String("arn:new")}, nil
		},
	}
	svc := newTestService(mock)

	arn, err := svc.ImportCertificate(context.Background(), ImportRequest{
		CertificatePEM: "LEAF",
		PrivateKeyPEM:  "KEY",
		Tags:           map[string]string{ManagedByTagKey: ManagedByTagValue},
	})
	require.NoError(t, err)
	assert.Equal(t, "arn:new", arn)

	require.NotNil(t, captured)
	assert.Nil(t, captured.CertificateArn, "a new import must not carry an ARN")
	assert.Nil(t, captured.CertificateChain, "an empty chain must be omitted, ACM rejects empty values")
	require.Len(t, captured.Tags, 1)
	assert.Equal(t, ManagedByTagKey, aws.ToString(captured.Tags[0].Key))
}

func TestImportCertificate_UpdateKeepsARNAndDropsTags(t *testing.T) {
	var captured *acm.ImportCertificateInput
	mock := &mockACM{
		importFn: func(_ context.Context, params *acm.ImportCertificateInput, _ ...func(*acm.Options)) (*acm.ImportCertificateOutput, error) {
			captured = params
			return &acm.ImportCertificateOutput{CertificateArn: params.CertificateArn}, nil
		},
	}
	svc := newTestService(mock)

	arn, err := svc.ImportCertificate(context.Background(), ImportRequest{
		ARN:            "arn:existing",
		CertificatePEM: "LEAF",
		ChainPEM:       "CHAIN",
		PrivateKeyPEM:  "KEY",
		Tags:           map[string]string{ManagedByTagKey: ManagedByTagValue},
	})
	require.NoError(t, err)
	assert.Equal(t, "arn:existing", arn, "re-import must keep the same ARN")

	require.NotNil(t, captured)
	assert.Equal(t, "arn:existing", aws.ToString(captured.CertificateArn))
	assert.Equal(t, []byte("CHAIN"), captured.CertificateChain)
	assert.Empty(t, captured.Tags, "ACM rejects tags on re-import")
}

func TestFindCertificateByDomains(t *testing.T) {
	page1 := &acm.ListCertificatesOutput{
		NextToken: aws.String("page2"),
		CertificateSummaryList: []acmtypes.CertificateSummary{
			{
				// Same domains but issued by ACM: must be ignored.
				CertificateArn:                  aws.String("arn:amazon-issued"),
				Type:                            acmtypes.CertificateTypeAmazonIssued,
				SubjectAlternativeNameSummaries: []string{"example.com", "www.example.com"},
			},
			{
				CertificateArn:                  aws.String("arn:other"),
				Type:                            acmtypes.CertificateTypeImported,
				SubjectAlternativeNameSummaries: []string{"other.com"},
			},
		},
	}
	page2 := &acm.ListCertificatesOutput{
		CertificateSummaryList: []acmtypes.CertificateSummary{
			{
				CertificateArn: aws.String("arn:match"),
				Type:           acmtypes.CertificateTypeImported,
				// Order and case differences must not prevent the match.
				SubjectAlternativeNameSummaries: []string{"WWW.example.com", "example.com"},
			},
		},
	}

	mock := &mockACM{
		listFn: func(_ context.Context, params *acm.ListCertificatesInput, _ ...func(*acm.Options)) (*acm.ListCertificatesOutput, error) {
			if params.NextToken == nil {
				return page1, nil
			}
			return page2, nil
		},
	}
	svc := newTestService(mock)

	arn, err := svc.FindCertificateByDomains(context.Background(), []string{"example.com", "www.example.com"})
	require.NoError(t, err)
	assert.Equal(t, "arn:match", arn, "must paginate past the first page and match on the SAN set")

	arn, err = svc.FindCertificateByDomains(context.Background(), []string{"missing.com"})
	require.NoError(t, err)
	assert.Empty(t, arn)
}

func TestFindCertificateByDomains_TruncatedSANsUsesDescribe(t *testing.T) {
	mock := &mockACM{
		listFn: func(_ context.Context, _ *acm.ListCertificatesInput, _ ...func(*acm.Options)) (*acm.ListCertificatesOutput, error) {
			return &acm.ListCertificatesOutput{
				CertificateSummaryList: []acmtypes.CertificateSummary{
					{
						CertificateArn:                       aws.String("arn:truncated"),
						Type:                                 acmtypes.CertificateTypeImported,
						SubjectAlternativeNameSummaries:      []string{"a.example.com"},
						HasAdditionalSubjectAlternativeNames: aws.Bool(true),
					},
				},
			}, nil
		},
		describeFn: func(_ context.Context, params *acm.DescribeCertificateInput, _ ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error) {
			assert.Equal(t, "arn:truncated", aws.ToString(params.CertificateArn))
			return &acm.DescribeCertificateOutput{
				Certificate: &acmtypes.CertificateDetail{
					SubjectAlternativeNames: []string{"a.example.com", "b.example.com"},
				},
			}, nil
		},
	}
	svc := newTestService(mock)

	arn, err := svc.FindCertificateByDomains(context.Background(), []string{"b.example.com", "a.example.com"})
	require.NoError(t, err)
	assert.Equal(t, "arn:truncated", arn)
}

func TestDeleteCertificate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock := &mockACM{
			deleteFn: func(_ context.Context, params *acm.DeleteCertificateInput, _ ...func(*acm.Options)) (*acm.DeleteCertificateOutput, error) {
				assert.Equal(t, "arn:x", aws.ToString(params.CertificateArn))
				return &acm.DeleteCertificateOutput{}, nil
			},
		}
		assert.NoError(t, newTestService(mock).DeleteCertificate(context.Background(), "arn:x"))
	})

	t.Run("already deleted is not an error", func(t *testing.T) {
		mock := &mockACM{
			deleteFn: func(_ context.Context, _ *acm.DeleteCertificateInput, _ ...func(*acm.Options)) (*acm.DeleteCertificateOutput, error) {
				return nil, &acmtypes.ResourceNotFoundException{Message: aws.String("gone")}
			},
		}
		assert.NoError(t, newTestService(mock).DeleteCertificate(context.Background(), "arn:x"))
	})

	t.Run("in use is reported as such", func(t *testing.T) {
		mock := &mockACM{
			deleteFn: func(_ context.Context, _ *acm.DeleteCertificateInput, _ ...func(*acm.Options)) (*acm.DeleteCertificateOutput, error) {
				return nil, &acmtypes.ResourceInUseException{Message: aws.String("attached to an ALB")}
			},
		}
		err := newTestService(mock).DeleteCertificate(context.Background(), "arn:x")
		require.Error(t, err)
		assert.True(t, IsInUse(err), "IsInUse must see through error wrapping")
	})
}

func TestNormalizeDomainSet(t *testing.T) {
	assert.Equal(t,
		normalizeDomainSet([]string{"B.com", " a.com ", "b.com", ""}),
		normalizeDomainSet([]string{"a.com", "b.com"}),
	)
	assert.NotEqual(t,
		normalizeDomainSet([]string{"a.com"}),
		normalizeDomainSet([]string{"a.com", "b.com"}),
	)
}

// Compile-time proof that the real ACM client satisfies our interface subset.
var _ ACMAPI = (*acm.Client)(nil)
