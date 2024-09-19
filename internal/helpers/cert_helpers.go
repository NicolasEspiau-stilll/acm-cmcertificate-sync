package helpers

import (
	"encoding/pem"
	"fmt"
	"strings"
)

// Helper function to split the leaf certificate and the certificate chain
func SplitCertificateAndChain(certData string) (string, string, error) {
	var leafCert string
	var certChain string

	// Iterate over the certData and split based on PEM blocks
	var pemBlocks []string
	for {
		block, rest := pem.Decode([]byte(certData))
		if block == nil {
			break
		}
		pemBlocks = append(pemBlocks, string(pem.EncodeToMemory(block)))
		certData = string(rest)
	}

	if len(pemBlocks) < 1 {
		return "", "", fmt.Errorf("no valid PEM blocks found")
	}

	// The first certificate is usually the leaf certificate
	leafCert = pemBlocks[0]

	// The rest form the certificate chain (intermediate certificates)
	if len(pemBlocks) > 1 {
		certChain = strings.Join(pemBlocks[1:], "")
	}

	return leafCert, certChain, nil
}
