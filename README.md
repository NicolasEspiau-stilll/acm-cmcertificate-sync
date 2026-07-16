# AWS Certificate Manager / Kube CertManager Sync

## Description

This Kubernetes addon will automatically:
- import Certificates issued by cert-manager in your cluster into AWS Certificate Manager (ACM)
- re-import renewed certificates **onto the same ACM ARN**, so resources referencing the certificate (ALB listeners, CloudFront, ...) keep working across renewals
- delete the ACM copy when the Certificate is deleted from the cluster (via a finalizer)

It's designed for AWS clusters (EKS or not) as it will use AWS IAM Role and perform ACM actions.

### How it works

- One ACM certificate is maintained **per cert-manager Certificate** (not per DNS name). All SANs are covered by the single imported certificate.
- The controller records the ACM ARN and a digest of the imported certificate in annotations on the Certificate resource:
  - `acm-cmcertificate-sync.stilll.fr/certificate-arn`
  - `acm-cmcertificate-sync.stilll.fr/certificate-hash`
- Unchanged certificates are never re-imported; renewals are detected through the digest and re-imported in place.
- If no ARN is recorded yet, the controller looks for an existing imported ACM certificate with the exact same domain set and adopts it instead of creating a duplicate.
- On deletion, a finalizer (`acm-cmcertificate-sync.stilll.fr/finalizer`) guarantees the ACM copy is removed first. If the ACM certificate is still attached to an AWS resource, deletion is retried every minute until you detach it (the Certificate stays in `Terminating` meanwhile).
- ACM certificates created by the controller are tagged with `ManagedBy=acm-cmcertificate-sync`, plus the Kubernetes namespace and name.

### Configuration

Set through the Helm values (rendered as environment variables):

| Value | Env var | Meaning |
|---|---|---|
| `acmcertmanagersync.awsRegion` | `AWS_REGION` | AWS region for ACM. Optional: when empty the SDK default chain resolves it. |
| `acmcertmanagersync.namespaces` | `WATCHED_NAMESPACES` | Namespaces to watch. Empty means all namespaces. |
| `acmcertmanagersync.domainPatterns` | `DOMAIN_PATTERNS` | Only Certificates with at least one domain matching one pattern are synced. Empty means all. Wildcards use `filepath.Match` syntax: `*.example.com` matches any subdomain depth but **not** the apex `example.com` (add it as its own pattern). |

## Read this if you're a user

### Pre-requisites
- kubectl version v1.11.3+.
- Access to a Kubernetes v1.11.3+ cluster.
- Helm v3.13.1+
- AWS IAM Role as designed here after.

#### AWS IAM Role policy
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "acm:ImportCertificate",
                "acm:DescribeCertificate",
                "acm:DeleteCertificate",
                "acm:ListCertificates",
                "acm:AddTagsToCertificate"
            ],
            "Resource": "*"
        }
    ]
}
```

#### AWS IAM Role trust relationship

If you're using [kube2iam](https://github.com/jtblin/kube2iam) see the [docs](https://github.com/jtblin/kube2iam?tab=readme-ov-file#iam-roles).

If you're working with an EKS cluster and and OIDC provider:
```json
{
    "Version": "2012-10-17",
    "Statement" : [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "<oidc_provider_arn>"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "<oidc_provider>:aud": "sts.amazonaws.com",
                    "<oidc_provider>:sub": "system:serviceaccount:<ACMCMSYNC_NAMESPACE>:<ACMCMSYNC_SA_NAME>"
                }
            }
        }
    ]
}
```
Where:
- `<oidc_provider_arn>` should look like ``
- `<oidc_provider>` should look like ``
- `<ACMCMSYNC_NAMESPACE>` is the namespace where you will deploy the addon
- `<ACMCMSYNC_SA_NAME>` is the addon's service account's name set in the values


If you deploy the Service Account with Helm, don't forget to set the annotation properly to make it use the AWS IAM Role.
Same if you create the Service Account outside the Helm deployment.

### Deploying with Helm

```sh
helm repo add acm-cmcertificate-sync nicolasespiau-stilll.github.io/acm-cmcertificate-sync
helm repo update
helm show values acm-cmcertificate-sync/acm-cmcertificate-sync > path/to/values.yaml
```

In the values, you can update the AWS Region, the domain filters that must be matched to sync certificates, and the namespaces where you want ACM CM Cert Sync to watch Certi

Update your values and deploy:
```sh
helm install --namespace acm-cm-sync --create-namespace acm-cm-sync acm-cmcertificate-sync/acm-cmcertificate-sync -f path/to/values.yaml
```

## Read this if you are developer

And you want to contribute, or simply fork and use the project on your side.

Run the unit tests with:

```sh
make test
```

The tests use the controller-runtime fake client and a mocked ACM API: no cluster, no AWS account and no kubebuilder binaries are required.

### Prerequisites
- go version v1.24+
- docker version 17.03+.
- kubectl version v1.11.3+.
- Access to a Kubernetes v1.11.3+ cluster.

### To Deploy on the cluster

> [!WARNING]
> I chose to remove the kustomize based deploy commands because I prefer working with helm and I would have make 
> mistakes. Feel free to contribute and restore them.

**Build and push your image to the location specified by `IMG`:**

```sh
make docker-build docker-push IMG=<some-registry>/acm-cmcertificate-sync:tag
```

**NOTE:** This image ought to be published in the personal registry you specified.
And it is required to have access to pull the image from the working environment.
Make sure you have the proper permission to the registry if the above commands don’t work.

## Contributing
// TODO(user): Add detailed information on how you would like others to contribute to this project

**NOTE:** Run `make help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.
