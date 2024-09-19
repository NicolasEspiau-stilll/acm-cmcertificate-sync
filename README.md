# AWS Certificate Manager / Kube CertManager Sync

## Description

This Kubernetes addon will automatically:
- import Certificates issued by Cert Manager in your cluster to AWS Cert Manager
- delete from AWS Cert Manager all Certificates deleted from your cluster

It's designed for AWS clusters (EKS or not) as it will use AWS IAM Role and perform ACM actions.

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
                "acm:ListCertificates"
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

> [!WARNING]
> I am not a proefficient Go developer. I chose Go because it works well with kubernetes api but I'm so bad at writting tests.
> Don't hesitate to fork and create pull requests with tests (or any other improvement).

### Prerequisites
- go version v1.22.0+
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

## Project Distribution

Following are the steps to build the installer and distribute this project to users.

1. Build the installer for the image built and published in the registry:

```sh
make build-installer IMG=<some-registry>/acm-cmcertificate-sync:tag
```

NOTE: The makefile target mentioned above generates an 'install.yaml'
file in the dist directory. This file contains all the resources built
with Kustomize, which are necessary to install this project without
its dependencies.

2. Using the installer

Users can just run kubectl apply -f <URL for YAML BUNDLE> to install the project, i.e.:

```sh
kubectl apply -f https://raw.githubusercontent.com/<org>/acm-cmcertificate-sync/<tag or branch>/dist/install.yaml
```

## Contributing
// TODO(user): Add detailed information on how you would like others to contribute to this project

**NOTE:** Run `make help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.
