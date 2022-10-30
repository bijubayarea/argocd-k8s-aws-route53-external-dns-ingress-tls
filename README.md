# argocd-k8s-aws-route53-external-dns-ingress-tls

ExternalDNS allows you to control DNS records dynamically via Kubernetes resources in a DNS provider-agnostic way

One great way to expose Kubernetes Applications to the world is using Ingress resources. On EKS we can avoid creating one Load Balancer each time we expose an Application. Moreover, K8S Ingress offers a single entry point to the cluster. So we can save money, manage and monitor one Load Balancer and reduce the attack surface of the Cluster. This is great, however, every time we need to expose an application we will need to create and manage DNS records manually. We can set externalDNS by adding a simple annotation to our ingress resources pointing to the DNS record and then it will be created automatically on Route53. In conclusion, using Ingress resources and ExternalDNS allows us to save time, money and improve security.

Normally when we expose an application on EKS we use a LoadBalancer service to expose the application, the problem with this is every time we create a new LoadBalancer service, AWS will create a new ELB. Ingress controllers on EKS allow us to use one ELB and configure the application access using Kubernetes resources.

By default an ingress controller doesn’t come with EKS, we need to install it. We’ll use nginx-ingress ingress controller to do that.

The NGINX Ingress Controller can be more efficient and cost-effective than a load balancer. Furthermore, features like path-based routing can be added with the NGINX ingress controller.

On the other hand, we can configure the Ingress controller as the only access to our Kubernetes Applications

With the Ingress controller we have the power to expose our applications to the world, however, creating each time every DNS record it’s annoying. To improve that we can use an external DNS to manage the DNS records of our ingresses automatically.

ExternalDNS synchronizes exposed Kubernetes Services and Ingresses with DNS providers. In a broader sense, ExternalDNS allows you to control DNS records dynamically via Kubernetes resources in a DNS provider-agnostic way.

## Pre-setup - Deploy k8s Infra

- [Deploy S3 backend for terraform state](https://github.com/bijubayarea/test-terraform-s3-remote-state)
- [Deploy EKS Cluster with 4 SPOT instances](https://github.com/bijubayarea/test-terraform-eks-cluster)
- Own the domain name (*.bijubayarea.tk) and update Internet domain registrar(like godaddy) with AWS nameservers 

## Steps
- Pre-setup steps above completed
- terraform to create k8s ServiceAccount to access Route53
- Deploy argoCD to EKS cluster
- Deploy ArgoCD App-set (boot-strap-app-set) for Ingress-Controller for host/path based routing
- Deploy ArgoCD App-set (boot-strap-app-set) for cert-manager to manage TLS certificates
- Deploy ArgoCD App-set (boot-strap-app-set) for external-dns to manipulate Route53
- Deploy ArgoCD App-set (test-app-set) to deploy applications - website, echo1 & echo2

## Final Goal
![Install external-dns](https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls/blob/main/images/external_dns.png)
![Install external-dns](https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls/blob/main/images/external_dns_2.png)
![install certmanager, ingress](https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls/blob/main/images/ingress-tls.png)

## ** VERY IMPORTANT **
** VERY IMPORTANT **
** VERY IMPORTANT **
- argoCD app-set (boot-strap) auto synch should disabled
- First sych "ingress-nginx" app, wait 2 mins
- wait for ingress-controller's load balanacer  to come up  
- update AWS Route53 A record "website.bijubayarea.tk" with ingress-controller's load balanacer
- synch "cert-manager"
- synch "external-dns"

cert-manger should be brought up only after nginx-ingress controller.

## terraform to create k8s ServiceAccount to access Route53

In the step, terraform is used to create 

- IAM Roles with trusted entity of EKS cluster's IODC provider
- IAM Policy to manipulate Route53 record
- IAM role-policy attachment to attach roles/policy
- Kubernetes service account to assume IAM role

## Deploy argoCD

Install Argo CD
All those components could be installed using a manifest provided by the Argo Project:
```
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/v2.4.7/manifests/install.yaml

```

IF NEEDED Install Argo CD CLI
To interact with the API Server we need to deploy the CLI:
```
sudo curl --silent --location -o /usr/local/bin/argocd https://github.com/argoproj/argo-cd/releases/download/v2.4.7/argocd-linux-amd64

sudochmod +x /usr/local/bin/argocd

```

Expose argocd-server
By default argocd-server is not publicaly exposed.  we will use a Load Balancer to make it usable:

```
kubectl patch svc argocd-server -n argocd -p '{"spec": {"type": "LoadBalancer"}}'
Wait about 2 minutes for the LoadBalancer creation

export ARGOCD_SERVER=`kubectl get svc argocd-server -n argocd -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'`

```

Login
The initial password is autogenerated with the pod name of the ArgoCD API server:

```
export ARGO_PWD=`kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}"| base64 -d`

Using admin as login and the autogenerated password:
argocd login $ARGOCD_SERVER --username admin --password $ARGO_PWD --insecure

You should get as an output:
'admin'logged insuccessfully
```

## Deploy ArgoCD App-set (`boot-strap-app-set`) for Ingress-Controller & cert-manager: 

boot-strap-apps from github repo : `repoURL: https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls.git`

See app-set at `repoURL: https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls.git/application-set/boot-strap-app-set/boot-strap-app-set.yaml`

This will install ingress-controller and cert-manager

```
 - git:
      repoURL: https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls.git
      revision: HEAD
      directories:
      - path: application-sets/boot-strap-apps/*

```
Install the App-set either using following ARGO CLI or from  web interface from LB `(581f61c66fa5407d8e6d89c12c1e479-1081541614.us-west-2.elb.amazonaws.com)`

** VERY IMPORTANT **
** VERY IMPORTANT **
- argoCD app-set (boot-strap) auto synch should disabled
- First sych "ingress-nginx" app, wait 2 mins, 
- wait for ingress-controller's load balanacer  to come up  
- synch "external-dns", update AWS Route53 A record "website.bijubayarea.tk" with ingress-controller's load balanacer
- synch "cert-manager"

```

argocd app create boot-strap --project default --sync-policy auto --auto-prune --sync-option CreateNamespace=true \
     --repo https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls.git \
     --path ./argocd-application-set/boot-strap-app-set/  \
     --dest-server https://kubernetes.default.svc --dest-namespace argocd 


```

## CONFIGURING THE EXTERNAL DNS
In short, external DNS is a pod running in your EKS cluster which watches over all your ingresses. When it detects an ingress with a host specified, it automatically picks up the hostname as well as the endpoint and creates a record for that resource in Route53. If the host is changed or deleted, external DNS will reflect the change immediately in Route53.

The next steps are two:

Configuring the permissions to give access to Route53
Deploying the External DNS. ExternalDNS reads the ingresses DNS hostnames (website.bijubayarea.tk, echo1.bijubayarea.tk & 
echo2.bijubayarea.tk) and creates an A record in hosted zone of AWS Route53.

STEPS inside terraform

Set up IAM permissions and deploy ExternalDNS
```
IAM Policy:

data "aws_iam_policy_document" "route53_policy" {
  statement {
    actions = [
      "route53:ChangeResourceRecordSets",
    ]

    resources = [
      "arn:aws:route53:::hostedzone/*",
    ]
  }

  statement {
    actions = [
      "route53:ListHostedZones",
      "route53:ListResourceRecordSets"
    ]

    resources = [
      "*"
    ]
  }

}

resource "aws_iam_policy" "policy" {

  name   = "${var.cluster}-${local.serviceaccount}-policy"
  path   = "/"
  policy = data.aws_iam_policy_document.route53_policy.json
}

```

IAM Role: with trusted entity=EKS cluster OIDC
```
data "aws_iam_policy_document" "role" {

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${var.issuer_url}:sub"
      values   = ["system:serviceaccount:${var.namespace}:${local.serviceaccount}"]
    }

    condition {
      test     = "StringEquals"
      variable = "${var.issuer_url}:aud"
      values   = ["sts.amazonaws.com"]
    }

    principals {
      # OIDC Provider ARN is the principal
      identifiers = ["${var.issuer_arn}"]
      type        = "Federated"
    }
  }
}

resource "aws_iam_role" "role" {

  assume_role_policy = data.aws_iam_policy_document.role[0].json
  name               = "${var.cluster}-${local.serviceaccount}-role"
}

```

Attach IAM Policy to IAM Role
```
resource "aws_iam_role_policy_attachment" "attach" {

  policy_arn = aws_iam_policy.policy[0].arn
  role       = aws_iam_role.role[0].name
}
```

Create Kubernetes Service Account with above IAM Role to access Route53
```
resource "kubernetes_service_account" "sa" {
  depends_on = [kubernetes_namespace.ns]
  automount_service_account_token = true

  metadata {
    name      = local.serviceaccount
    namespace = var.namespace

    annotations = {
      "eks.amazonaws.com/role-arn" = "${var.iam_role}"
    }
  }

  lifecycle {
    ignore_changes = [
      metadata[0].labels,
    ]
  }
}
```

```
Synch argoCd app-set "external-dns"
This creates cluster-role to watch ingress for hostnames

```


##  DNS record for http-echo and website is auto managed



```
curl echo1.bijubayarea.tk

Output
echo1
```
![](https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls/blob/main/images/echo_1_image.png)

![](https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls/blob/main/images/echo_2_image.png)




## Deploy ArgoCD App-set (`httpecho-app-set`) for test http-echo: 

See app-set at `repoURL: https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls.git/application-set/boot-strap-app-set/boot-strap-app-set.yaml`

This will install 2 deployments echo1 and echo2. Please see `https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls/application-set/test-apps/http-echo`

```
 - git:
      repoURL: https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls.git
      revision: HEAD
      directories:
      - path: application-sets/test-apps/*

```
Install the App-set either using following ARGO CLI or from  web interface 
from LB `(581f61c66fa5407d8e6d89c12c1e479-1081541614.us-west-2.elb.amazonaws.com)`
App-set provisions : namespace, deployment, service and ingress

```

 argocd app create test-apps --project default --sync-policy auto --auto-prune --sync-option CreateNamespace=true \
      --repo https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls.git \
      --path ./argocd-application-set/test-app-set/  \
      --dest-server https://kubernetes.default.svc --dest-namespace argocd 

```

 ArgoCD UI display

 ![](https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls/blob/main/images/argocd_snapshot.png)



## Installing and Configuring Cert-Manager
 install v1.7.1 of cert-manager into our cluster. cert-manager is a Kubernetes add-on that provisions TLS certificates from Let’s Encrypt and other certificate authorities (CAs) and manages their lifecycles. Certificates can be automatically requested and configured by annotating Ingress Resources, appending a tls section to the Ingress spec, and configuring one or more Issuers or ClusterIssuers to specify your preferred certificate authority. To learn more about Issuer and ClusterIssuer objects, consult the official cert-manager documentation on [Issuers](https://cert-manager.io/docs/concepts/issuer/).

Install cert-manager and its [Custom Resource Definitions](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/) (CRDs) like Issuers and ClusterIssuers by following the official [installation instructions](https://cert-manager.io/docs/installation/kubernetes/). Note that a namespace called cert-manager will be created into which the cert-manager objects will be created:

ArgoCD will deploy the cert-manager in namespace=cert-manager

```
Add yaml files under 
application-set/boot-strap-apps/cert-manager/cert-manager.yaml
application-set/boot-strap-apps/cert-manager/cluster-issuer-prod-cert.yaml

```


Add annotate ingress=httpecho-ingress with ClusterIssuer just created - `cert-manager.io/cluster-issuer: "letsencrypt-prod"`.
"letsencrypt-prod" is the ClusterIssuer.

Here we add an annotation to set the cert-manager ClusterIssuer to `letsencrypt-prod`, the test certificate ClusterIssuer. We also add an annotation that describes the type of ingress, in this case nginx.


Add tls to ingress=httpecho-ingress
We also add a tls block to specify the hosts for which we want to acquire certificates, and specify a secretName. This secret will contain the TLS private key and issued certificate. Be sure to swap out bijubayarea.tk with the domain for which you’ve created DNS records.

More details in [Securing Ingress Resources](https://cert-manager.io/docs/usage/ingress/)

- Securing Ingress Resources
  A common use-case for cert-manager is requesting TLS signed certificates to secure your ingress resources. This can be done by simply adding 
  annotations to your Ingress resources and cert-manager will facilitate creating the Certificate resource for you. A small sub-component of 
  cert-manager, ingress-shim, is responsible for this.

- How It Works
  The sub-component ingress-shim watches Ingress resources across your cluster. If it observes an Ingress with annotations described in the 
  Supported Annotations section, it will ensure a Certificate resource with the name provided in the tls.secretName field and configured as 
  described on the Ingress exists. For example:

```
metadata:
  name: echo-ingress
  namespace: http-echo
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: "letsencrypt-prod"


spec:
  tls:
  - hosts:
    - echo1.bijubayarea.tk
    - echo2.bijubayarea.tk
    secretName: http-echo-tls

```

##  Check certificates managed by Cert-Manager

```
$ kubectl -n http-echo describe ingress echo-ingress
Name:             echo-ingress
Labels:           app.kubernetes.io/instance=http-echo
Namespace:        http-echo
Address:          afd597bb1a7d54c099cee24475938458-1587408250.us-west-2.elb.amazonaws.com
Default backend:  default-http-backend:80 (<error: endpoints "default-http-backend" not found>)
TLS:
  http-echo-tls terminates echo1.bijubayarea.tk,echo2.bijubayarea.tk
Rules:
  Host                  Path  Backends
  ----                  ----  --------
  echo1.bijubayarea.tk
                        /   echo1:80 (10.0.1.117:5678)
  echo2.bijubayarea.tk
                        /   echo2:80 (10.0.2.101:5678)
Annotations:            cert-manager.io/cluster-issuer: letsencrypt-prod
                        kubernetes.io/ingress.class: nginx
Events:
  Type    Reason             Age                    From                      Message
  ----    ------             ----                   ----                      -------
  Normal  Sync               2m22s (x3 over 5h43m)  nginx-ingress-controller  Scheduled for sync
  Normal  CreateCertificate  2m22s                  cert-manager              Successfully created Certificate "http-echo-tls"


$ kubectl describe ingress -n http-echo
Name:             cm-acme-http-solver-mgc8d
Labels:           acme.cert-manager.io/http-domain=1312032652
                  acme.cert-manager.io/http-token=1280315029
                  acme.cert-manager.io/http01-solver=true
Namespace:        http-echo
Address:          afd597bb1a7d54c099cee24475938458-1587408250.us-west-2.elb.amazonaws.com
Default backend:  default-http-backend:80 (<error: endpoints "default-http-backend" not found>)
Rules:
  Host                  Path  Backends
  ----                  ----  --------
  echo2.bijubayarea.tk
                        /.well-known/acme-challenge/sw1nir1dCiTnUpAcDoqMNg3TMu1bDsQ7NOZj-DlgCk0   cm-acme-http-solver-fjphw:8089 (<none>)
Annotations:            kubernetes.io/ingress.class: nginx
                        nginx.ingress.kubernetes.io/whitelist-source-range: 0.0.0.0/0,::/0
Events:
  Type    Reason  Age              From                      Message
  ----    ------  ----             ----                      -------
  Normal  Sync    2s (x2 over 6s)  nginx-ingress-controller  Scheduled for sync


Name:             cm-acme-http-solver-zkvp5
Labels:           acme.cert-manager.io/http-domain=1310984075
                  acme.cert-manager.io/http-token=1046154894
                  acme.cert-manager.io/http01-solver=true
Namespace:        http-echo
Address:          afd597bb1a7d54c099cee24475938458-1587408250.us-west-2.elb.amazonaws.com
Default backend:  default-http-backend:80 (<error: endpoints "default-http-backend" not found>)
Rules:
  Host                  Path  Backends
  ----                  ----  --------
  echo1.bijubayarea.tk
                        /.well-known/acme-challenge/kMjIh0z6E9NwmeeUBT2TKvP2Vz4iDzlcWaVa6Hb9lSk   cm-acme-http-solver-rztlw:8089 (10.0.3.26:8089)
Annotations:            kubernetes.io/ingress.class: nginx
                        nginx.ingress.kubernetes.io/whitelist-source-range: 0.0.0.0/0,::/0
Events:
  Type    Reason  Age              From                      Message
  ----    ------  ----             ----                      -------
  Normal  Sync    3s (x2 over 7s)  nginx-ingress-controller  Scheduled for sync


```

```
$ kubectl get certificates

$ kubectl describe certificates

$ k -n http-echo get certificates
NAME            READY   SECRET          AGE
http-echo-tls   True    http-echo-tls   5m7s


$ k -n http-echo describe  certificates http-echo-tls
Name:         http-echo-tls
Namespace:    http-echo
Labels:       app.kubernetes.io/instance=http-echo
Annotations:  <none>
API Version:  cert-manager.io/v1
Kind:         Certificate
Metadata:

    Manager:      controller
    Operation:    Update
    Subresource:  status
    Time:         2022-10-27T00:20:44Z
  Owner References:
    API Version:           networking.k8s.io/v1
    Block Owner Deletion:  true
    Controller:            true
    Kind:                  Ingress
    Name:                  echo-ingress
    UID:                   fa21ff6c-906b-4e2e-a90b-c2dbafa7f025
  Resource Version:        83845
  UID:                     033e9e44-eeea-41df-bcea-fb9a08e8ac98
Spec:
  Dns Names:
    echo1.bijubayarea.tk
    echo2.bijubayarea.tk
  Issuer Ref:
    Group:      cert-manager.io
    Kind:       ClusterIssuer
    Name:       letsencrypt-prod
  Secret Name:  http-echo-tls
  Usages:
    digital signature
    key encipherment
Status:
  Conditions:
    Last Transition Time:  2022-10-27T00:20:44Z
    Message:               Certificate is up to date and has not expired
    Observed Generation:   1
    Reason:                Ready
    Status:                True
    Type:                  Ready
  Not After:               2023-01-24T23:20:42Z
  Not Before:              2022-10-26T23:20:43Z
  Renewal Time:            2022-12-25T23:20:42Z
  Revision:                1
Events:
  Type    Reason     Age    From          Message
  ----    ------     ----   ----          -------
  Normal  Issuing    5m26s  cert-manager  Issuing certificate as Secret does not exist
  Normal  Generated  5m25s  cert-manager  Stored new private key in temporary Secret resource "http-echo-tls-hfrq4"
  Normal  Requested  5m25s  cert-manager  Created new CertificateRequest resource "http-echo-tls-d7f6x"
  Normal  Issuing    4m55s  cert-manager  The certificate has been successfully issued

$ kubectl get orders

$ kubectl -n http-echo get orders
NAME                             STATE   AGE
http-echo-tls-d7f6x-2650895051   valid   6m30s


$ kubectl -n http-echo describe orders http-echo-tls-d7f6x-2650895051
Name:         http-echo-tls-d7f6x-2650895051
Namespace:    http-echo
Labels:       app.kubernetes.io/instance=http-echo
Annotations:  cert-manager.io/certificate-name: http-echo-tls
              cert-manager.io/certificate-revision: 1
              cert-manager.io/private-key-secret-name: http-echo-tls-hfrq4
API Version:  acme.cert-manager.io/v1
Kind:         Order
....
....
....
Events:
  Type    Reason    Age    From          Message
  ----    ------    ----   ----          -------
  Normal  Created   6m54s  cert-manager  Created Challenge resource "http-echo-tls-d7f6x-2650895051-455781877" for domain "echo1.bijubayarea.tk"
  Normal  Created   6m54s  cert-manager  Created Challenge resource "http-echo-tls-d7f6x-2650895051-4256994384" for domain "echo2.bijubayarea.tk"
  Normal  Complete  6m25s  cert-manager  Order completed successfully

```

## Results:

Browser verifies CA authority - letsencrypt
![](https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls/blob/main/images/http-echo-secure_connection.png)

![](https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls/blob/main/images/http-echo-secure_connection_2.png)

After adding a personal website in 
```
$ ls application-set/test-apps/website/
personal-website-deployment.yaml  
personal-website-ingress.yaml  
personal-website-namespace.yaml  
personal-website-service.yaml

https://https://website.bijubayarea.tk/

```
![](https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls/blob/main/images/personal_website_tls.png)

## Verify Route53 is updated with DNS entry

pod external-dns will auto add a DNS A record in hosted zone for the hostname defined in ingress
Check if the ELB load balancer names is correct entry for the DNS A Record

![](https://github.com/bijubayarea/argocd-k8s-aws-route53-external-dns-ingress-tls/blob/main/images/route53_auto_update.png)


## Debug External DNS

 problem with the DNS records after 300 seconds or 5 minutes we could check the External DNS pod Logs.
 ```
> k logs external-dns-pod -n kube-system -f
time="2022-01-19T04:16:07Z" level=info msg="All records are already up to date"
time="2022-01-19T04:17:09Z" level=info msg="Desired change: CREATE testing-nginx.example.com A [Id: /hostedzone/Z02855792S1GV7JKSYHM5]"
time="2022-01-19T04:17:09Z" level=info msg="Desired change: CREATE testing-nginx.example.com TXT [Id: /hostedzone/Z02855792S1GV7JKSYHM5]"
time="2022-01-19T04:17:09Z" level=info msg="2 record(s) in zone example.com. [Id: /hostedzone/Z02855792S1GV7JKSYHM5] were successfully updated"
time="2022-01-19T04:18:08Z" level=info msg="All records are already up to date"
 ```
## Conclusion

In this guide, you set up an Nginx Ingress to load balance and route external requests to backend Services inside of your Kubernetes cluster. 
You also secured the Ingress by installing the cert-manager certificate provisioner and setting up a Let’s Encrypt certificate for two host paths.

External DNS also takes cares of picking up any new hostnames from new Ingress and update A record of hostname in Route53 with new 

## To delete argoCD app:

Use either argocd CLI or argoCd GUI to delete infra

```
argocd app delete test-apps
argocd app delete boot-strap
kubectl patch svc argocd-server -n argocd -p '{"spec": {"type": "ClusterIP"}}'

kubectl delete -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/v2.4.7/manifests/install.yaml
kubectl delete namespace argocd


```

```
terraform destroy test-terraform-eks-cluster
terraform destroy test-terraform-s3-remote-state

```


