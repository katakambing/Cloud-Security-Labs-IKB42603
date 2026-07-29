# IKB42603 Lab 0: Environment Setup Report
NO ID: 52215225039
## System Requirements

This setup was completed for a Kali Linux environment. Kali is Debian-based, so the required packages are installed with `apt`. Run the commands from a terminal with an account that can use `sudo`.

- Kali Linux with an active Internet connection
- At least 4 GB RAM and 10 GB free disk space
- `sudo` access
- A supported CPU architecture (`amd64` or `arm64`)

Update the package index and install the utilities used by the remaining steps:

```bash
sudo apt update
sudo apt install -y ca-certificates curl unzip
```

![.evidence of system package preparation](./.evidence/system-package-preparation.png)

## Tool Installations

### Docker

Docker provides the container runtime used to start LocalStack.

1. Install Docker from the Kali repository.

   ```bash
   sudo apt install -y docker.io
   ```

2. Enable and start the Docker service.

   ```bash
   sudo systemctl enable --now docker
   ```

3. Allow the current user to run Docker commands without typing `sudo`.

   ```bash
   sudo usermod -aG docker "$USER"
   ```

   Log out and log back in after this command for the group change to take effect. Until then, prefix Docker commands with `sudo`.

4. Verify the installation.

   ```bash
   docker --version
   sudo docker run --rm hello-world
   ```

   Expected output resembles:

   ```text
   Docker version 20.10.x, build xxxxxxx
   Hello from Docker!
   ```

![.evidence of Docker installation](./.evidence/docker-version-and-hello-world.png)

### AWS CLI v2

The AWS CLI is used to send API requests to the local AWS-compatible LocalStack endpoint.

1. Download and install the AWS CLI v2 bundle for the current CPU architecture.

   ```bash
   ARCH="$(uname -m)"
   case "$ARCH" in
     x86_64) AWS_ARCH="x86_64" ;;
     aarch64|arm64) AWS_ARCH="aarch64" ;;
     *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
   esac

   curl "https://awscli.amazonaws.com/awscli-exe-linux-${AWS_ARCH}.zip" -o awscliv2.zip
   unzip -q awscliv2.zip
   sudo ./aws/install --update
   rm -rf aws awscliv2.zip
   ```

2. Verify the installation.

   ```bash
   aws --version
   ```

   Expected output resembles:

   ```text
   aws-cli/2.x.x Python/3.x.x Linux/x.x.x botocore/2.x.x
   ```

![.evidence of AWS CLI v2 installation](./.evidence/aws-cli-version.png)

### kind

kind (Kubernetes IN Docker) creates Kubernetes clusters using Docker containers.

1. Download the kind binary for the current architecture and install it.

   ```bash
   ARCH="$(uname -m)"
   case "$ARCH" in
     x86_64) KIND_ARCH="amd64" ;;
     aarch64|arm64) KIND_ARCH="arm64" ;;
     *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
   esac

   curl -Lo ./kind "https://kind.sigs.k8s.io/dl/v0.23.0/kind-linux-${KIND_ARCH}"
   chmod +x ./kind
   sudo install -m 0755 ./kind /usr/local/bin/kind
   rm ./kind
   ```

2. Verify the installation.

   ```bash
   kind --version
   ```

   Expected output:

   ```text
   kind v0.23.0 go1.x.x linux/amd64
   ```

![.evidence of kind installation](./.evidence/kind-version.png)

### kubectl

`kubectl` is the command-line client used to manage Kubernetes clusters.

1. Download the stable `kubectl` binary for the current architecture and install it.

   ```bash
   ARCH="$(uname -m)"
   case "$ARCH" in
     x86_64) KUBECTL_ARCH="amd64" ;;
     aarch64|arm64) KUBECTL_ARCH="arm64" ;;
     *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
   esac

   KUBECTL_VERSION="$(curl -L -s https://dl.k8s.io/release/stable.txt)"
   curl -LO "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${KUBECTL_ARCH}/kubectl"
   chmod +x kubectl
   sudo install -m 0755 kubectl /usr/local/bin/kubectl
   rm kubectl
   ```

2. Verify the installation.

   ```bash
   kubectl version --client
   ```

   Expected output resembles:

   ```text
   Client Version: v1.x.x
   Kustomize Version: v5.x.x
   ```

![.evidence of kubectl installation](./.evidence/kubectl-version.png)

## LocalStack Initialization

LocalStack emulates AWS services locally. Start it in a separate terminal. This command occupies that terminal while LocalStack is running:

```bash
sudo docker run --rm -p 4566:4566 localstack/localstack:3.0
```

For a detached session, add `-d`:

```bash
sudo docker run --rm -d --name localstack -p 4566:4566 localstack/localstack:3.0
```

Verify that the container is running and that the LocalStack health endpoint is reachable:

```bash
sudo docker ps --filter name=localstack
curl http://localhost:4566/_localstack/health
```

Expected output resembles:

```text
CONTAINER ID   IMAGE                       ...   PORTS
xxxxxxxxxxxx   localstack/localstack:3.0   ...   0.0.0.0:4566->4566/tcp
{"services": { ... }}
```

![.evidence of LocalStack running](./.evidence/localstack-container-and-health.png)

## AWS CLI Configuration

The following are LocalStack-only dummy credentials. They do not grant access to an AWS account and must not be replaced with real credentials for this lab.

Configure the default AWS CLI profile:

```bash
aws configure set aws_access_key_id test
aws configure set aws_secret_access_key test
aws configure set default.region us-east-1
aws configure set default.output json
```

Confirm the settings:

```bash
aws configure list
```

Expected output resembles:

```text
      Name                    Value             Type    Location
      ----                    -----             ----    --------
   access_key     ****************test      config-file    ~/.aws/credentials
   secret_key     ****************test      config-file    ~/.aws/credentials
       region                us-east-1      config-file    ~/.aws/config
```

Test the configured CLI against LocalStack, explicitly directing the request to the local endpoint:

```bash
aws --endpoint-url=http://localhost:4566 sts get-caller-identity
```

Expected output resembles:

```json
{
  "UserId": "...",
  "Account": "000000000000",
  "Arn": "arn:aws:iam::000000000000:root"
}
```

![.evidence of AWS CLI LocalStack configuration](./.evidence/aws-cli-localstack-sts.png)
