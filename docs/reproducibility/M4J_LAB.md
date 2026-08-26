# Running Aegis-OT

This guide provides two executable paths. The Docker path is the shortest way
to exercise the system. The six-host M4j path is the deployment-assurance lab
and requires a compatible VirtualBox host.

## Fast local Docker path

Docker with Compose and Buildx is the only host prerequisite for this path.
From a clean checkout:

```bash
docker compose up --build -d
docker compose ps
curl --fail --silent http://127.0.0.1:8080/health
curl --fail --silent http://127.0.0.1:8081/health
docker compose --profile experiment run --rm agent-probe
docker compose down
```

The probe exercises one permitted action and the registered replay, unsafe
action, and direct-network-bypass denials. A successful run is local,
single-Docker-host implementation evidence against the synthetic plant. It is
not a six-host result, physical-PLC evidence, independent validation, or a
production deployment.

## Six-host M4j lab

The current contract uses the pinned `generic/ubuntu2204` 4.3.12 VirtualBox
box, six VMs, 12 vCPUs, and at most 18 GiB of guest memory. Use an x86-64 host
with Vagrant, VirtualBox, Docker with Buildx, Python 3.11 or newer, and enough
capacity for that envelope. Apple Silicon is not a validated executor for the
current pinned Vagrant box. Network access is required to acquire the pinned
box, authenticated Ubuntu packages, and exact-digest container images.

The commands below are intentionally explicit. Replace every angle-bracketed
value with an absolute path or reviewed hash. Keep all generated identities,
secrets, bundles, SSH material, and evidence in one current-user-owned mode-0700
directory outside the checkout.

### 1. Install the controller environment and validate the contracts

```bash
install -d -m 700 <PRIVATE_OPERATOR_ROOT>
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev,simulation]"
python -m venv <PRIVATE_OPERATOR_ROOT>/ansible-2.19.12
<PRIVATE_OPERATOR_ROOT>/ansible-2.19.12/bin/python -m pip install ansible-core==2.19.12
PYTHONPATH=src .venv/bin/python scripts/validate_m4j_deployment.py --check
PYTHONPATH=src .venv/bin/python scripts/validate_m4j_workloads.py --check-contract
PYTHONPATH=src .venv/bin/python scripts/run_m4j_acceptance.py --plan
git status --short
git rev-parse HEAD
```

Stop if `git status --short` prints anything. Record the full commit ID. Use
`sha256sum` on Linux or `shasum -a 256` on macOS to review and record the exact
Vagrant, `ansible-playbook`, Docker client, and Docker Buildx executable hashes.

### 2. Create and provision the six VMs with exact package pins

```bash
PYTHONPATH=src .venv/bin/python scripts/prepare_m4j_package_pins.py \
  --vagrant <ABSOLUTE_VAGRANT_EXECUTABLE> \
  --vagrant-sha256 <VAGRANT_SHA256> \
  --ansible-playbook <PRIVATE_OPERATOR_ROOT>/ansible-2.19.12/bin/ansible-playbook \
  --ansible-playbook-sha256 <ANSIBLE_PLAYBOOK_SHA256> \
  --output <PRIVATE_OPERATOR_ROOT>/m4j-package-pins.env \
  --provision

PYTHONPATH=src .venv/bin/python scripts/prepare_m4j_ssh_transport.py \
  --source-commit <FULL_COMMIT> \
  --output <PRIVATE_OPERATOR_ROOT>/ssh-transport
```

The package-pin helper starts the pinned VMs without provisioning, obtains the
authenticated candidate versions and APT-source manifests from all six roles,
requires exact agreement, and only then provisions. The SSH helper consumes
the per-VM Ed25519 host keys exported through that local Vagrant provisioning
channel. This establishes local lab trust, not independently validated host
identity.

### 3. Establish and review the local builder boundary

```bash
PYTHONPATH=src .venv/bin/python scripts/prepare_m4j_builder_identity.py \
  --output <PRIVATE_OPERATOR_ROOT>/builder-authority

PYTHONPATH=src .venv/bin/python scripts/build_m4j_bundle.py \
  --inspect-builder-profile \
  --docker-client <ABSOLUTE_DOCKER_EXECUTABLE> \
  --docker-client-sha256 <DOCKER_SHA256> \
  --docker-buildx-plugin <ABSOLUTE_DOCKER_BUILDX_EXECUTABLE> \
  --docker-buildx-plugin-sha256 <DOCKER_BUILDX_SHA256> \
  --docker-socket <ABSOLUTE_PROTECTED_DOCKER_UNIX_SOCKET>
```

Review the returned daemon, BuildKit worker, platform, executable hashes,
endpoint, and trust statement separately from the build. Record its
`profile_sha256`; do not automatically learn and trust a profile inside the
same build operation.

### 4. Build the exact-source inputs

```bash
PYTHONPATH=src .venv/bin/python scripts/build_m4j_bundle.py \
  --output <PRIVATE_OPERATOR_ROOT>/application-bundle \
  --commit <FULL_COMMIT> \
  --builder-signing-key <PRIVATE_OPERATOR_ROOT>/builder-authority/builder.private \
  --docker-client <ABSOLUTE_DOCKER_EXECUTABLE> \
  --docker-client-sha256 <DOCKER_SHA256> \
  --docker-buildx-plugin <ABSOLUTE_DOCKER_BUILDX_EXECUTABLE> \
  --docker-buildx-plugin-sha256 <DOCKER_BUILDX_SHA256> \
  --docker-socket <ABSOLUTE_PROTECTED_DOCKER_UNIX_SOCKET> \
  --expected-builder-profile-sha256 <REVIEWED_PROFILE_SHA256>

PYTHONPATH=src .venv/bin/python scripts/prepare_m4j_runtime_images.py \
  --output <PRIVATE_OPERATOR_ROOT>/runtime-images \
  --pull

PYTHONPATH=src .venv/bin/python scripts/prepare_m4j_secrets.py \
  --source-commit <FULL_COMMIT> \
  --output <PRIVATE_OPERATOR_ROOT>/deployment-secrets
```

The application bundle is signed by the local operator-configured builder
authority. Its signature and reviewed profile bind exact source and output
identity, but the profiled Docker daemon and BuildKit worker remain trusted
components; this is not independent or hermetic build provenance.

### 5. Plan, apply, probe, and retain the local result

Run the deployment command once without `--apply` and inspect its canonical
plan. Then repeat it with the apply/probe arguments shown below:

```bash
PYTHONPATH=src .venv/bin/python scripts/deploy_m4j_workloads.py \
  --source-commit <FULL_COMMIT> \
  --bundle <PRIVATE_OPERATOR_ROOT>/application-bundle \
  --runtime-images <PRIVATE_OPERATOR_ROOT>/runtime-images \
  --secrets <PRIVATE_OPERATOR_ROOT>/deployment-secrets \
  --builder-trusted-public-key <PRIVATE_OPERATOR_ROOT>/builder-authority/builder.public \
  --expected-builder-profile-sha256 <REVIEWED_PROFILE_SHA256>

PYTHONPATH=src .venv/bin/python scripts/deploy_m4j_workloads.py \
  --source-commit <FULL_COMMIT> \
  --bundle <PRIVATE_OPERATOR_ROOT>/application-bundle \
  --runtime-images <PRIVATE_OPERATOR_ROOT>/runtime-images \
  --secrets <PRIVATE_OPERATOR_ROOT>/deployment-secrets \
  --builder-trusted-public-key <PRIVATE_OPERATOR_ROOT>/builder-authority/builder.public \
  --expected-builder-profile-sha256 <REVIEWED_PROFILE_SHA256> \
  --known-hosts <PRIVATE_OPERATOR_ROOT>/ssh-transport/known_hosts \
  --ansible-playbook <PRIVATE_OPERATOR_ROOT>/ansible-2.19.12/bin/ansible-playbook \
  --ansible-playbook-sha256 <ANSIBLE_PLAYBOOK_SHA256> \
  --apply \
  --probe \
  --probe-output <PRIVATE_OPERATOR_ROOT>/m4j-live-probe.json \
  --probe-signing-key <PRIVATE_OPERATOR_ROOT>/builder-authority/builder.private \
  --probe-trusted-public-key <PRIVATE_OPERATOR_ROOT>/builder-authority/builder.public

PYTHONPATH=src .venv/bin/python scripts/run_m4j_acceptance.py \
  --live \
  --output <PRIVATE_OPERATOR_ROOT>/m4j-network-acceptance \
  --ssh-config <PRIVATE_OPERATOR_ROOT>/ssh-transport/ssh_config \
  --known-hosts <PRIVATE_OPERATOR_ROOT>/ssh-transport/known_hosts
```

Using the same local key for builder and controller-probe signatures is a
bounded lab convenience. Use separately governed trust anchors when identity
separation or independent custody is part of the evaluation objective.

An accepted local run establishes only the checks recorded by the signed
two-phase workload probe and six-VM network campaign for that exact commit,
input set, and host. It does not establish physical-system effectiveness,
hostile-hypervisor resistance, external qualification, production readiness,
or independent replication.

Author: Angelis Pseftis
