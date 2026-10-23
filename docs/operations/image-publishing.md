# Image publishing

The metering image is built by `.github/workflows/publish.yaml` on every push
to `main` and pushed to:

```text
quay.io/modden/enmaas-metering-service
```

This is an **interim personal namespace** owned by `@mrodden`. It remains in
place until the Konflux-based build and deployment path is ready. Moving to an
org-owned Quay repository later requires changing the workflow `IMAGE` value,
updating the GitHub Actions secrets, and updating the staging/prod cluster pull
secret.

## Ownership

- Quay repository: `quay.io/modden/enmaas-metering-service`
- Owner: Mathew Odden (`@mrodden`)
- Intended long-term target: an org-owned Quay repository or a Konflux-built
  image

The personal namespace is an interim build path, not a production
supply-chain boundary. Production deployments must pin the digest from an
approved workflow run.

## Credentials

Two separate robot accounts are used:

- **Build/push:** one repository-scoped robot per image repository, with
  `Write` permission and no broader access. The `enmaas-metering-service`
  builder credentials are stored only as the `QUAY_USERNAME` and `QUAY_TOKEN`
  GitHub Actions repository secrets and are used only by this workflow.
- **Pull:** one separate read-only robot with `Read` permission on the related
  EnMaaS image repositories. Its credentials are stored only in the cluster
  pull secrets. It is not used by CI.

The workflow passes the builder credentials through step-level environment
variables and `docker login --password-stdin`; secrets are never interpolated
into the generated shell script.

## Rotation

Rotate a credential immediately if it is exposed or a maintainer with access
leaves, and otherwise on a regular schedule (at least every 90 days).

1. Create a replacement robot token in Quay with the same scope.
2. Update the single location that holds the old credential:
   - builder: the `QUAY_USERNAME` and `QUAY_TOKEN` repository secrets;
   - pull: the cluster pull secrets.
3. Run the publish workflow and verify the image pushes, or verify a test pod
   can pull the image.
4. Revoke the old robot token.

## Release and consumption policy

- Every push to `main` produces a development image:
  - `:main` is a mutable convenience tag.
  - `:sha-<full 40-character commit SHA>` identifies the build for that commit.
- Tags are convenience pointers. The image digest is the immutable reference.
- The workflow pushes the full-SHA image and records
  `quay.io/modden/enmaas-metering-service@sha256:...` plus the source commit in
  the Actions run summary before moving `:main`. That digest is the
  authoritative deployment reference.
- Deploy by digest. Never deploy `:main`.
- Promotion is explicit: build on `main`, validate the digest in staging, then
  update the digest pin in the EnMaaS deployment configuration for staging and
  production.
- Version tags and signed provenance attestations are deferred until the
  Konflux-based build migration. The OCI source, revision, and version labels
  provide traceability metadata only; they are not a signature.
- Publishing is gated on `go test ./...` and `go vet ./...`.
