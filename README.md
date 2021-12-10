# Nomad `cosign` Pinner

This is a hacky proof-of-concept for adding container image integrity checks to
the Nomad ecosystem. Please don't use this for anything real.

[Cosign](https://github.com/sigstore/cosign) is a tool for signing and
verifying container images. The Cosign project includes `cosigned`, an example
Kubernetes admission webhook that verifies container image signatures using
Cosign when Pods or higher level resources are created or modified.

This goal of this proof-of-concept is to see if we can add similar integrity
controls to [Nomad](https://www.nomadproject.io/). The catch is that Nomad does
not have anything like admission controllers yet. There is no natural place to
integrate signature verification when Nomad jobs are created or modified.

In this demo, we use `hclwrite` to statically rewrite Nomad job specifications
with pinned, Cosign-verified digests added to image refs. This isn't quite
comparable to an admission controller, but it does automate image signature
validation pre-deploy. This method allows you to use tags in job specifications
and receive minor patches (updated digests) each time you re-run the tool and
re-deploy without manually looking up digests or validating signatures.

## Usage

We build and push an image in `.github/workflows/example-app.yml` using `ko`.
We sign it using `cosign`, backed by Fulcio with GitHub Actions OIDC tokens.

```bash
# Run the Nomad dev agent.
nomad agent -dev

# Verify signatures for images in example.nomad, and pin trusted hashes.
# The --trusted-gh-repo-refs flag specifies GitHub repos that we trust to sign images.
go run cmd/nomad-cosign-pinner/main.go \
  --file example.nomad \
  --trusted-gh-repo-refs ethanal/nomad-cosign-pinner@refs/heads/main \
  > example_pinned.nomad
# Verification for ghcr.io/ethanal/example-app:v0.0.1 --
# The following checks were performed on each of these signatures:
#   - The cosign claims were validated
#   - Existence of the claims in the transparency log was verified offline
#   - Any certificates were verified against the Fulcio roots.
# main.go:210: [example.nomad] Pinned verified hash: ghcr.io/ethanal/example-app:v0.0.1@sha256:9aa51f658cb78bf14a48b904dd651556204fc7c0afaa1fe77a7f0375ac1ad82c

# Inspect the diff between the original and modified job spec.
diff example.nomad example_pinned.nomad
# 17c17
# <         image = "ghcr.io/ethanal/example-app:v0.0.1"
# ---
# >         image = "ghcr.io/ethanal/example-app:v0.0.1@sha256:9aa51f658cb78bf14a48b904dd651556204fc7c0afaa1fe77a7f0375ac1ad82c"

# Run the Nomad job with pinned hashes.
NOMAD_ADDR=http://localhost:4646 nomad run example_pinned.nomad

# Test the app.
curl http://localhost:8080/
# Hello world :)
```

## Shortcomings
`hclwrite` can not evaluate expressions, so unless images are specified as
string literals, the static rewriting is not possible.
