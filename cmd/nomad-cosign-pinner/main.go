package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio/fulcioroots"
	"github.com/sigstore/cosign/cmd/cosign/cli/verify"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/payload"
)

type githubCertVerifier struct {
	trustedRepoRefs map[string]map[string]struct{}
}

func newGithubCertVerifier() *githubCertVerifier {
	return &githubCertVerifier{
		trustedRepoRefs: map[string]map[string]struct{}{},
	}
}

func (v *githubCertVerifier) AddTrusted(repo string, ref string) {
	if _, ok := v.trustedRepoRefs[repo]; !ok {
		v.trustedRepoRefs[repo] = map[string]struct{}{}
	}

	v.trustedRepoRefs[repo][ref] = struct{}{}
}

func (v *githubCertVerifier) repoRefCertIsTrusted(repo string, ref string) bool {
	if m, ok := v.trustedRepoRefs[repo]; ok {
		_, ok := m[ref]
		return ok
	}
	return false
}

const githubIssuerURI = "https://token.actions.githubusercontent.com"
const githubRepoBasePath = "https://github.com/"

func (v *githubCertVerifier) CertIsTrusted(cert *x509.Certificate) bool {
	issuerURL := signature.CertIssuerExtension(cert)
	if issuerURL != githubIssuerURI {
		return false
	}

	subject := signature.CertSubject(cert)
	subjParts := strings.Split(subject, "@")
	if len(subjParts) != 2 {
		return false
	}
	workflowURI := subjParts[0]
	ref := subjParts[1]

	if !strings.HasPrefix(workflowURI, githubRepoBasePath) {
		return false
	}
	workflowPath := strings.TrimPrefix(workflowURI, githubRepoBasePath)
	pathParts := strings.Split(workflowPath, "/")
	if len(pathParts) < 2 {
		return false
	}
	repo := strings.Join(pathParts[:2], "/")

	if !v.repoRefCertIsTrusted(repo, ref) {
		return false
	}

	return true
}

type ociRefResolver struct {
	co         *cosign.CheckOpts
	ghVerifier *githubCertVerifier
}

func newOCIRefResolver(co *cosign.CheckOpts, ghVerifier *githubCertVerifier) *ociRefResolver {
	return &ociRefResolver{
		co:         co,
		ghVerifier: ghVerifier,
	}
}

func (r *ociRefResolver) resolve(imgRef string) (digestedImg string, trusted bool, err error) {
	ref, err := name.ParseReference(imgRef)
	if err != nil {
		return "", false, err
	}

	sigs, bundleVerified, err := cosign.VerifyImageSignatures(context.Background(), ref, r.co)
	if err != nil {
		return "", false, err
	}

	verify.PrintVerificationHeader(imgRef, r.co, bundleVerified)
	if !bundleVerified {
		return "", false, nil
	}

	var trustedSig *oci.Signature
	for _, sig := range sigs {
		cert, err := sig.Cert()
		if err != nil {
			return "", false, err
		}

		if r.ghVerifier.CertIsTrusted(cert) {
			trustedSig = &sig
			break
		}
	}

	if trustedSig == nil {
		return "", false, nil
	}

	b, err := (*trustedSig).Payload()
	if err != nil {
		return "", false, err
	}

	p := &payload.SimpleContainerImage{}
	err = json.Unmarshal(b, p)
	if err != nil {
		return "", false, err
	}

	digest := p.Critical.Image.DockerManifestDigest
	digestedImg = imgRef
	if !strings.HasSuffix(imgRef, "@"+digest) {
		digestedImg += "@" + digest
	}

	return digestedImg, true, nil
}

func getStringLiteral(expr *hclwrite.Expression) (t *hclwrite.Token, ok bool) {
	tokens := expr.BuildTokens(hclwrite.Tokens{})
	ok = len(tokens) == 3 && tokens[0].Type == hclsyntax.TokenOQuote && tokens[1].Type == hclsyntax.TokenQuotedLit && tokens[2].Type == hclsyntax.TokenCQuote
	if !ok {
		return nil, false
	}
	return tokens[1], true
}

func rewriteFile(file string, resolver *ociRefResolver) ([]byte, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("error reading file %q: %w", file, err)
	}

	conf, diags := hclwrite.ParseConfig(b, "", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil, fmt.Errorf("file %q has errors %s", diags)
	}

	for _, block := range conf.Body().Blocks() {
		if block.Type() != "job" {
			continue
		}

		for _, block := range block.Body().Blocks() {
			if block.Type() != "group" {
				continue
			}

			for _, block := range block.Body().Blocks() {
				if block.Type() != "task" {
					continue
				}

				for _, block := range block.Body().Blocks() {
					if block.Type() != "config" {
						continue
					}

					body := block.Body()
					attr := body.GetAttribute("image")
					if attr == nil {
						continue
					}

					litToken, ok := getStringLiteral((*attr).Expr())
					if !ok {
						return nil, fmt.Errorf("image must be a quoted string literal (file: %v)", file)
					}

					img := string(litToken.Bytes)
					digestedImg, trusted, err := resolver.resolve(img)
					if err != nil {
						return nil, fmt.Errorf("error resolving image %v: %w", img, err)
					}
					if !trusted {
						return nil, fmt.Errorf("image %v is not trusted (file: %v)", img, file)
					}
					litToken.Bytes = []byte(digestedImg)
					log.Printf("[%v] Pinned verified hash: %v", file, digestedImg)
				}
			}
		}
	}

	return conf.Bytes(), nil
}

var fileName = flag.String("file", "", "Nomad HCL file to translate")
var trustedGHRepoRefs = flag.String("trusted-gh-repo-refs", "", "comma-separated list of <repo>@<ref> that are trusted to build images")

func main() {
	flag.Parse()

	if *fileName == "" {
		log.Fatal("--file is required")
	}

	if *trustedGHRepoRefs == "" {
		log.Fatal("--trusted-gh-repo-refs is required")
	}

	co := &cosign.CheckOpts{
		RootCerts:     fulcioroots.Get(),
		ClaimVerifier: cosign.SimpleClaimVerifier,
	}

	ghVerifier := newGithubCertVerifier()

	for _, rr := range strings.Split(*trustedGHRepoRefs, ",") {
		parts := strings.Split(rr, "@")
		if len(parts) != 2 {
			log.Fatalf("invalid repo ref %q, expected \"<repo>@<ref>\"", rr)
		}
		repo := parts[0]
		ref := parts[1]
		ghVerifier.AddTrusted(repo, ref)
	}

	r := newOCIRefResolver(co, ghVerifier)

	rewritten, err := rewriteFile(*fileName, r)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(string(rewritten))
	return
}
