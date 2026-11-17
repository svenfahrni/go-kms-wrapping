// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/miekg/pkcs11"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/keybuilder"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/session"
	"github.com/openbao/go-kms-wrapping/v2/kms"
	"github.com/stretchr/testify/require"
)

func TestOAEP(t *testing.T) {
	ctx := t.Context()
	svc := NewTestKMS(t)

	// Generate an RSA key:
	label := rand.Text()
	require.NoError(t, svc.pool.Scope(ctx, func(s *session.Handle) error {
		_, _, err := s.GenerateKeyPair(keybuilder.RSA(4096).Label(label).Build())
		return err
	}))

	hashes := []string{"default", "sha1", "sha224", "sha256", "sha384", "sha512"}
	if svc.token.Info.ManufacturerID == "SoftHSM project" {
		// SoftHSM only supports OAEP over SHA-1, special case it here.
		hashes = []string{"sha1"}
	}

	roundtrip := func(t *testing.T, key kms.Key) {
		t.Helper()
		input := []byte("foobar")
		ciphertext, err := key.Encrypt(ctx, &kms.CipherOptions{Data: input})
		require.NoError(t, err)
		require.NotEmpty(t, ciphertext)
		require.NotEqual(t, input, ciphertext)
		plaintext, err := key.Decrypt(ctx, &kms.CipherOptions{Data: ciphertext})
		require.NoError(t, err)
		require.Equal(t, input, plaintext)
	}

	for name, config := range map[string]kms.ConfigMap{
		"software": {
			"disable_software_encryption": false,
		},
		"hardware": {
			"disable_software_encryption": true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			for _, hash := range hashes {
				t.Run(hash, func(t *testing.T) {
					svc := NewTestKMS(t, config)
					// Retrieve the key via GetKey from a KMS with above
					// parameters set:
					config := kms.ConfigMap{"label": label}
					if hash != "default" {
						config["rsa_oaep_hash"] = hash
					}
					key, err := svc.GetKey(ctx, &kms.KeyOptions{ConfigMap: config})
					require.NoError(t, err)
					require.IsType(t, &rsaKey{}, key)
					roundtrip(t, key)
				})
			}
		})
	}
}

func TestPSS(t *testing.T) {
	ctx := t.Context()
	svc := NewTestKMS(t)

	// Generate an RSA key:
	label := rand.Text()
	require.NoError(t, svc.pool.Scope(ctx, func(s *session.Handle) error {
		_, _, err := s.GenerateKeyPair(keybuilder.RSA(4096).Label(label).Build())
		return err
	}))

	// Retrieve it via GetKey:
	key, err := svc.GetKey(ctx, &kms.KeyOptions{
		ConfigMap: kms.ConfigMap{"label": label},
	})
	require.NoError(t, err)
	require.IsType(t, &rsaKey{}, key)

	hashes := map[crypto.Hash]x509.SignatureAlgorithm{
		crypto.SHA256: x509.SHA256WithRSAPSS,
		crypto.SHA384: x509.SHA384WithRSAPSS,
		crypto.SHA512: x509.SHA512WithRSAPSS,
	}

	for hash, algo := range hashes {
		t.Run(hash.String(), func(t *testing.T) {
			t.Run("Sign+Verify", func(t *testing.T) {
				opts := &rsa.PSSOptions{
					Hash:       hash,
					SaltLength: rsa.PSSSaltLengthAuto,
				}

				h := hash.New()
				_, _ = h.Write([]byte("foo"))
				digest := h.Sum(nil)

				// Plain message:
				o := &kms.SignOptions{
					Data:       []byte("foo"),
					SignerOpts: opts,
				}
				signature, err := key.Sign(ctx, o)
				require.NoError(t, err)
				require.NotEmpty(t, signature)
				require.NoError(t, key.Verify(ctx, &kms.VerifyOptions{
					Data:       o.Data,
					SignerOpts: opts,
					Signature:  signature,
				}))

				// Pre-hashed:
				o = &kms.SignOptions{
					Data:       digest,
					Prehashed:  true,
					SignerOpts: opts,
				}
				signature, err = key.Sign(ctx, o)
				require.NoError(t, err)
				require.NotEmpty(t, signature)
				require.NoError(t, key.Verify(ctx, &kms.VerifyOptions{
					Data:       o.Data,
					Prehashed:  true,
					SignerOpts: o.SignerOpts,
					Signature:  signature,
				}))
			})

			t.Run("x509", func(t *testing.T) {
				signer, err := kms.NewSigner(ctx, key)
				require.NoError(t, err)
				template := &x509.Certificate{
					IsCA:                  true,
					BasicConstraintsValid: true,
					SignatureAlgorithm:    algo,
				}
				certBytes, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
				require.NoError(t, err)
				cert, err := x509.ParseCertificate(certBytes)
				require.NoError(t, err)
				err = cert.CheckSignatureFrom(cert)
				require.NoError(t, err)
			})
		})
	}
}

func TestPKCS1v15(t *testing.T) {
	ctx := t.Context()
	svc := NewTestKMS(t)

	label := rand.Text()
	require.NoError(t, svc.pool.Scope(ctx, func(s *session.Handle) error {
		_, _, err := s.GenerateKeyPair(keybuilder.RSA(2048).Label(label).Build())
		return err
	}))

	for _, mechanism := range []string{"", "CKM_RSA_PKCS"} {
		name := mechanism
		if name == "" {
			name = "unpinned"
		}
		t.Run(name, func(t *testing.T) {
			config := kms.ConfigMap{"label": label}
			if mechanism != "" {
				config["mechanism"] = mechanism
			}
			key, err := svc.GetKey(ctx, &kms.KeyOptions{ConfigMap: config})
			require.NoError(t, err)
			public, err := key.ExportPublic(ctx)
			require.NoError(t, err)
			pub := public.(*rsa.PublicKey)

			for _, hash := range []crypto.Hash{crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
				t.Run(hash.String(), func(t *testing.T) {
					message := []byte("PKCS#1 v1.5 signing")
					h := hash.New()
					_, _ = h.Write(message)
					digest := h.Sum(nil)

					signature, err := key.Sign(ctx, &kms.SignOptions{
						Data:       message,
						SignerOpts: hash,
					})
					require.NoError(t, err)
					require.Len(t, signature, pub.Size())
					// Check the token's DigestInfo encoding against the standard
					// library, independently of the provider's Verify method.
					require.NoError(t, rsa.VerifyPKCS1v15(pub, hash, digest, signature))
					require.NoError(t, key.Verify(ctx, &kms.VerifyOptions{
						Data:       message,
						SignerOpts: hash,
						Signature:  signature,
					}))

					prehashed, err := key.Sign(ctx, &kms.SignOptions{
						Data:       digest,
						Prehashed:  true,
						SignerOpts: hash,
					})
					require.NoError(t, err)
					// PKCS#1 v1.5 signatures are deterministic.
					require.Equal(t, signature, prehashed)
					require.NoError(t, key.Verify(ctx, &kms.VerifyOptions{
						Data:       digest,
						Prehashed:  true,
						SignerOpts: hash,
						Signature:  prehashed,
					}))

					t.Run("invalid signatures", func(t *testing.T) {
						altered := append([]byte(nil), signature...)
						altered[len(altered)-1] ^= 1
						for _, bad := range [][]byte{nil, signature[:len(signature)-1], altered} {
							require.ErrorIs(t, key.Verify(ctx, &kms.VerifyOptions{
								Data:       message,
								SignerOpts: hash,
								Signature:  bad,
							}), kms.ErrInvalidSignature)
						}
						require.ErrorIs(t, key.Verify(ctx, &kms.VerifyOptions{
							Data:       []byte("changed message"),
							SignerOpts: hash,
							Signature:  signature,
						}), kms.ErrInvalidSignature)
						for _, length := range []int{0, hash.Size() - 1, hash.Size() + 1} {
							require.Error(t, key.Verify(ctx, &kms.VerifyOptions{
								Data:       make([]byte, length),
								Prehashed:  true,
								SignerOpts: hash,
								Signature:  signature,
							}))
						}
					})
				})
			}

			for _, algorithm := range []x509.SignatureAlgorithm{x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA} {
				t.Run(algorithm.String(), func(t *testing.T) {
					signer, err := kms.NewSigner(ctx, key)
					require.NoError(t, err)
					template := &x509.Certificate{
						IsCA:                  true,
						BasicConstraintsValid: true,
						SignatureAlgorithm:    algorithm,
					}
					der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
					require.NoError(t, err)
					cert, err := x509.ParseCertificate(der)
					require.NoError(t, err)
					require.NoError(t, cert.CheckSignatureFrom(cert))
				})
			}
		})
	}
}

func TestRSASignInvalidOptions(t *testing.T) {
	// A missing pool ensures invalid inputs are rejected before a token call.
	key := &rsaKey{}
	for _, pss := range []bool{false, true} {
		t.Run(fmt.Sprintf("PSS=%t", pss), func(t *testing.T) {
			optsForHash := func(hash crypto.Hash) crypto.SignerOpts {
				if pss {
					return &rsa.PSSOptions{Hash: hash}
				}
				return hash
			}
			for _, hash := range []crypto.Hash{0, crypto.MD5, crypto.SHA1, crypto.SHA512_256} {
				t.Run(hash.String(), func(t *testing.T) {
					_, err := key.Sign(t.Context(), &kms.SignOptions{
						Data:       []byte("message"),
						SignerOpts: optsForHash(hash),
					})
					require.Error(t, err)
				})
			}
			for _, hash := range []crypto.Hash{crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
				for _, length := range []int{0, hash.Size() - 1, hash.Size() + 1} {
					t.Run(fmt.Sprintf("%s/%d", hash, length), func(t *testing.T) {
						_, err := key.Sign(t.Context(), &kms.SignOptions{
							Data:       make([]byte, length),
							Prehashed:  true,
							SignerOpts: optsForHash(hash),
						})
						require.Error(t, err)
					})
				}
			}
		})
	}
}

func TestRSAMechanismMismatch(t *testing.T) {
	for _, tt := range []struct {
		name string
		mech uint
		opts crypto.SignerOpts
	}{
		{"PSS rejects PKCS1v15", pkcs11.CKM_RSA_PKCS_PSS, crypto.SHA256},
		{"PKCS1v15 rejects PSS", pkcs11.CKM_RSA_PKCS, &rsa.PSSOptions{Hash: crypto.SHA256}},
		{"OAEP rejects PKCS1v15", pkcs11.CKM_RSA_PKCS_OAEP, crypto.SHA256},
		{"OAEP rejects PSS", pkcs11.CKM_RSA_PKCS_OAEP, &rsa.PSSOptions{Hash: crypto.SHA256}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			key := &rsaKey{mech: &tt.mech}
			_, err := key.Sign(t.Context(), &kms.SignOptions{SignerOpts: tt.opts})
			require.Error(t, err)
			require.Error(t, key.Verify(t.Context(), &kms.VerifyOptions{SignerOpts: tt.opts}))
		})
	}
}
