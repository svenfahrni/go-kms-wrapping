// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/miekg/pkcs11"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/session"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

// newRSA constructs a new rsaKey.
func newRSA(
	pool *session.PoolRef,
	public, private object,
	mech *uint,
	oaepHash crypto.Hash,
	disableSoftwareEncryption bool,
) (kms.Key, error) {
	if mech != nil {
		switch *mech {
		// pkcs11.CKM_SHA{X}_RSA_PKCS_PSS variants can be added in the future if
		// there is desire for remote message hashing.
		case pkcs11.CKM_RSA_PKCS, pkcs11.CKM_RSA_PKCS_PSS, pkcs11.CKM_RSA_PKCS_OAEP:
		default:
			return nil, fmt.Errorf("unsupported RSA key mechanism: %x", *mech)
		}
	}

	exportPublic := onceOrCancel(func(ctx context.Context) (*rsa.PublicKey, error) {
		temp := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
		}
		attr, err := session.Scope(ctx, pool, func(s *session.Handle) ([]*pkcs11.Attribute, error) {
			// RSA keys have all params available on the public key, too. This
			// seems like the less invasive object to query.
			return s.GetAttributeValue(public.handle, temp)
		})
		if err != nil {
			return nil, fmt.Errorf("export public key: %w", err)
		}
		n := new(big.Int).SetBytes(attr[0].Value)
		e := new(big.Int).SetBytes(attr[1].Value)
		// Sanity checks
		switch {
		case n.Cmp(big.NewInt(1)) != 1:
			err = errors.New("modulus is less than one")
		case e.Cmp(big.NewInt(1)) != 1:
			err = errors.New("exponent is less than one")
		case n.Cmp(e) != 1:
			err = errors.New("modulus is not greater than exponent")
		case e.BitLen() > 32:
			err = errors.New("exponent is longer than 32 bits")
		case n.BitLen() < 2048:
			err = errors.New("modulus is shorter than 2048 bits")
		}
		if err != nil {
			return nil, fmt.Errorf("export public key: %w", err)
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	})

	return &rsaKey{
		pool:                      pool,
		pubHandle:                 public.handle,
		prvHandle:                 private.handle,
		public:                    exportPublic,
		mech:                      mech,
		oaepHash:                  oaepHash,
		disableSoftwareEncryption: disableSoftwareEncryption,
	}, nil
}

// rsaKey wraps keys of type CKK_RSA.
type rsaKey struct {
	kms.UnimplementedKey

	pool      *session.PoolRef
	pubHandle pkcs11.ObjectHandle
	prvHandle pkcs11.ObjectHandle

	// Exported public key.
	public func(context.Context) (*rsa.PublicKey, error)

	// Optionally pinned mechanism to use for all operations.
	mech *uint

	// The hash to use in RSA-OAEP mode.
	oaepHash crypto.Hash

	// Whether to disable performing RSA-OAEP encryption in software.
	disableSoftwareEncryption bool
}

var rsaLookup = map[crypto.Hash]struct {
	hash, mgf uint
	oid       asn1.ObjectIdentifier
}{
	crypto.SHA1:   {pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1, asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}},
	crypto.SHA224: {pkcs11.CKM_SHA224, pkcs11.CKG_MGF1_SHA224, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}},
	crypto.SHA256: {pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}},
	crypto.SHA384: {pkcs11.CKM_SHA384, pkcs11.CKG_MGF1_SHA384, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}},
	crypto.SHA512: {pkcs11.CKM_SHA512, pkcs11.CKG_MGF1_SHA512, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}},
}

func (r *rsaKey) Encrypt(ctx context.Context, opts *kms.CipherOptions) ([]byte, error) {
	// Check for pinned mechanism:
	if r.mech != nil && *r.mech != pkcs11.CKM_RSA_PKCS_OAEP {
		return nil, fmt.Errorf("unsupported mode: %x", *r.mech)
	}

	if !r.disableSoftwareEncryption {
		pub, err := r.public(ctx)
		if err != nil {
			return nil, err
		}
		return rsa.EncryptOAEP(r.oaepHash.New(), rand.Reader, pub, opts.Data, nil)
	}

	hashMechs := rsaLookup[r.oaepHash]
	mech := pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP,
		pkcs11.NewOAEPParams(hashMechs.hash, hashMechs.mgf, pkcs11.CKZ_DATA_SPECIFIED, nil))

	return session.Scope(ctx, r.pool, func(s *session.Handle) ([]byte, error) {
		if err := s.EncryptInit(mech, r.pubHandle); err != nil {
			return nil, err
		}
		return s.Encrypt(opts.Data)
	})
}

func (r *rsaKey) Decrypt(ctx context.Context, opts *kms.CipherOptions) ([]byte, error) {
	// Check for pinned mechanism:
	if r.mech != nil && *r.mech != pkcs11.CKM_RSA_PKCS_OAEP {
		return nil, fmt.Errorf("unsupported mode: %x", *r.mech)
	}

	hashMechs := rsaLookup[r.oaepHash]
	mech := pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP,
		pkcs11.NewOAEPParams(hashMechs.hash, hashMechs.mgf, pkcs11.CKZ_DATA_SPECIFIED, nil))

	return session.Scope(ctx, r.pool, func(s *session.Handle) ([]byte, error) {
		if err := s.DecryptInit(mech, r.prvHandle); err != nil {
			return nil, err
		}
		return s.Decrypt(opts.Data)
	})
}

func (r *rsaKey) Sign(ctx context.Context, opts *kms.SignOptions) ([]byte, error) {
	// Check for pinned mechanism:
	mechanism := rsaSigningMechanism(opts.SignerOpts)
	if r.mech != nil && *r.mech != mechanism {
		return nil, fmt.Errorf("unsupported scheme: %x", *r.mech)
	}

	hash := opts.HashFunc()
	hashMechs, ok := rsaLookup[hash]
	switch {
	case !ok:
		return nil, fmt.Errorf("unsupported hash function: %s", hash)
	case hashMechs.hash == pkcs11.CKM_SHA_1:
		// SHA-1 is supported via OAEP for compatibility with the PKCS#11 seal
		// wrapper, but there's no reason to allow its usage for signing.
		return nil, errors.New("SHA-1 signing is unsupported")
	}

	mech := pkcs11.NewMechanism(mechanism, nil)
	switch o := opts.SignerOpts.(type) {
	case *rsa.PSSOptions:
		switch o.SaltLength {
		case rsa.PSSSaltLengthAuto, rsa.PSSSaltLengthEqualsHash:
		default:
			return nil, errors.New("custom PSS salt lengths are not supported")
		}
		mech = pkcs11.NewMechanism(mechanism,
			pkcs11.NewPSSParams(hashMechs.hash, hashMechs.mgf, uint(hash.Size())))
	}

	data := opts.Data
	if !opts.Prehashed {
		h := opts.HashFunc().New()
		_, _ = h.Write(data)
		data = h.Sum(nil)
	}
	if len(data) != hash.Size() {
		return nil, errors.New("input must be hashed with the specified hash function")
	}

	if mechanism == pkcs11.CKM_RSA_PKCS {
		// CKM_RSA_PKCS adds the PKCS#1 v1.5 padding, but expects the caller
		// to encode the digest and its algorithm as a DER DigestInfo.
		var err error
		data, err = asn1.Marshal(struct {
			Algorithm pkix.AlgorithmIdentifier
			Digest    []byte
		}{
			Algorithm: pkix.AlgorithmIdentifier{
				Algorithm:  hashMechs.oid,
				Parameters: asn1.NullRawValue,
			},
			Digest: data,
		})
		if err != nil {
			return nil, fmt.Errorf("encode DigestInfo: %w", err)
		}
	}

	return session.Scope(ctx, r.pool, func(s *session.Handle) ([]byte, error) {
		if err := s.SignInit(mech, r.prvHandle); err != nil {
			return nil, err
		}
		return s.Sign(data)
	})
}

func (r *rsaKey) Verify(ctx context.Context, opts *kms.VerifyOptions) error {
	// Check for pinned mechanism:
	if r.mech != nil && *r.mech != rsaSigningMechanism(opts.SignerOpts) {
		return fmt.Errorf("unsupported scheme: %x", *r.mech)
	}

	hash := opts.HashFunc()
	// We don't actually need this lookup to use software verification below,
	// but it guards us from using bad hash functions that can't be constructed.
	if _, ok := rsaLookup[hash]; !ok {
		return fmt.Errorf("unsupported hash function: %s", hash)
	}

	data := opts.Data
	if !opts.Prehashed {
		h := opts.HashFunc().New()
		_, _ = h.Write(data)
		data = h.Sum(nil)
	}

	pub, err := r.public(ctx)
	if err != nil {
		return err
	}

	switch o := opts.SignerOpts.(type) {
	case *rsa.PSSOptions:
		if err := rsa.VerifyPSS(pub, opts.HashFunc(), data, opts.Signature, o); err != nil {
			return fmt.Errorf("%w: %w", kms.ErrInvalidSignature, err)
		}
	default:
		if err := rsa.VerifyPKCS1v15(pub, hash, data, opts.Signature); err != nil {
			return fmt.Errorf("%w: %w", kms.ErrInvalidSignature, err)
		}
	}

	return nil
}

func rsaSigningMechanism(opts crypto.SignerOpts) uint {
	if _, ok := opts.(*rsa.PSSOptions); ok {
		return pkcs11.CKM_RSA_PKCS_PSS
	}
	return pkcs11.CKM_RSA_PKCS
}

func (r *rsaKey) ExportPublic(ctx context.Context) (crypto.PublicKey, error) {
	return r.public(ctx)
}
