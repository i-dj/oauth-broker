package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var ErrInvalidSignature = errors.New("invalid device signature")

type DeviceAuthRequest struct {
	DeviceID  string `json:"device_id" binding:"required"`
	Nonce     string `json:"nonce" binding:"required"`
	Timestamp int64  `json:"timestamp" binding:"required"`
	Signature string `json:"signature" binding:"required"`
}

func SignedPayload(deviceID, nonce string, timestamp int64) []byte {
	return []byte(deviceID + "\n" + nonce + "\n" + strconv.FormatInt(timestamp, 10))
}

func VerifyDeviceSignature(publicKeyPEM string, req DeviceAuthRequest, skew time.Duration) error {
	if skew <= 0 {
		skew = 5 * time.Minute
	}
	requestTime := time.Unix(req.Timestamp, 0).UTC()
	now := time.Now().UTC()
	if requestTime.Before(now.Add(-skew)) || requestTime.After(now.Add(skew)) {
		return fmt.Errorf("timestamp outside allowed clock skew")
	}
	signature, err := decodeSignature(req.Signature)
	if err != nil {
		return err
	}
	publicKey, err := parsePublicKey(publicKeyPEM)
	if err != nil {
		return err
	}
	payload := SignedPayload(req.DeviceID, req.Nonce, req.Timestamp)
	digest := sha256.Sum256(payload)
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err == nil {
			return nil
		}
		return rsa.VerifyPSS(key, crypto.SHA256, digest[:], signature, nil)
	case *ecdsa.PublicKey:
		if ecdsa.VerifyASN1(key, digest[:], signature) {
			return nil
		}
		return ErrInvalidSignature
	case ed25519.PublicKey:
		if ed25519.Verify(key, payload, signature) {
			return nil
		}
		return ErrInvalidSignature
	default:
		return errors.New("unsupported public key type")
	}
}

func ValidatePublicKey(publicKeyPEM string) error {
	_, err := parsePublicKey(publicKeyPEM)
	return err
}

func parsePublicKey(publicKeyPEM string) (any, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("invalid public key PEM")
	}
	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return key, nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err == nil {
		return cert.PublicKey, nil
	}
	return nil, errors.New("unsupported public key PEM")
}

func decodeSignature(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, ErrInvalidSignature
	}
	if decoded, err := base64.RawURLEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.URLEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return nil, ErrInvalidSignature
}
