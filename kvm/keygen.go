package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"
)

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

func genCert() {
	// priv, err := rsa.GenerateKey(rand.Reader, *rsaBits)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		l.Fatal(err.Error())
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"GammaByte.xyz"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 1460),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	/*
	   hosts := strings.Split(*host, ",")
	   for _, h := range hosts {
	   	if ip := net.ParseIP(h); ip != nil {
	   		template.IPAddresses = append(template.IPAddresses, ip)
	   	} else {
	   		template.DNSNames = append(template.DNSNames, h)
	   	}
	   }
	   if *isCA {
	   	template.IsCA = true
	   	template.KeyUsage |= x509.KeyUsageCertSign
	   }
	*/

	crt, err := os.OpenFile("/etc/gammabyte/lsapi/lsapi-kvm.crt", os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
	key, err := os.OpenFile("/etc/gammabyte/lsapi/lsapi-kvm.key", os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0640)
	err = os.Chown("/etc/gammabyte/lsapi/lsapi-kvm.key", os.Getuid(), os.Getegid())
	if err != nil {
		panic(err.Error())
		return
	}
	err = os.Chown("/etc/gammabyte/lsapi/lsapi-kvm.crt", os.Getuid(), os.Getegid())
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		l.Fatalf("Failed to create certificate: %s", err)
	}

	mw := io.MultiWriter(crt, l.Writer())
	out := &bytes.Buffer{}
	err = pem.Encode(mw, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		panic(err.Error())
	}

	l.Println(out.String())
	out.Reset()
	err = pem.Encode(key, pemBlockForKey(priv))
	if err != nil {
		panic(err.Error())
	}

	//l.Println(out.String())
}
