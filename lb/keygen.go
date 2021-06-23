package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/klauspost/compress/gzhttp"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
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

func genCert(crtPath string, keyPath string, org string, countryCode string, province string, locality string, zipcode string, isCertificateAuthority bool, fqdn string, orgUnit string, streetAddress string, ipAddress string) {
	// priv, err := rsa.GenerateKey(rand.Reader, *rsaBits)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		l.Fatal(err.Error())
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(int64(time.Now().Year())),
		Subject: pkix.Name{
			Country:            []string{countryCode},
			Organization:       []string{org},
			OrganizationalUnit: []string{orgUnit},
			Locality:           []string{locality},
			Province:           []string{province},
			StreetAddress:      []string{streetAddress},
			PostalCode:         []string{zipcode},
			CommonName:         fqdn,
		},
		IPAddresses: []net.IP{
			net.ParseIP(ipAddress),
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Hour * 24 * 1460),
		IsCA:        isCertificateAuthority,
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{fqdn},
	}

	crt, err := os.OpenFile(crtPath, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
	if err != nil {
		l.Printf("Error creating certificate file: %s\n", err.Error())
		panic(err.Error())
	}
	var trustPathCrt string
	if isCertificateAuthority == true {
		trustPathCrt = "/etc/pki/ca-trust/source/anchors/"
	} else {
		trustPathCrt = "/etc/pki/tls/certs/"
	}
	trustStoreCrt, err := os.OpenFile(trustPathCrt+fqdn+".crt", os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
	if err != nil {
		l.Printf("Error creating certificate file: %s\n", err.Error())
		panic(err.Error())
	}
	trustStoreKey, err := os.OpenFile("/etc/pki/tls/private/"+fqdn+".key", os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0400)
	key, err := os.OpenFile(keyPath, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0640)
	if err != nil {
		l.Printf("Error creating certificate file: %s\n", err.Error())
		panic(err.Error())
	}
	err = os.Chown(keyPath, os.Getuid(), os.Getegid())
	if err != nil {
		l.Printf("Error changing ownership of keyfile: %s\n", err.Error())
		panic(err.Error())
	}
	err = os.Chown(crtPath, os.Getuid(), os.Getegid())
	if err != nil {
		l.Printf("Error changing ownership of certificate: %s\n", err.Error())
		panic(err.Error())
	}
	err = os.Chown(trustPathCrt+fqdn+".crt", os.Getuid(), os.Getegid())
	if err != nil {
		l.Printf("Error changing certificate ownership in local trust store: %s\n", err.Error())
		panic(err.Error())
	}
	err = os.Chown("/etc/pki/tls/private/"+fqdn+".key", os.Getuid(), os.Getegid())
	if err != nil {
		l.Printf("Error changing ownership of private TLS key: %s\n", err.Error())
		panic(err.Error())
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		l.Printf("Failed to create certificate: %s", err.Error())
		panic(err.Error())
	}

	mw := io.MultiWriter(crt, trustStoreCrt, l.Writer())
	out := &bytes.Buffer{}
	err = pem.Encode(mw, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		l.Printf("Error encoding certificate: %s\n", err.Error())
		panic(err.Error())
	}

	l.Println(out.String())
	out.Reset()
	kw := io.MultiWriter(trustStoreKey, key)
	err = pem.Encode(kw, pemBlockForKey(priv))
	if err != nil {
		l.Printf("Error encoding PEM key: %s\n", err.Error())
		panic(err.Error())
	}
	_, err = exec.Command("/usr/bin/update-ca-trust", "extract").Output()
	if err != nil {
		l.Printf("Error updating ca trust: %s\n", err.Error())
		panic(err.Error())
	}

}

func sendCert(w http.ResponseWriter, r *http.Request) {
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		l.Printf("Error reading body bytes: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var t int
	if len(ConfigFile.MasterKey) >= 32 {
		t = 32
	} else if len(ConfigFile.MasterKey) <= 32 && len(ConfigFile.MasterKey) >= 24 {
		t = 24
	} else if len(ConfigFile.MasterKey) <= 24 && len(ConfigFile.MasterKey) >= 16 {
		t = 16
	}

	key := []byte(ConfigFile.MasterKey[:t])

	enc := bodyBytes
	block, err := aes.NewCipher(key)
	if err != nil {
		l.Printf("Error creating new AES cipher block: %s\n", err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		l.Printf("Error creating new aesGCM cipher block: %s\n", err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	nonceSize := aesGCM.NonceSize()
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		l.Printf("Error decrypting authphrase: %s\n", err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if string(plaintext) != "K{eR8]:pP:$z}xSogwQ(tzjK#=io_6M:yT;fFdNrbL%Ce*}K[XO>;r[G" {
		l.Printf("Authphrase not accepted.")
		w.WriteHeader(http.StatusUnauthorized)
		return
	} else if string(plaintext) == "K{eR8]:pP:$z}xSogwQ(tzjK#=io_6M:yT;fFdNrbL%Ce*}K[XO>;r[G" {
		cert, err := ioutil.ReadFile("/etc/gammabyte/lsapi/lb.crt")
		if err != nil {
			l.Printf("Error reading certificate from file: %s\n", err.Error())
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, err = fmt.Fprint(w, string(cert))
		if err != nil {
			l.Printf("Error returning certificate to client: %s\n", err.Error())
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		r.Body.Close()
		time.Sleep(3 * time.Second)
		err = getClientCert("https://" + r.Header.Get("hostname") + ":" + r.Header.Get("listenport") + "/api/getcert")
		if err != nil {
			l.Printf("Error getting client certificate: %s\n", err.Error())
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
}

func getClientCert(url string) error {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:            rootCAs,
			InsecureSkipVerify: true,
			KeyLogWriter:       l.Writer(),
		},
	}
	client1 := &http.Client{
		Transport: gzhttp.Transport(transport),
	}
	l.Printf("Host certificate URL: %s\n", url)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		l.Printf("Error creating new HTTP request: %s\n", err.Error())
		return err
	}
	resp, err := client1.Do(req)
	//resp, err := client.Do("https://"+r.Header.Get("hostname")+":"+r.Header.Get("listenport")+"/api/getcert")
	if err != nil {
		l.Printf("Error getting client cert: %s\n", err.Error())
		return err
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		l.Printf("Error reading response body: %s\n", err.Error())
		return err
	}
	rootCAs.AppendCertsFromPEM(bodyBytes)

	return err
}
