package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/jcmturner/golick/licence"
)

const appTitle = "Go licence generator"

var buildhash = "Not set"
var buildtime = "Not set"
var version = "Not set"

func ver() (string, string, time.Time) {
	bt, _ := time.Parse(time.RFC3339, buildtime)
	return version, buildhash, bt
}

// versionStr returns the version number, hash from git and the time of the build in a pretty formatted string.
func versionStr() string {
	v, bh, bt := ver()
	return fmt.Sprintf("%s Version Information:\nVersion:\t%s\nBuild hash:\t%s\nBuild time:\t%v\n", appTitle, v, bh, bt)
}

func main() {
	keyPath := flag.String("key", "", "Path to private key file")
	v := flag.Bool("version", false, "Print version information")
	d := flag.Int64("duration", 0, "Duration in days of licence from now")
	m := flag.Int64("maxcount", 0, "Max count for licence coverage")
	r := flag.Int64("runduration", 0, "Duration in minutes the licence will enable the service to run for. Typically for trial usage.")
	i := flag.String("init", "", "Initialise licencing key pair at the path provided")
	flag.Parse()

	// Print version information and exit.
	if *v {
		fmt.Fprintln(os.Stderr, versionStr())
		os.Exit(0)
	}

	if *i != "" {
		pvt, pub, err := initLicKeyPair(*i)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating key pair: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Private key: %s\nPublic key: %s\n", pvt, pub)
		os.Exit(0)
	}

	if *keyPath == "" {
		fmt.Fprintln(os.Stderr, "Private key path not specified.")
		os.Exit(1)
	}

	keyFile, err := os.Open(*keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not access private key: %v\n", err)
		os.Exit(1)
	}
	key, err := loadPvtKey(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not load private key: %v", err)
		os.Exit(1)
	}

	var l *licence.Licence
	if *r > 0 {
		mins := time.Duration(*r) * time.Minute
		l, err = licence.NewRunPeriod(key, mins, *m)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not generate licence: %v\n", err)
			os.Exit(1)
		}
	} else {
		if *d <= 0 {
			fmt.Fprintln(os.Stderr, "Duration must be a positive integer.")
			os.Exit(1)
		}
		days := time.Duration(*d)
		l, err = licence.New(key, time.Now().UTC(), time.Now().UTC().Add(time.Hour*24*days), *m)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not generate licence: %v\n", err)
			os.Exit(1)
		}
	}
	lk, err := l.String()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not generate key string: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("%s\nKey:\n%s\n", l.Print(), lk)
}

func loadPvtKey(r io.Reader) (*rsa.PrivateKey, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	der, err := hex.DecodeString(string(b))
	return x509.ParsePKCS1PrivateKey(der)
}

func initLicKeyPair(path string) (string, string, error) {
	pair, _ := rsa.GenerateKey(rand.Reader, 2048)

	pubbytes := x509.MarshalPKCS1PublicKey(pair.Public().(*rsa.PublicKey))
	pvtbytes := x509.MarshalPKCS1PrivateKey(pair)

	u, err := uuid.GenerateUUID()
	if err != nil {
		return "", "", err
	}
	path = strings.TrimRight(path, "/") + "/"
	pvtPath := path + u + ".key"
	pubPath := path + u + ".pub"

	pvtFile, err := os.Create(pvtPath)
	if err != nil {
		return "", "", err
	}
	err = pvtFile.Chmod(0600)
	if err != nil {
		return "", "", err
	}
	_, err = pvtFile.WriteString(hex.EncodeToString(pvtbytes))
	if err != nil {
		return "", "", err
	}

	pubFile, err := os.Create(pubPath)
	if err != nil {
		return "", "", err
	}
	err = pubFile.Chmod(0644)
	if err != nil {
		return "", "", err
	}
	_, err = pubFile.WriteString(hex.EncodeToString(pubbytes))
	if err != nil {
		return "", "", err
	}
	return pvtFile.Name(), pubFile.Name(), nil
}
