// Copyright 2020 Hewlett Packard Enterprise Development LP


package hms_certs

import (
	"bytes"
	"log"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"encoding/json"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"
	"github.com/sirupsen/logrus"
	"stash.us.cray.com/HMS/hms-base"
)


var cbCalled = false
var globalT  *testing.T
var expStatusG  = http.StatusOK

var k8sTokenFilename = "/tmp/k8stoken"
var k8sTestToken = `xyzzy1234`
var vaultTestToken = `aabbccdd`
var cachainFilename = "/tmp/ca_chain.crt"

var cannedCAChain = `-----BEGIN CERTIFICATE-----\nxxx\n-----END CERTIFICATE-----`
var cannedVaultCertData = VaultCertData{RequestID:     "AAAA",
                                        LeaseID:       "BBBB",
                                        Renewable:     false,
                                        LeaseDuration: 1234,
                                        Data: CertInfo{CAChain: []string{"-----BEGIN CERTIFICATE-----\nCCCC\n-----END CERTIFICATE-----","-----BEGIN CERFICATE-----\nDDDD\n-----END CERTIFICATE-----",},
                                                       Certificate:    "-----BEGIN CERTIFICATE-----\nEEEE\n-----END_CERTIFICATE-----",
                                                       Expiration:     5678,
                                                       IssuingCA:      "FFFF",
                                                       PrivateKey:     "-----BEGIN RSA PRIVATE KEY-----\nGGGG\n-----END RSA PRIVATE KEY-----",
                                                       PrivateKeyType: "rsa",
                                                       FQDN: ".aaa.com",
                                                       SerialNumber:   "JJJJ",},
}



func vaultTokenHandler(w http.ResponseWriter, req *http.Request) {
	//Verify the correct POST payload
	exp := `{"jwt":"` + k8sTestToken + `","role":"pki-common-direct"}`
	body,berr := ioutil.ReadAll(req.Body)
	if (berr != nil) {
		log.Printf("ERROR reading request body: %v",berr)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if (string(body) != exp) {
		log.Printf("ERROR mismatch in POST payload, exp: '%s', got: '%s'",
			exp,string(body))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//Return the canned vault token

	var jdata vaultTokStuff
	jdata.Auth.ClientToken = vaultTestToken
	ba,baerr := json.Marshal(&jdata)
	if (baerr != nil) {
		log.Printf("ERROR marshalling vault token payload: %v",baerr)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type","application/json")
	w.Write(ba)
}

func pkiCertHandler(w http.ResponseWriter, req *http.Request) {
	//Verify the header has the correct vault token
	hstr,ok := req.Header["X-Vault-Token"]
	if (!ok) {
		log.Printf("ERROR, X-Vault-Token missing from headers.")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if (hstr[0] != vaultTestToken) {
		log.Printf("ERROR, header X-Vault-Token mismatch, exp: '%s', got: '%s'",
			vaultTestToken,hstr[0])
		w.WriteHeader(http.StatusInternalServerError)
		return
	}


	//Generate response payload

	ba,berr := json.Marshal(&cannedVaultCertData)
	if (berr != nil) {
		log.Printf("ERROR marshalling canned vault cert data: %v",berr)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type","application/json")
	w.Write(ba)
}


func pkiCAChainHandler(w http.ResponseWriter, req *http.Request) {
	//Verify the header has the correct vault token
	hstr,ok := req.Header["X-Vault-Token"]
	if (!ok) {
		log.Printf("ERROR, X-Vault-Token missing from headers.")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if (hstr[0] != vaultTestToken) {
		log.Printf("ERROR, header X-Vault-Token mismatch, exp: '%s', got: '%s'",
			vaultTestToken,hstr[0])
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(cannedCAChain))
}

func genericHandler(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(expStatusG)
	w.Write([]byte(`{"Status":"OK"}`))
}


func setEnviron(t *testing.T) {
	__vaultEnabled = false
	os.Setenv("VAULT_ENABLE","0")
	os.Setenv("CRAY_VAULT_JWT_FILE",k8sTokenFilename)
	os.Setenv("CRAY_VAULT_ROLE_FILE",k8sTokenFilename)

	err := ioutil.WriteFile(k8sTokenFilename,[]byte(k8sTestToken),0666)
	if (err != nil) {
		t.Errorf("Error, can't write token file '%s'.",k8sTokenFilename)
	}
	os.Chmod(k8sTokenFilename,0666)
	ConfigParams.LogInsecureFailover = true
}


func TestGetHTTPClient(t *testing.T) {
	client := getHTTPClient()
	if (client == nil) {
		t.Errorf("Client is nil.")
	}
	client2 := getHTTPClient()
	if (client != client2) {
		t.Errorf("Clients are not the same.")
	}
}


func TestGetVaultToken(t *testing.T) {
	setEnviron(t)

	testServer := httptest.NewServer(http.HandlerFunc(vaultTokenHandler))
	defer testServer.Close()
	ConfigParams.K8SAuthUrl = testServer.URL
	tok,tokErr := getVaultToken()
	if (tokErr != nil) {
		t.Errorf("Error in getVaultToken(): %v",tokErr)
	}
	if (tok != vaultTestToken) {
		t.Errorf("Mismatch in vault token, exp: '%s', got: '%s'",
			vaultTestToken,tok)
	}
}

func TestGenAllDomainAltNames(t *testing.T) {
	var dnames,rnames string
	var eps []string
	var err error

	//Generate cabinet strings

	prefix := "x0"
	eps = append(eps,fmt.Sprintf("%sc0",prefix))
	for slot := 0; slot < 4; slot ++ {
		eps = append(eps,fmt.Sprintf("%sm%d",prefix,slot))
		eps = append(eps,fmt.Sprintf("%sm%d-rts",prefix,slot))
	}
	for slot := 0; slot < maxRVChassisSlot; slot ++ {
		for bmc := 0; bmc < maxSlotBMC; bmc ++ {
			eps = append(eps,fmt.Sprintf("%sc0s%db%d",prefix,slot,bmc))
			eps = append(eps,fmt.Sprintf("%sc0r%db%d",prefix,slot,bmc))
		}
	}
	for chassis := 1; chassis < maxCabChassis; chassis ++ {
		eps = append(eps,fmt.Sprintf("%sc%d",prefix,chassis))
		for slot := 0; slot < maxChassisSlot; slot ++ {
			for bmc := 0; bmc < maxSlotBMC; bmc ++ {
				eps = append(eps,fmt.Sprintf("%sc%ds%db%d",
						prefix,chassis,slot,bmc))
				eps = append(eps,fmt.Sprintf("%sc%dr%db%d",
						prefix,chassis,slot,bmc))
			}
		}
	}

	for _,ep := range(eps) {
		if (strings.Contains(ep,"-rts")) {
			continue
		}
		if (base.GetHMSTypeString(ep) == "") {
			t.Errorf("Invalid XName: '%s'",ep)
		}
	}

	dnames = strings.Join(eps,",")
	rnames,err = genAllDomainAltNames("x0",CertDomainCabinet)
	if (err != nil) {
		t.Errorf("Error generting cabinet alt names: %v",err)
	}
	if (dnames != rnames) {
		t.Errorf("Mismatch of cab names, exp: '%s', got: '%s'",
			dnames,rnames)
	}

	//Chassis 0
	eps = []string{}
	prefix = "x0c0"
	for slot := 0; slot < maxRVChassisSlot; slot ++ {
		for bmc := 0; bmc < maxSlotBMC; bmc ++ {
			eps = append(eps,fmt.Sprintf("%ss%db%d",prefix,slot,bmc))
			eps = append(eps,fmt.Sprintf("%sr%db%d",prefix,slot,bmc))
		}
	}
	dnames = strings.Join(eps,",")
	rnames,err = genAllDomainAltNames(prefix,CertDomainChassis)
	if (err != nil) {
		t.Errorf("Error generting chassis 0 alt names: %v",err)
	}
	if (dnames != rnames) {
		t.Errorf("Mismatch of chassis 0 names, exp: '%s', got: '%s'",
			dnames,rnames)
	}

	//Chassis 1
	eps = []string{}
	prefix = "x0c1"
	for slot := 0; slot < maxChassisSlot; slot ++ {
		for bmc := 0; bmc < maxSlotBMC; bmc ++ {
			eps = append(eps,fmt.Sprintf("%ss%db%d",prefix,slot,bmc))
			eps = append(eps,fmt.Sprintf("%sr%db%d",prefix,slot,bmc))
		}
	}
	dnames = strings.Join(eps,",")
	rnames,err = genAllDomainAltNames(prefix,CertDomainChassis)
	if (err != nil) {
		t.Errorf("Error generting chassis 1 alt names: %v",err)
	}
	if (dnames != rnames) {
		t.Errorf("Mismatch of chassis 1 names, exp: '%s', got: '%s'",
			dnames,rnames)
	}

	//Blade level

	eps = []string{}
	prefix = "x0c1s2"
	for bmc := 0; bmc < maxSlotBMC; bmc ++ {
		eps = append(eps,fmt.Sprintf("%sb%d",prefix,bmc))
	}
	dnames = strings.Join(eps,",")
	rnames,err = genAllDomainAltNames(prefix,CertDomainBlade)
	if (err != nil) {
		t.Errorf("Error generting compute blade  alt names: %v",err)
	}
	if (dnames != rnames) {
		t.Errorf("Mismatch of compute blade names, exp: '%s', got: '%s'",
			dnames,rnames)
	}

	eps = []string{}
	prefix = "x0c1r2"
	for bmc := 0; bmc < maxSlotBMC; bmc ++ {
		eps = append(eps,fmt.Sprintf("%sb%d",prefix,bmc))
	}
	dnames = strings.Join(eps,",")
	rnames,err = genAllDomainAltNames(prefix,CertDomainBlade)
	if (err != nil) {
		t.Errorf("Error generting switch blade alt names: %v",err)
	}
	if (dnames != rnames) {
		t.Errorf("Mismatch of switch blade names, exp: '%s', got: '%s'",
			dnames,rnames)
	}

	//BMC level

	eps = []string{}
	prefix = "x0c1s2b0"
	dnames = prefix
	rnames,err = genAllDomainAltNames(prefix,CertDomainBMC)
	if (err != nil) {
		t.Errorf("Error generting BMC alt names: %v",err)
	}
	if (dnames != rnames) {
		t.Errorf("Mismatch of BMC names, exp: '%s', got: '%s'",
			dnames,rnames)
	}

	//Error cases

	prefix = "x0"
	rnames,err = genAllDomainAltNames(prefix,CertDomainChassis)
	if (err == nil) {
		t.Errorf("Expected error with bad chassis prefix 'x0', didn't see one.")
	}

	rnames,err = genAllDomainAltNames(prefix,"xyzzy")
	if (err == nil) {
		t.Errorf("Expected error with bad domain name 'xyzzy', didn't see one.")
	}
}

func TestCheckDomain(t *testing.T) {
	var err error
	var domName string

	//Single cabinet, OK

	eps := []string{"x0"}
	domName,err = CheckDomain(eps,CertDomainCabinet)
	if (err != nil) {
		t.Errorf("Unexpeced error in cab CheckDomain(): %v",err)
	}
	if (domName != "x0") {
		t.Errorf("Mismatch cab domain name, exp: 'x0', got: '%s'",domName)
	}

	//All within a cabinet, OK
	eps = []string{"x0c0s0b0","x0c0s1b0","x0c1s2b1"}
	domName,err = CheckDomain(eps,CertDomainCabinet)
	if (err != nil) {
		t.Errorf("Unexpeced error in cab CheckDomain(): %v",err)
	}
	if (domName != "x0") {
		t.Errorf("Mismatch cab domain name, exp: 'x0', got: '%s'",domName)
	}

	//Not all in cab, not OK
	eps = []string{"x0c0s0b0","x1c0s1b0"}
	domName,err = CheckDomain(eps,CertDomainCabinet)
	if (err == nil) {
		t.Errorf("Expeced error in cab CheckDomain(), didn't see one.")
	}

	//All within a chassis, OK
	eps = []string{"x0c0s0b0","x0c0s1b0","x0c0s2b1"}
	domName,err = CheckDomain(eps,CertDomainChassis)
	if (err != nil) {
		t.Errorf("Unexpeced error in chassis CheckDomain(): %v",err)
	}
	if (domName != "x0c0") {
		t.Errorf("Mismatch chassis domain name, exp: 'x0', got: '%s'",domName)
	}

	//Not all in chassis, not OK
	eps = []string{"x0c0s0b0","x0c1s1b0"}
	domName,err = CheckDomain(eps,CertDomainChassis)
	if (err == nil) {
		t.Errorf("Expeced error in chassis CheckDomain(), didn't see one.")
	}

	//Not all in cab, not OK
	eps = []string{"x0c0s0b0","x1c0s1b0"}
	domName,err = CheckDomain(eps,CertDomainChassis)
	if (err == nil) {
		t.Errorf("Expeced error in chassis CheckDomain(), didn't see one.")
	}

	//All within a blade, OK
	eps = []string{"x0c0s0b0","x0c0s0b1","x0c0s0b2"}
	domName,err = CheckDomain(eps,CertDomainBlade)
	if (err != nil) {
		t.Errorf("Unexpeced error in blade CheckDomain(): %v",err)
	}
	if (domName != "x0c0s0") {
		t.Errorf("Mismatch blade domain name, exp: 'x0c0s0', got: '%s'",domName)
	}

	//Not all in blade, not OK
	eps = []string{"x0c0s0b0","x0c0s1b0"}
	domName,err = CheckDomain(eps,CertDomainBlade)
	if (err == nil) {
		t.Errorf("Expeced error in blade CheckDomain(), didn't see one.")
	}

	//Not all in chassis, not OK
	eps = []string{"x0c0s0b0","x0c1s0b1"}
	domName,err = CheckDomain(eps,CertDomainBlade)
	if (err == nil) {
		t.Errorf("Expeced error in blade CheckDomain(), didn't see one.")
	}

	//Not all in cab, not OK
	eps = []string{"x0c0s0b0","x1c0s0b1"}
	domName,err = CheckDomain(eps,CertDomainBlade)
	if (err == nil) {
		t.Errorf("Expected error in blade CheckDomain(), didn't see one.")
	}

	//All in BMC, OK
	eps = []string{"x0c1s2b0"}
	domName,err = CheckDomain(eps,CertDomainBMC)
	if (err != nil) {
		t.Errorf("Unexpeced error in BMC CheckDomain(): %v",err)
	}
	if (domName != "x0c1s2b0") {
		t.Errorf("Mismatch BMC domain name, exp: 'x0c1s2b0', got: '%s'",domName)
	}

	//Too many in BMC, not OK
	eps = []string{"x0c1s2b0","x0c1s2b1"}
	domName,err = CheckDomain(eps,CertDomainBMC)
	if (err == nil) {
		t.Errorf("Expected error in BMC CheckDomain() with multiple targs, didn't see one.")
	}

	//Bad domain

	domName,err = CheckDomain(eps,"xyzzy")
	if (err == nil) {
		t.Errorf("Expected error from bad domain, didn't see one.")
	}

	//Bad xname

	eps = []string{"xzc0sybd"}
	domName,err = CheckDomain(eps,CertDomainBlade)
	if (err == nil) {
		t.Errorf("Expected error from bad xname, didn't see one.")
	}
}


//NOTE: this function also test createTargCerts().

func TestCreateCert(t *testing.T) {
	var jdata VaultCertData

	setEnviron(t)

	//Set up test servers for vault token and vault PKI

	vtServer := httptest.NewServer(http.HandlerFunc(vaultTokenHandler))
	pkiServer := httptest.NewServer(http.HandlerFunc(pkiCertHandler))
	defer vtServer.Close()
	defer pkiServer.Close()
	ConfigParams.K8SAuthUrl = vtServer.URL
	ConfigParams.VaultPKIUrl = pkiServer.URL

	err := CreateCert([]string{"x0c0s0b0","x0c0s1b0"},CertDomainCabinet,"",&jdata)
	if (err != nil) {
		t.Errorf("ERROR CreateCert(): %v",err)
	}

	//Compare returned struct with canned one.

	if (jdata.RequestID != cannedVaultCertData.RequestID) {
		t.Errorf("Mismatch RequestID, exp: '%s', got: '%s'",
			jdata.RequestID,cannedVaultCertData.RequestID)
	}
	if (jdata.LeaseID != cannedVaultCertData.LeaseID) {
		t.Errorf("Mismatch LeaseID, exp: '%s', got: '%s'",
			jdata.LeaseID,cannedVaultCertData.LeaseID)
	}
	if (jdata.Renewable != cannedVaultCertData.Renewable) {
		t.Errorf("Mismatch Renewable, exp: %t, got: %t",
			jdata.Renewable,cannedVaultCertData.Renewable)
	}
	if (jdata.LeaseDuration != cannedVaultCertData.LeaseDuration) {
		t.Errorf("Mismatch LeaseDuration, exp: %d, got: %d",
			jdata.LeaseDuration,cannedVaultCertData.LeaseDuration)
	}
	if (len(jdata.Data.CAChain) == 0) {
		t.Errorf("CAChain is zero length, expecting >= 1.")
	}
	if ((len(jdata.Data.CAChain) > 0) && (jdata.Data.CAChain[0] != cannedVaultCertData.Data.CAChain[0])) {
		t.Errorf("Mismatch CAChain[0], exp: '%s', got: '%s'",
			jdata.Data.CAChain[0],cannedVaultCertData.Data.CAChain[0])
	}
	if (jdata.Data.Certificate != cannedVaultCertData.Data.Certificate) {
		t.Errorf("Mismatch Certificate, exp: '%s', got: '%s'",
			jdata.Data.Certificate,cannedVaultCertData.Data.Certificate)
	}
	if (jdata.Data.Expiration != cannedVaultCertData.Data.Expiration) {
		t.Errorf("Mismatch Expiration, exp: %d, got: %d",
			jdata.Data.Expiration,cannedVaultCertData.Data.Expiration)
	}
	if (jdata.Data.IssuingCA != cannedVaultCertData.Data.IssuingCA) {
		t.Errorf("Mismatch IssuingCA, exp: '%s', got: '%s'",
			jdata.Data.IssuingCA,cannedVaultCertData.Data.IssuingCA)
	}
	if (jdata.Data.PrivateKey != cannedVaultCertData.Data.PrivateKey) {
		t.Errorf("Mismatch PrivateKey, exp: '%s', got: '%s'",
			jdata.Data.PrivateKey,cannedVaultCertData.Data.PrivateKey)
	}
	if (jdata.Data.PrivateKeyType != cannedVaultCertData.Data.PrivateKeyType) {
		t.Errorf("Mismatch PrivateKeyType, exp: '%s', got: '%s'",
			jdata.Data.PrivateKeyType,cannedVaultCertData.Data.PrivateKeyType)
	}
	if (jdata.Data.SerialNumber != cannedVaultCertData.Data.SerialNumber) {
		t.Errorf("Mismatch SerialNumber, exp: '%s', got: '%s'",
			jdata.Data.SerialNumber,cannedVaultCertData.Data.SerialNumber)
	}

	//Same test but using a single cab name

	err = CreateCert([]string{"x0"},CertDomainCabinet,"",&jdata)
	if (err != nil) {
		t.Errorf("ERROR CreateCert(): %v",err)
	}

	//Compare returned struct with canned one.

	if (jdata.RequestID != cannedVaultCertData.RequestID) {
		t.Errorf("Mismatch RequestID, exp: '%s', got: '%s'",
			jdata.RequestID,cannedVaultCertData.RequestID)
	}
	if (jdata.LeaseID != cannedVaultCertData.LeaseID) {
		t.Errorf("Mismatch LeaseID, exp: '%s', got: '%s'",
			jdata.LeaseID,cannedVaultCertData.LeaseID)
	}
	if (jdata.Renewable != cannedVaultCertData.Renewable) {
		t.Errorf("Mismatch Renewable, exp: %t, got: %t",
			jdata.Renewable,cannedVaultCertData.Renewable)
	}
	if (jdata.LeaseDuration != cannedVaultCertData.LeaseDuration) {
		t.Errorf("Mismatch LeaseDuration, exp: %d, got: %d",
			jdata.LeaseDuration,cannedVaultCertData.LeaseDuration)
	}
	if (len(jdata.Data.CAChain) == 0) {
		t.Errorf("CAChain is zero length, expecting >= 1.")
	}
	if ((len(jdata.Data.CAChain) > 0) && (jdata.Data.CAChain[0] != cannedVaultCertData.Data.CAChain[0])) {
		t.Errorf("Mismatch CAChain[0], exp: '%s', got: '%s'",
			jdata.Data.CAChain[0],cannedVaultCertData.Data.CAChain[0])
	}
	if (jdata.Data.Certificate != cannedVaultCertData.Data.Certificate) {
		t.Errorf("Mismatch Certificate, exp: '%s', got: '%s'",
			jdata.Data.Certificate,cannedVaultCertData.Data.Certificate)
	}
	if (jdata.Data.Expiration != cannedVaultCertData.Data.Expiration) {
		t.Errorf("Mismatch Expiration, exp: %d, got: %d",
			jdata.Data.Expiration,cannedVaultCertData.Data.Expiration)
	}
	if (jdata.Data.IssuingCA != cannedVaultCertData.Data.IssuingCA) {
		t.Errorf("Mismatch IssuingCA, exp: '%s', got: '%s'",
			jdata.Data.IssuingCA,cannedVaultCertData.Data.IssuingCA)
	}
	if (jdata.Data.PrivateKey != cannedVaultCertData.Data.PrivateKey) {
		t.Errorf("Mismatch PrivateKey, exp: '%s', got: '%s'",
			jdata.Data.PrivateKey,cannedVaultCertData.Data.PrivateKey)
	}
	if (jdata.Data.PrivateKeyType != cannedVaultCertData.Data.PrivateKeyType) {
		t.Errorf("Mismatch PrivateKeyType, exp: '%s', got: '%s'",
			jdata.Data.PrivateKeyType,cannedVaultCertData.Data.PrivateKeyType)
	}
	if (jdata.Data.SerialNumber != cannedVaultCertData.Data.SerialNumber) {
		t.Errorf("Mismatch SerialNumber, exp: '%s', got: '%s'",
			jdata.Data.SerialNumber,cannedVaultCertData.Data.SerialNumber)
	}

	//Use a FQDN, multiple

	fqdn := ".aaa.com"
	err = CreateCert([]string{"x0c0s0b0","x0c0s1b0"},CertDomainCabinet,fqdn,&jdata)
	if (err != nil) {
		t.Errorf("ERROR CreateCert(): %v",err)
	}

	//Make sure the FQDN got through.

	if (jdata.Data.FQDN != fqdn) {
		t.Errorf("ERROR CreateCert(), FQDN mismatch, exp: '%s', got: '%s'",
			fqdn,jdata.Data.FQDN)
	}

	//Same test, single cab

	fqdn = "aaa.com"
	err = CreateCert([]string{"x0"},CertDomainCabinet,fqdn,&jdata)
	if (err != nil) {
		t.Errorf("ERROR CreateCert(): %v",err)
	}
	if (jdata.Data.FQDN != ("."+fqdn)) {
		t.Errorf("ERROR CreateCert(), FQDN mismatch, exp: '.%s', got: '%s'",
			fqdn,jdata.Data.FQDN)
	}
}

func createFakeCAChainCRT() error {
	ferr := ioutil.WriteFile(cachainFilename,[]byte(cannedCAChain),0777)
	if (ferr != nil) {
		return ferr
	}
	ferr = os.Chmod(cachainFilename,0777)
	if (ferr != nil) {
		return ferr
	}
	return nil
}


func TestFetchCAChain(t *testing.T) {
	setEnviron(t)
	vtServer := httptest.NewServer(http.HandlerFunc(vaultTokenHandler))
	caServer := httptest.NewServer(http.HandlerFunc(pkiCAChainHandler))
	defer vtServer.Close()
	defer caServer.Close()
	ConfigParams.K8SAuthUrl = vtServer.URL
	ConfigParams.VaultCAUrl = caServer.URL

	ferr := createFakeCAChainCRT()
	if (ferr != nil) {
		t.Errorf("ERROR creating fake CA chain CRT: %v",ferr)
	}

	chain,err := FetchCAChain("/tmp/ca_chain.crt")
	if (err != nil) {
		t.Errorf("ERROR fetching CA chain: %v",err)
	}
	if (chain != cannedCAChain) {
		t.Errorf("Mismatch in CA chain, exp: '%s', got: '%s'",
			cannedCAChain,chain)
	}
}

func TestNLTuple(t *testing.T) {
	withNL := 
`AAAA
BBBB
CCCC\nDDDD`
	withNLExp := `AAAA\nBBBB\nCCCC\nDDDD`
	withTuple := `WWWW\nXXXX\nYYYY\nZZZZ`
	withTupleExp := 
`WWWW
XXXX
YYYY
ZZZZ`

	str := NewlineToTuple(withNL)
	if (str != withNLExp) {
		t.Errorf("Mismatch NewlineToTuple(), exp: '%s', got: '%s'",
			withNLExp,str)
	}

	str = TupleToNewline(withTuple)
	if (str != withTupleExp) {
		t.Errorf("Mismatch TupleToNewline(), exp: '%s', got: '%s'",
			withTupleExp,str)
	}
}

//Only for coverage

func TestInit(t *testing.T) {
	Init(nil)
	Init(logrus.New())
}

func TestCreateHTTPClientPair(t *testing.T) {
	setEnviron(t)
	ferr := createFakeCAChainCRT()
	if (ferr != nil) {
		t.Errorf("ERROR creating fake CA Chain CRT: %v",ferr)
	}

	cpp,cerr := CreateHTTPClientPair(cachainFilename,3)
	if (cerr != nil) {
		t.Errorf("Error creating HTTP client pair: %v",cerr)
	}
	if (cpp == nil) {
		t.Errorf("ERROR: unexpecte nil HTTP client pair.")
	}
	if (cpp.SecureClient == nil) {
		t.Errorf("ERROR: unexpected nil secure client.")
	}
	if (cpp.InsecureClient == nil) {
		t.Errorf("ERROR: unexpected nil insecure client.")
	}
	t.Logf("Secure: SecC: %p, insecC: %p",cpp.SecureClient,cpp.InsecureClient)
	if (cpp.SecureClient == cpp.InsecureClient) {
		t.Errorf("ERROR: secure == insecure client with no CA URI.")
	}

	//Create client pair with no CA URI

	cpp,cerr = CreateHTTPClientPair("",3)
	if (cerr != nil) {
		t.Errorf("Error creating HTTP client pair: %v",cerr)
	}
	if (cpp == nil) {
		t.Errorf("ERROR: unexpecte nil HTTP client pair.")
	}
	if (cpp.SecureClient == nil) {
		t.Errorf("ERROR: unexpected nil secure client.")
	}
	if (cpp.InsecureClient == nil) {
		t.Errorf("ERROR: unexpected nil insecure client.")
	}
	t.Logf("Insecure: SecC: %p, insecC: %p",cpp.SecureClient,cpp.InsecureClient)
	if (cpp.SecureClient != cpp.InsecureClient) {
		t.Errorf("ERROR: secure != insecure client with no CA URI.")
	}
}

func TestHTTPPairOps(t *testing.T) {
	setEnviron(t)
	ferr := createFakeCAChainCRT()
	if (ferr != nil) {
		t.Errorf("ERROR creating fake CA Chain CRT: %v",ferr)
	}

	cpp,cerr := CreateHTTPClientPair(cachainFilename,3)
	if (cerr != nil) {
		t.Errorf("Error creating HTTP client pair: %v",cerr)
	}

	srv := httptest.NewServer(http.HandlerFunc(genericHandler))
	defer srv.Close()

	req,qerr := http.NewRequest("GET",srv.URL,nil)
	if (qerr != nil) {
		t.Fatalf("ERROR creating request: %v",qerr)
	}
	cpp.CloseIdleConnections()
	rsp,rerr := cpp.Do(req)
	if (rerr != nil) {
		t.Errorf("ERROR from Do(): %v",rerr)
	}
	if (rsp == nil) {
		t.Errorf("ERROR: Do() rsp is nil.")
	}
	if (cpp.FailedOver == true) {
		t.Errorf("Do() operation incorrectly failed over.")
	}

	rsp,rerr = cpp.Get(srv.URL)
	if (rerr != nil) {
		t.Errorf("ERROR from Get(): %v",rerr)
	}
	if (rsp == nil) {
		t.Errorf("ERROR: Get() rsp is nil.")
	}
	if (cpp.FailedOver == true) {
		t.Errorf("Get() operation incorrectly failed over.")
	}
	rsp,rerr = cpp.Head(srv.URL)
	if (rerr != nil) {
		t.Errorf("ERROR from Head(): %v",rerr)
	}
	if (rsp == nil) {
		t.Errorf("ERROR: Head() rsp is nil.")
	}
	if (cpp.FailedOver == true) {
		t.Errorf("Head() operation incorrectly failed over.")
	}

	rsp,rerr = cpp.Post(srv.URL, "application/json", bytes.NewBuffer([]byte(`{"Stuff":"things"}`)))
	if (rerr != nil) {
		t.Errorf("ERROR from Post(): %v",rerr)
	}
	if (rsp == nil) {
		t.Errorf("ERROR: Post() rsp is nil.")
	}
	if (cpp.FailedOver == true) {
		t.Errorf("Post() operation incorrectly failed over.")
	}

	rsp,rerr = cpp.PostForm(srv.URL, url.Values{})
	if (rerr != nil) {
		t.Errorf("ERROR from PostForm(): %v",rerr)
	}
	if (rsp == nil) {
		t.Errorf("ERROR: PostForm() rsp is nil.")
	}
	if (cpp.FailedOver == true) {
		t.Errorf("PostForm() operation incorrectly failed over.")
	}

	//Create ClientPair with no CA, test all funcs

	cpp,cerr = CreateHTTPClientPair("",3)
	if (cerr != nil) {
		t.Errorf("Error creating HTTP client pair: %v",cerr)
	}
	cpp.CloseIdleConnections()
	rsp,rerr = cpp.Do(req)
	if (rerr != nil) {
		t.Errorf("ERROR from Do(): %v",rerr)
	}
	if (rsp == nil) {
		t.Errorf("ERROR: Do() rsp is nil.")
	}
	if (cpp.FailedOver == true) {
		t.Errorf("Do() operation incorrectly failed over.")
	}

	rsp,rerr = cpp.Get(srv.URL)
	if (rerr != nil) {
		t.Errorf("ERROR from Get(): %v",rerr)
	}
	if (rsp == nil) {
		t.Errorf("ERROR: Get() rsp is nil.")
	}
	if (cpp.FailedOver == true) {
		t.Errorf("Get() operation incorrectly failed over.")
	}
	rsp,rerr = cpp.Head(srv.URL)
	if (rerr != nil) {
		t.Errorf("ERROR from Head(): %v",rerr)
	}
	if (rsp == nil) {
		t.Errorf("ERROR: Head() rsp is nil.")
	}
	if (cpp.FailedOver == true) {
		t.Errorf("Head() operation incorrectly failed over.")
	}

	rsp,rerr = cpp.Post(srv.URL, "application/json", bytes.NewBuffer([]byte(`{"Stuff":"things"}`)))
	if (rerr != nil) {
		t.Errorf("ERROR from Post(): %v",rerr)
	}
	if (rsp == nil) {
		t.Errorf("ERROR: Post() rsp is nil.")
	}
	if (cpp.FailedOver == true) {
		t.Errorf("Post() operation incorrectly failed over.")
	}

	rsp,rerr = cpp.PostForm(srv.URL, url.Values{})
	if (rerr != nil) {
		t.Errorf("ERROR from PostForm(): %v",rerr)
	}
	if (rsp == nil) {
		t.Errorf("ERROR: PostForm() rsp is nil.")
	}
	if (cpp.FailedOver == true) {
		t.Errorf("PostForm() operation incorrectly failed over.")
	}


	//Error conditions

	expStatusG = http.StatusBadRequest
	rsp,rerr = cpp.Get(srv.URL)
	if (rerr != nil) {
		t.Errorf("ERROR from Get(): %v",rerr)
	}
	if (rsp.StatusCode != http.StatusBadRequest) {
		t.Errorf("Bad return status from Get(): %d",rsp.StatusCode)
	}

	// Make secure client fail.  First, replace it with a bad URL

	expStatusG = http.StatusOK
	badURL := "http://bad.url.gub"
	breq,_ := http.NewRequest("GET",badURL,nil)
	rsp,rerr = cpp.Do(breq)
	if (rerr == nil) {
		t.Errorf("Do() with bad URL should have failed.")
	}
	rsp,rerr = cpp.Get(badURL)
	if (rerr == nil) {
		t.Errorf("Get() with bad URL should have failed.")
	}
	rsp,rerr = cpp.Head(badURL)
	if (rerr == nil) {
		t.Errorf("Head() with bad URL should have failed.")
	}
	rsp,rerr = cpp.Post(badURL, "application/json", bytes.NewBuffer([]byte(`{"Stuff":"things"}`)))
	if (rerr == nil) {
		t.Errorf("Post() with bad URL should have failed.")
	}
	rsp,rerr = cpp.PostForm(badURL, url.Values{})
	if (rerr == nil) {
		t.Errorf("PostForm() with bad URL should have failed.")
	}

	//Remove insecure client, leave secure.

	tmpSC := cpp.InsecureClient
	cpp.InsecureClient = nil
	rsp,rerr = cpp.Do(breq)
	if (rerr == nil) {
		t.Errorf("Do() with bad URL should have failed.")
	}
	rsp,rerr = cpp.Get("http://bad.url.gub")
	if (rerr == nil) {
		t.Errorf("Get() with bad URL should have failed.")
	}
	rsp,rerr = cpp.Head(badURL)
	if (rerr == nil) {
		t.Errorf("Head() with bad URL should have failed.")
	}
	rsp,rerr = cpp.Post(badURL, "application/json", bytes.NewBuffer([]byte(`{"Stuff":"things"}`)))
	if (rerr == nil) {
		t.Errorf("Post() with bad URL should have failed.")
	}
	rsp,rerr = cpp.PostForm(badURL, url.Values{})
	if (rerr == nil) {
		t.Errorf("PostForm() with bad URL should have failed.")
	}

	//Restore insecure client, remove secure client

	cpp.InsecureClient = tmpSC
	cpp.SecureClient = nil
	cpp.CloseIdleConnections()
	rsp,rerr = cpp.Do(breq)
	if (rerr == nil) {
		t.Errorf("Do() with bad URL should have failed.")
	}
	rsp,rerr = cpp.Get("http://bad.url.gub")
	if (rerr == nil) {
		t.Errorf("Get() with bad URL should have failed.")
	}
	rsp,rerr = cpp.Head(badURL)
	if (rerr == nil) {
		t.Errorf("Head() with bad URL should have failed.")
	}
	rsp,rerr = cpp.Post(badURL, "application/json", bytes.NewBuffer([]byte(`{"Stuff":"things"}`)))
	if (rerr == nil) {
		t.Errorf("Post() with bad URL should have failed.")
	}
	rsp,rerr = cpp.PostForm(badURL, url.Values{})
	if (rerr == nil) {
		t.Errorf("PostForm() with bad URL should have failed.")
	}

	//Should work

	rsp,rerr = cpp.Do(req)
	if (rerr != nil) {
		t.Errorf("Do() with nil secure client failed: %v.",rerr)
	}
	rsp,rerr = cpp.Get(srv.URL)
	if (rerr != nil) {
		t.Errorf("Get() with nil secure client failed: %v.",rerr)
	}
	rsp,rerr = cpp.Head(srv.URL)
	if (rerr != nil) {
		t.Errorf("Head() with nil secure client failed: %v.",rerr)
	}
	rsp,rerr = cpp.Post(srv.URL, "application/json", bytes.NewBuffer([]byte(`{"Stuff":"things"}`)))
	if (rerr != nil) {
		t.Errorf("Post() with nil secure client failed: %v.",rerr)
	}
	rsp,rerr = cpp.PostForm(srv.URL, url.Values{})
	if (rerr != nil) {
		t.Errorf("PostForm() with nil secure client failed: %v.",rerr)
	}

	//Uninitialized client pair
	var cppU HTTPClientPair
	rsp,rerr = cppU.Do(req)
	if (rerr == nil) {
		t.Errorf("Do() with uninitialized client pair didn't fail, should have.")
	}
	rsp,rerr = cppU.Get(srv.URL)
	if (rerr == nil) {
		t.Errorf("Get() with uninitialized client pair didn't fail, should have.")
	}
	rsp,rerr = cppU.Head(srv.URL)
	if (rerr == nil) {
		t.Errorf("Head() with uninitialized client pair didn't fail, should have.")
	}
	rsp,rerr = cppU.Post(srv.URL, "application/json", bytes.NewBuffer([]byte(`{"Stuff":"things"}`)))
	if (rerr == nil) {
		t.Errorf("Post() with uninitialized client pair didn't fail, should have.")
	}
	rsp,rerr = cppU.PostForm(srv.URL, url.Values{})
	if (rerr == nil) {
		t.Errorf("PostForm() with uninitialized client pair didn't fail, should have.")
	}

	//Nil client pair object ptr
	var cppN *HTTPClientPair
	cppN = nil
	rsp,rerr = cppN.Do(req)
	if (rerr == nil) {
		t.Errorf("Do() with nil client pair didn't fail, should have.")
	}
	rsp,rerr = cppN.Get(srv.URL)
	if (rerr == nil) {
		t.Errorf("Get() with nil client pair didn't fail, should have.")
	}
	rsp,rerr = cppN.Head(srv.URL)
	if (rerr == nil) {
		t.Errorf("Head() with nil client pair didn't fail, should have.")
	}
	rsp,rerr = cppN.Post(srv.URL, "application/json", bytes.NewBuffer([]byte(`{"Stuff":"things"}`)))
	if (rerr == nil) {
		t.Errorf("Post() with nil client pair didn't fail, should have.")
	}
	rsp,rerr = cppN.PostForm(srv.URL, url.Values{})
	if (rerr == nil) {
		t.Errorf("PostForm() with nil client pair didn't fail, should have.")
	}
}

func TestRetryableHTTPPairOps(t *testing.T) {
	setEnviron(t)
	ferr := createFakeCAChainCRT()
	if (ferr != nil) {
		t.Errorf("ERROR creating fake CA Chain CRT: %v",ferr)
	}

	cpp,cerr := CreateRetryableHTTPClientPair(cachainFilename,3,2,1)
	if (cerr != nil) {
		t.Errorf("Error creating HTTP client pair: %v",cerr)
	}

	srv := httptest.NewServer(http.HandlerFunc(genericHandler))
	defer srv.Close()

	req,qerr := http.NewRequest("GET",srv.URL,nil)
	if (qerr != nil) {
		t.Fatalf("ERROR creating request: %v",qerr)
	}
	cpp.CloseIdleConnections()
	rsp,rerr := cpp.Do(req)
	if (rerr != nil) {
		t.Errorf("ERROR from Do(): %v",rerr)
	}
	if (rsp == nil) {
		t.Errorf("ERROR: Do() rsp is nil.")
	}
	if (cpp.FailedOver == true) {
		t.Errorf("Do() operation incorrectly failed over.")
	}

	rsp,rerr = cpp.Get(srv.URL)
	if (rerr != nil) {
		t.Errorf("ERROR from Get(): %v",rerr)
	}
	if (rsp == nil) {
		t.Errorf("ERROR: Get() rsp is nil.")
	}
	if (cpp.FailedOver == true) {
		t.Errorf("Get() operation incorrectly failed over.")
	}
	rsp,rerr = cpp.Head(srv.URL)
	if (rerr != nil) {
		t.Errorf("ERROR from Head(): %v",rerr)
	}
	if (rsp == nil) {
		t.Errorf("ERROR: Head() rsp is nil.")
	}
	if (cpp.FailedOver == true) {
		t.Errorf("Head() operation incorrectly failed over.")
	}

	rsp,rerr = cpp.Post(srv.URL, "application/json", bytes.NewBuffer([]byte(`{"Stuff":"things"}`)))
	if (rerr != nil) {
		t.Errorf("ERROR from Post(): %v",rerr)
	}
	if (rsp == nil) {
		t.Errorf("ERROR: Post() rsp is nil.")
	}
	if (cpp.FailedOver == true) {
		t.Errorf("Post() operation incorrectly failed over.")
	}

	rsp,rerr = cpp.PostForm(srv.URL, url.Values{})
	if (rerr != nil) {
		t.Errorf("ERROR from PostForm(): %v",rerr)
	}
	if (rsp == nil) {
		t.Errorf("ERROR: PostForm() rsp is nil.")
	}
	if (cpp.FailedOver == true) {
		t.Errorf("PostForm() operation incorrectly failed over.")
	}

	//Create ClientPair with no CA, test all funcs

	cpp,cerr = CreateRetryableHTTPClientPair("",3,2,1)
	if (cerr != nil) {
		t.Errorf("Error creating HTTP client pair: %v",cerr)
	}
	cpp.CloseIdleConnections()
	rsp,rerr = cpp.Do(req)
	if (rerr != nil) {
		t.Errorf("ERROR from Do(): %v",rerr)
	}
	if (rsp == nil) {
		t.Errorf("ERROR: Do() rsp is nil.")
	}
	if (cpp.FailedOver == true) {
		t.Errorf("Do() operation incorrectly failed over.")
	}

	rsp,rerr = cpp.Get(srv.URL)
	if (rerr != nil) {
		t.Errorf("ERROR from Get(): %v",rerr)
	}
	if (rsp == nil) {
		t.Errorf("ERROR: Get() rsp is nil.")
	}
	if (cpp.FailedOver == true) {
		t.Errorf("Get() operation incorrectly failed over.")
	}
	rsp,rerr = cpp.Head(srv.URL)
	if (rerr != nil) {
		t.Errorf("ERROR from Head(): %v",rerr)
	}
	if (rsp == nil) {
		t.Errorf("ERROR: Head() rsp is nil.")
	}
	if (cpp.FailedOver == true) {
		t.Errorf("Head() operation incorrectly failed over.")
	}

	rsp,rerr = cpp.Post(srv.URL, "application/json", bytes.NewBuffer([]byte(`{"Stuff":"things"}`)))
	if (rerr != nil) {
		t.Errorf("ERROR from Post(): %v",rerr)
	}
	if (rsp == nil) {
		t.Errorf("ERROR: Post() rsp is nil.")
	}
	if (cpp.FailedOver == true) {
		t.Errorf("Post() operation incorrectly failed over.")
	}

	rsp,rerr = cpp.PostForm(srv.URL, url.Values{})
	if (rerr != nil) {
		t.Errorf("ERROR from PostForm(): %v",rerr)
	}
	if (rsp == nil) {
		t.Errorf("ERROR: PostForm() rsp is nil.")
	}
	if (cpp.FailedOver == true) {
		t.Errorf("PostForm() operation incorrectly failed over.")
	}


	//Error conditions

	cpp,cerr = CreateRetryableHTTPClientPair(cachainFilename,3,2,1)
	if (cerr != nil) {
		t.Errorf("Error creating HTTP client pair: %v",cerr)
	}
	expStatusG = http.StatusBadRequest
	rsp,rerr = cpp.Get(srv.URL)
	if (rerr != nil) {
		t.Errorf("ERROR from Get(): %v",rerr)
	}
	if (rsp.StatusCode != http.StatusBadRequest) {
		t.Errorf("Bad return status from Get(): %d",rsp.StatusCode)
	}

	// Make secure client fail.  First, replace it with a bad URL

	expStatusG = http.StatusOK
	badURL := "http://bad.url.gub"
	breq,_ := http.NewRequest("GET",badURL,nil)
	rsp,rerr = cpp.Do(breq)
	if (rerr == nil) {
		t.Errorf("Do() with bad URL should have failed.")
	}
	rsp,rerr = cpp.Get(badURL)
	if (rerr == nil) {
		t.Errorf("Get() with bad URL should have failed.")
	}
	rsp,rerr = cpp.Head(badURL)
	if (rerr == nil) {
		t.Errorf("Head() with bad URL should have failed.")
	}
	rsp,rerr = cpp.Post(badURL, "application/json", bytes.NewBuffer([]byte(`{"Stuff":"things"}`)))
	if (rerr == nil) {
		t.Errorf("Post() with bad URL should have failed.")
	}
	rsp,rerr = cpp.PostForm(badURL, url.Values{})
	if (rerr == nil) {
		t.Errorf("PostForm() with bad URL should have failed.")
	}

	//Remove insecure client, leave secure.

	tmpSC := cpp.InsecureClient
	cpp.InsecureClient = nil
	rsp,rerr = cpp.Do(breq)
	if (rerr == nil) {
		t.Errorf("Do() with bad URL should have failed.")
	}
	rsp,rerr = cpp.Get("http://bad.url.gub")
	if (rerr == nil) {
		t.Errorf("Get() with bad URL should have failed.")
	}
	rsp,rerr = cpp.Head(badURL)
	if (rerr == nil) {
		t.Errorf("Head() with bad URL should have failed.")
	}
	rsp,rerr = cpp.Post(badURL, "application/json", bytes.NewBuffer([]byte(`{"Stuff":"things"}`)))
	if (rerr == nil) {
		t.Errorf("Post() with bad URL should have failed.")
	}
	rsp,rerr = cpp.PostForm(badURL, url.Values{})
	if (rerr == nil) {
		t.Errorf("PostForm() with bad URL should have failed.")
	}

	//Restore insecure client, remove secure client

	cpp.InsecureClient = tmpSC
	cpp.SecureClient = nil
	cpp.CloseIdleConnections()
	rsp,rerr = cpp.Do(breq)
	if (rerr == nil) {
		t.Errorf("Do() with bad URL should have failed.")
	}
	rsp,rerr = cpp.Get("http://bad.url.gub")
	if (rerr == nil) {
		t.Errorf("Get() with bad URL should have failed.")
	}
	rsp,rerr = cpp.Head(badURL)
	if (rerr == nil) {
		t.Errorf("Head() with bad URL should have failed.")
	}
	rsp,rerr = cpp.Post(badURL, "application/json", bytes.NewBuffer([]byte(`{"Stuff":"things"}`)))
	if (rerr == nil) {
		t.Errorf("Post() with bad URL should have failed.")
	}
	rsp,rerr = cpp.PostForm(badURL, url.Values{})
	if (rerr == nil) {
		t.Errorf("PostForm() with bad URL should have failed.")
	}

	//Should work

	rsp,rerr = cpp.Do(req)
	if (rerr != nil) {
		t.Errorf("Do() with nil secure client failed: %v.",rerr)
	}
	rsp,rerr = cpp.Get(srv.URL)
	if (rerr != nil) {
		t.Errorf("Get() with nil secure client failed: %v.",rerr)
	}
	rsp,rerr = cpp.Head(srv.URL)
	if (rerr != nil) {
		t.Errorf("Head() with nil secure client failed: %v.",rerr)
	}
	rsp,rerr = cpp.Post(srv.URL, "application/json", bytes.NewBuffer([]byte(`{"Stuff":"things"}`)))
	if (rerr != nil) {
		t.Errorf("Post() with nil secure client failed: %v.",rerr)
	}
	rsp,rerr = cpp.PostForm(srv.URL, url.Values{})
	if (rerr != nil) {
		t.Errorf("PostForm() with nil secure client failed: %v.",rerr)
	}
}


func TestHTTPPairOps_Failover(t *testing.T) {
	badURL := "https://www.xyzzy.bum"
	setEnviron(t)
	ConfigParams.LogInsecureFailover = true
	ferr := createFakeCAChainCRT()
	if (ferr != nil) {
		t.Errorf("ERROR creating fake CA Chain CRT: %v",ferr)
	}

	cpp,cerr := CreateHTTPClientPair(cachainFilename,3)
	if (cerr != nil) {
		t.Errorf("Error creating HTTP client pair: %v",cerr)
	}
	if (cpp == nil) {
		t.Errorf("ERROR: unexpecte nil HTTP client pair.")
	}

	req,qerr := http.NewRequest("GET",badURL,nil)
	if (qerr != nil) {
		t.Fatalf("ERROR creating request: %v",qerr)
	}
	cpp.CloseIdleConnections()
	cpp.Do(req)
	if (cpp.FailedOver != true) {
		t.Errorf("Do() operation without failover indicator.")
	}

	cpp.Get(badURL)
	if (cpp.FailedOver != true) {
		t.Errorf("Get() operation without failover indicator.")
	}
	cpp.Head(badURL)
	if (cpp.FailedOver != true) {
		t.Errorf("Head() operation without failover indicator.")
	}

	cpp.Post(badURL, "application/json", bytes.NewBuffer([]byte(`{"Stuff":"things"}`)))
	if (cpp.FailedOver != true) {
		t.Errorf("Post() operation without failover indicator.")
	}

	cpp.PostForm(badURL, url.Values{})
	if (cpp.FailedOver != true) {
		t.Errorf("PostForm() operation without failover indicator.")
	}
}

func TestRetryableHTTPPairOps_Failover(t *testing.T) {
	badURL := "https://www.xyzzy.bum"
	setEnviron(t)
	ConfigParams.LogInsecureFailover = true
	ferr := createFakeCAChainCRT()
	if (ferr != nil) {
		t.Errorf("ERROR creating fake CA Chain CRT: %v",ferr)
	}

	cpp,cerr := CreateRetryableHTTPClientPair(cachainFilename,3,2,1)
	if (cerr != nil) {
		t.Errorf("Error creating HTTP client pair: %v",cerr)
	}
	if (cpp == nil) {
		t.Errorf("ERROR: unexpecte nil HTTP client pair.")
	}

	req,qerr := http.NewRequest("GET",badURL,nil)
	if (qerr != nil) {
		t.Fatalf("ERROR creating request: %v",qerr)
	}
	cpp.CloseIdleConnections()
	cpp.Do(req)
	if (cpp.FailedOver != true) {
		t.Errorf("Do() operation without failover indicator.")
	}

	cpp.Get(badURL)
	if (cpp.FailedOver != true) {
		t.Errorf("Get() operation without failover indicator.")
	}
	cpp.Head(badURL)
	if (cpp.FailedOver != true) {
		t.Errorf("Head() operation without failover indicator.")
	}

	cpp.Post(badURL, "application/json", bytes.NewBuffer([]byte(`{"Stuff":"things"}`)))
	if (cpp.FailedOver != true) {
		t.Errorf("Post() operation without failover indicator.")
	}

	cpp.PostForm(badURL, url.Values{})
	if (cpp.FailedOver != true) {
		t.Errorf("PostForm() operation without failover indicator.")
	}
}

func TestHTTPPairOps_NoLog(t *testing.T) {
	setEnviron(t)
	ferr := createFakeCAChainCRT()
	if (ferr != nil) {
		t.Errorf("ERROR creating fake CA Chain CRT: %v",ferr)
	}

	cpp,cerr := CreateHTTPClientPair(cachainFilename,3)
	if (cerr != nil) {
		t.Errorf("Error creating HTTP client pair: %v",cerr)
	}

	srv := httptest.NewServer(http.HandlerFunc(genericHandler))
	defer srv.Close()

	ConfigParams.LogInsecureFailover = false
	req,qerr := http.NewRequest("GET",srv.URL,nil)
	if (qerr != nil) {
		t.Fatalf("ERROR creating request: %v",qerr)
	}
	cpp.CloseIdleConnections()
	rsp,rerr := cpp.Do(req)
	if (rerr != nil) {
		t.Errorf("ERROR from Do(): %v",rerr)
	}
	if (rsp == nil) {
		t.Errorf("ERROR: Do() rsp is nil.")
	}

	rsp,rerr = cpp.Get(srv.URL)
	if (rerr != nil) {
		t.Errorf("ERROR from Get(): %v",rerr)
	}
	if (rsp == nil) {
		t.Errorf("ERROR: Get() rsp is nil.")
	}
	rsp,rerr = cpp.Head(srv.URL)
	if (rerr != nil) {
		t.Errorf("ERROR from Head(): %v",rerr)
	}
	if (rsp == nil) {
		t.Errorf("ERROR: Head() rsp is nil.")
	}

	rsp,rerr = cpp.Post(srv.URL, "application/json", bytes.NewBuffer([]byte(`{"Stuff":"things"}`)))
	if (rerr != nil) {
		t.Errorf("ERROR from Post(): %v",rerr)
	}
	if (rsp == nil) {
		t.Errorf("ERROR: Post() rsp is nil.")
	}

	rsp,rerr = cpp.PostForm(srv.URL, url.Values{})
	if (rerr != nil) {
		t.Errorf("ERROR from PostForm(): %v",rerr)
	}
	if (rsp == nil) {
		t.Errorf("ERROR: PostForm() rsp is nil.")
	}

	//Create ClientPair with no CA, test all funcs

	cpp,cerr = CreateHTTPClientPair("",3)
	if (cerr != nil) {
		t.Errorf("Error creating HTTP client pair: %v",cerr)
	}
	cpp.CloseIdleConnections()
	rsp,rerr = cpp.Do(req)
	if (rerr != nil) {
		t.Errorf("ERROR from Do(): %v",rerr)
	}
	if (rsp == nil) {
		t.Errorf("ERROR: Do() rsp is nil.")
	}

	rsp,rerr = cpp.Get(srv.URL)
	if (rerr != nil) {
		t.Errorf("ERROR from Get(): %v",rerr)
	}
	if (rsp == nil) {
		t.Errorf("ERROR: Get() rsp is nil.")
	}
	rsp,rerr = cpp.Head(srv.URL)
	if (rerr != nil) {
		t.Errorf("ERROR from Head(): %v",rerr)
	}
	if (rsp == nil) {
		t.Errorf("ERROR: Head() rsp is nil.")
	}

	rsp,rerr = cpp.Post(srv.URL, "application/json", bytes.NewBuffer([]byte(`{"Stuff":"things"}`)))
	if (rerr != nil) {
		t.Errorf("ERROR from Post(): %v",rerr)
	}
	if (rsp == nil) {
		t.Errorf("ERROR: Post() rsp is nil.")
	}

	rsp,rerr = cpp.PostForm(srv.URL, url.Values{})
	if (rerr != nil) {
		t.Errorf("ERROR from PostForm(): %v",rerr)
	}
	if (rsp == nil) {
		t.Errorf("ERROR: PostForm() rsp is nil.")
	}


	//Error conditions

	expStatusG = http.StatusBadRequest
	rsp,rerr = cpp.Get(srv.URL)
	if (rerr != nil) {
		t.Errorf("ERROR from Get(): %v",rerr)
	}
	if (rsp.StatusCode != http.StatusBadRequest) {
		t.Errorf("Bad return status from Get(): %d",rsp.StatusCode)
	}

	// Make secure client fail.  First, replace it with a bad URL

	expStatusG = http.StatusOK
	badURL := "http://bad.url.gub"
	breq,_ := http.NewRequest("GET",badURL,nil)
	rsp,rerr = cpp.Do(breq)
	if (rerr == nil) {
		t.Errorf("Do() with bad URL should have failed.")
	}
	rsp,rerr = cpp.Get(badURL)
	if (rerr == nil) {
		t.Errorf("Get() with bad URL should have failed.")
	}
	rsp,rerr = cpp.Head(badURL)
	if (rerr == nil) {
		t.Errorf("Head() with bad URL should have failed.")
	}
	rsp,rerr = cpp.Post(badURL, "application/json", bytes.NewBuffer([]byte(`{"Stuff":"things"}`)))
	if (rerr == nil) {
		t.Errorf("Post() with bad URL should have failed.")
	}
	rsp,rerr = cpp.PostForm(badURL, url.Values{})
	if (rerr == nil) {
		t.Errorf("PostForm() with bad URL should have failed.")
	}

	//Remove secure client

	cpp.SecureClient = nil
	cpp.CloseIdleConnections()
	rsp,rerr = cpp.Do(breq)
	if (rerr == nil) {
		t.Errorf("Do() with bad URL should have failed.")
	}
	rsp,rerr = cpp.Get("http://bad.url.gub")
	if (rerr == nil) {
		t.Errorf("Get() with bad URL should have failed.")
	}
	rsp,rerr = cpp.Head(badURL)
	if (rerr == nil) {
		t.Errorf("Head() with bad URL should have failed.")
	}
	rsp,rerr = cpp.Post(badURL, "application/json", bytes.NewBuffer([]byte(`{"Stuff":"things"}`)))
	if (rerr == nil) {
		t.Errorf("Post() with bad URL should have failed.")
	}
	rsp,rerr = cpp.PostForm(badURL, url.Values{})
	if (rerr == nil) {
		t.Errorf("PostForm() with bad URL should have failed.")
	}

	//Should work

	rsp,rerr = cpp.Do(req)
	if (rerr != nil) {
		t.Errorf("Do() with nil secure client failed: %v.",rerr)
	}
	rsp,rerr = cpp.Get(srv.URL)
	if (rerr != nil) {
		t.Errorf("Get() with nil secure client failed: %v.",rerr)
	}
	rsp,rerr = cpp.Head(srv.URL)
	if (rerr != nil) {
		t.Errorf("Head() with nil secure client failed: %v.",rerr)
	}
	rsp,rerr = cpp.Post(srv.URL, "application/json", bytes.NewBuffer([]byte(`{"Stuff":"things"}`)))
	if (rerr != nil) {
		t.Errorf("Post() with nil secure client failed: %v.",rerr)
	}
	rsp,rerr = cpp.PostForm(srv.URL, url.Values{})
	if (rerr != nil) {
		t.Errorf("PostForm() with nil secure client failed: %v.",rerr)
	}
}

func caCB(caChain string) {
	if (caChain != "") {
		globalT.Logf("CAChain change seen: '%s'",caChain)
		cbCalled = true
	}
}


func TestCAUpdateRegister(t *testing.T) {
	setEnviron(t)
	globalT = t
	fname := "/tmp/CATestChain"
	err := ioutil.WriteFile(fname,[]byte("aaaaaCAChain"),0777)
	if (err != nil) {
		t.Errorf("ERROR creating '%s': %v",fname,err)
	}
	os.Chmod(fname,0777)
	err = CAUpdateRegister(fname,caCB)
	time.Sleep(2 * time.Second)

	//First update
	err = ioutil.WriteFile(fname,[]byte("BBBBBCAChain"),0777)
	if (err != nil) {
		t.Errorf("ERROR updating '%s': %v",fname,err)
	}
	time.Sleep(15 * time.Second)
	if (!cbCalled) {
		t.Errorf("ERROR, CA update callback was not called after 15 sec.")
	}

	//Second update

	cbCalled = false
	err = ioutil.WriteFile(fname,[]byte("CCCCCCAChain"),0777)
	if (err != nil) {
		t.Errorf("ERROR updating '%s': %v",fname,err)
	}
	time.Sleep(18 * time.Second)
	if (!cbCalled) {
		t.Errorf("ERROR, CA update callback was not called after 15 sec.")
	}

	//Test unregister

	err = CAUpdateUnregister(fname)
	if (err != nil) {
		t.Errorf("ERROR unregistering callback for '%s': %v",fname,err)
	}

	cbCalled = false
	err = ioutil.WriteFile(fname,[]byte("DDDDDCAChain"),0777)
	if (err != nil) {
		t.Errorf("ERROR updating '%s': %v",fname,err)
	}
	time.Sleep(22 * time.Second)
	if (cbCalled) {
		t.Errorf("ERROR, CA update callback was called, should not have been.")
	}
}

func TestCertDataOps(t *testing.T) {
	setEnviron(t)

	crt := "AABBCCDD"
	ckey := "FFGGHHII"
	certData := VaultCertData{Data: CertInfo{Certificate: crt,PrivateKey: ckey,},}

	err := StoreCertData("x1000",certData)
	if (err != nil) {
		t.Errorf("ERROR storing cert data: %v",err)
	}

	vcd,verr := FetchCertData("x1000c0s0b0",CertDomainCabinet)
	if (verr != nil) {
		t.Errorf("ERROR fetching cert data: %v",verr)
	}

	if (vcd.Data.Certificate != crt) {
		t.Errorf("ERROR mismatch of cert data, exp: '%s', got: '%s'",
			crt,vcd.Data.Certificate)
	}
	if (vcd.Data.PrivateKey != ckey) {
		t.Errorf("ERROR mismatch of key data, exp: '%s', got: '%s'",
			ckey,vcd.Data.PrivateKey)
	}

	vcd,verr = FetchCertData("x2",CertDomainCabinet)
	if (verr == nil) {
		t.Errorf("Fetch with bad xname didn't fail, should have.")
	}

	verr = DeleteCertData("x1000",false)
	if (verr != nil) {
		t.Errorf("Delete of cert failed: %v",verr)
	}

	verr = DeleteCertData("x2",false)
	if (verr == nil) {
		t.Errorf("Delete of invalid cert data should have failed, did not.")
	}

	verr = DeleteCertData("x1000",true)
	if (verr != nil) {
		t.Errorf("Forced delete of non-existent cert failed: %v",verr)
	}
}

