// MIT License
// 
// (C) Copyright [2020-2022] Hewlett Packard Enterprise Development LP
// 
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.


package hms_certs

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"
	"github.com/sirupsen/logrus"
	"github.com/Cray-HPE/hms-xname/xnametypes"
)


var cbCalled = false
var globalT  *testing.T
var expStatusG  = http.StatusOK
var gotUserAgentHdrG bool
var gotUrlEncHdrG bool

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

var ghExp = `{"Status":"OK"}`

func genericHandler(w http.ResponseWriter, req *http.Request) {
	gotUserAgentHdrG = hasUserAgentHeader(req)
	gotUrlEncHdrG = hasUrlEncodingHeader(req)
	w.WriteHeader(expStatusG)
	w.Write([]byte(ghExp))
}

func genericHandlerReturnOK(w *http.Response) (bool,string,string) {
	body,err := ioutil.ReadAll(w.Body)
	if (err != nil) {
		return false,ghExp,"Error reading response body"
	}
	if (strings.TrimSpace(ghExp) != strings.TrimSpace(string(body))) {
		return false,ghExp,string(body)
	}
	return true,"",""
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

func hasUserAgentHeader(r *http.Request) bool {
	if (len(r.Header) == 0) {
		return false
	}

	_,ok := r.Header["User-Agent"]
	if (!ok) {
		return false
	}
	return true
}

func hasUrlEncodingHeader(r *http.Request) bool {
	if (len(r.Header) == 0) {
		return false
	}

	vals,ok := r.Header["Content-Type"]
	if (!ok) {
		return false
	}

	found := false
	for _,v := range(vals) {
		if (v == "application/x-www-form-urlencoded") {
			found = true
			break
		}
	}

	return found
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
		if (xnametypes.GetHMSTypeString(ep) == "") {
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
	InitInstance(logrus.New(),"CertsTest")
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
	var ok bool
	var exp,act string

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
	ok,exp,act = genericHandlerReturnOK(rsp)
	if (!ok) {
		t.Errorf("Do() return mismatch, exp: '%s', got: '%s'",exp,act)
	}

	globalT = t
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
	if (!gotUserAgentHdrG) {
		t.Errorf("Get() operation has no User-Agent header.")
	}
	ok,exp,act = genericHandlerReturnOK(rsp)
	if (!ok) {
		t.Errorf("Get() return mismatch, exp: '%s', got: '%s'",exp,act)
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
	if (!gotUserAgentHdrG) {
		t.Errorf("Post() operation has no User-Agent header.")
	}
	ok,exp,act = genericHandlerReturnOK(rsp)
	if (!ok) {
		t.Errorf("Post() return mismatch, exp: '%s', got: '%s'",exp,act)
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
	if (!gotUserAgentHdrG) {
		t.Errorf("PostForm() operation has no User-Agent header.")
	}
	if (!gotUrlEncHdrG) {
		t.Errorf("PostForm() operation has no URL encoding header.")
	}
	ok,exp,act = genericHandlerReturnOK(rsp)
	if (!ok) {
		t.Errorf("PostForm() return mismatch, exp: '%s', got: '%s'",exp,act)
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
	ok,exp,act = genericHandlerReturnOK(rsp)
	if (!ok) {
		t.Errorf("Do() return mismatch, exp: '%s', got: '%s'",exp,act)
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
	if (!gotUserAgentHdrG) {
		t.Errorf("Get() operation has no User-Agent header.")
	}
	ok,exp,act = genericHandlerReturnOK(rsp)
	if (!ok) {
		t.Errorf("Get() return mismatch, exp: '%s', got: '%s'",exp,act)
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
	if (!gotUserAgentHdrG) {
		t.Errorf("Post() operation has no User-Agent header.")
	}
	ok,exp,act = genericHandlerReturnOK(rsp)
	if (!ok) {
		t.Errorf("Post() return mismatch, exp: '%s', got: '%s'",exp,act)
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
	if (!gotUserAgentHdrG) {
		t.Errorf("PostForm() operation has no User-Agent header.")
	}
	if (!gotUrlEncHdrG) {
		t.Errorf("PostForm() operation has no URL encoding header.")
	}
	ok,exp,act = genericHandlerReturnOK(rsp)
	if (!ok) {
		t.Errorf("PostForm() return mismatch, exp: '%s', got: '%s'",exp,act)
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
	if (!gotUserAgentHdrG) {
		t.Errorf("Get() operation has no User-Agent header.")
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
	if (!gotUserAgentHdrG) {
		t.Errorf("Post() operation has no User-Agent header.")
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
	if (!gotUserAgentHdrG) {
		t.Errorf("PostForm() operation has no User-Agent header.")
	}
	if (!gotUrlEncHdrG) {
		t.Errorf("PostForm() operation has no URL encoding header.")
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
	if (!gotUserAgentHdrG) {
		t.Errorf("Do() operation has no User-Agent header.")
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
	if (!gotUserAgentHdrG) {
		t.Errorf("Get() operation has no User-Agent header.")
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
	if (!gotUserAgentHdrG) {
		t.Errorf("Post() operation has no User-Agent header.")
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
	if (!gotUserAgentHdrG) {
		t.Errorf("PostForm() operation has no User-Agent header.")
	}
	if (!gotUrlEncHdrG) {
		t.Errorf("PostForm() operation has no URL encoding header.")
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

