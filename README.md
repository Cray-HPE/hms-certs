# hms_certs Go package

This repo contains a GO packages which allows applications to fetch CA 
chain/bundles and create TLS cert/key pairs.  This is very Redfish-centric; 
at some point in the future it may need to be expanded for other HTTP endpoint 
types.

Typical usage is to create a TLS cert/key pair on a per-cabinet basis.
This is done thusly:

	var rdata hms_certs.VaultCertData
	err := hms_certs.CreateCerts([]string{"x1000",}, CertDomainCabinet,&rdata)

'rdata' contains the CA chain, TLS cert and TLS private key for that cabinet, 
all PEM-encoded.  The certificate contains Subject Alternative Names (SANS) 
for all possible endpoints in that cabinet.  Thus, the same certificate can
be used for all BMCs in a cabinet.

It is also possible to grab just the CA chain, as follows:

	caChain,err := hms_certs.FetchCAChain()

'caChain' contains the PEM-encoded CA chain.  This would typically be used by 
services that want to establish secure HTTPS transports to talk with 
endpoints (typically Redfish) that have their TLS cert/key pairs in place.

Finally, there are some utility functions that can take PEM encoded cert or key
strings and replace newlines with literal '\n' character tuples, or take the 
'\n' tuples and replace them with literal newlines.   This is because JSON 
payloads need the tuples, but GO http setup functions need the literal newlines.

## Data Structures

```
// Returned cert info from the Vault PKI.  This data is returned to the 
// caller in some of of the hms_certs API calls.

type VaultCertData struct {
	RequestID     string   `json:"request_id"`
	LeaseID       string   `json:"lease_id"`
	Renewable     bool     `json:"renewable"`
	LeaseDuration int      `json:"lease_duration"`
	Data          CertInfo `json:"data"`
}

type CertInfo struct {
	CAChain        []string `json:"ca_chain"`
	Certificate    string   `json:"certificate"`
	Expiration     int      `json:"expiration"`
	IssuingCA      string   `json:"issuing_ca"`
	PrivateKey     string   `json:"private_key"`
	PrivateKeyType string   `json:"private_key_type"`
	SerialNumber   string   `json:"serial_number"`
	FQDN           string   `json:"fqdn,omitempty"`
}
```

### HTTP Client Pair

```
type HTTPClientPair struct {
	SecureClient   *http.Client
	InsecureClient *http.Client
}
```

The HTTP client pair object is used for TLS-secure HTTP calls.  This object
contains one TLS-validated and one non-valided HTTP client.  This object type 
implements a standard Golang http interface (Do(), Get(), Post() etc. 
methods).  

An HTTP client pair is created using a CA URI string.  This allows for the
set-up of an HTTP transport with TLS security.   This is one transport of
the client pair.   The other client is a non-validated client.

Note that it is possible to create an HTTP client pair with an empty CA URI;
in this case the client pair object will only contain the non-validated client.

When using the client pair, note that the target BMC may or may not have
valid TLS certs installed.  If the client pair has both a validated and 
non-validated client, the client pair will first attempt using the validated
client, and if that fails with an authorization error, then it will "fail over"
and use the non-validated client.

This is done so that the application doesn't have to keep track of which 
BMCs have TLS certs installed and which do not, which is a pretty messy
prospect.


### Constants

```
const (
	CertDomainCabinet = "CERT_DOMAIN_CABINET"          //Cabinet BMC domain
	CertDomainChassis = "CERT_DOMAIN_CHASSIS"          //Chassis BMC domain
	CertDomainBlade   = "CERT_DOMAIN_BLADE"            //Blade BMC domain
	CertDomainBMC     = "CERT_DOMAIN_BMC"              //BMC-only domain

	VaultCAChainURI   = "vault://pki_common/ca_chain"  //Default Vault CA chain URI
)
```

### Configurable Parameters

There are parameters which affect the operation of this package.  The 
defaults should work on a real system.  But, for testing purposes, some of
these may be altered.

Defaults:

```
hms_certs.Config.K8SAuthUrl:      "http://cray-vault.vault:8200/v1/auth/kubernetes/login"
hms_certs.Config.VaultPKIUrl:     "http://cray-vault.vault:8200/v1/pki_common/issue/pki-common"
hms_certs.Config.VaultCAUrl:      "http://cray-vault.vault:8200/v1/pki_common/ca_chain"
hms_certs.Config.VaultKeyBase:    "secret"
hms_certs.Config.CertKeyBasePath: "certs"
```

There are also some environment variables that are global to all applications
using Vault (which are not specific to hms_certs but are indirectly used):

```
CRAY_VAULT_JWT_FILE:   The file containing the access token.  Default is
                       "/var/run/secrets/kubernetes.io/serviceaccount/token".
CRAY_VAULT_ROLE_FILE:  The file containing the namespace.  Default is
                       "/var/run/secrets/kubernetes.io/serviceaccount/namespace".
CRAY_VAULT_AUTH_PATH:  Vault URL tail for k8s logins.  Default is 
                       "/auth/kubernetes/login"
```

As an example, when testing, SCSD overrides:

```
hms_certs.Config.K8SAuthUrl
hms_certs.Config.VaultPKIUrl
hms_certs.Config.VaultCAUrl
CRAY_VAULT_JWT_FILE
CRAY_VAULT_ROLE_FILE
```


## Functions

```
// Initialize the certs package.  This mainly just sets up the logging and
// the micro service instance name for HTTP headers.

func Init(loggerP *logrus.Logger)

func InitInstance(loggerP *logrus.Logger, svcName string)


// Given a list of BMC endpoints and a domain type, verify that all endpoints 
// are contained in the same cert domain and return the domain xname.
//
// endpoints(in): Array of BMC XNames
// domain(in):    Domain type, e.g. CertDomainCabinet
// Return:        Domain XName, e.g. "x1000"
//                nil on success, error info on error.

func CheckDomain(endpoints []string, domain string) (string,error)


// Create a TLS cert/key pair for a given set of endpoints.  The endpoints
// must be confined to the domain specified.  For example, if CertDomainCabinet
// is specified, all endpoints must reside in the same cabinet.
//
// If there is only one endpoint specified, then all possible components of 
// the specified type in the specified domain will be included in the key.
//
// Example, cert/key for sparse components:
//   endpoints: ["x0c0s0b0","x0c0s1b0","x0c0s2b0"], domain: cab
//      key will be for x0000 and have SANs for the endpoints listed.
//
// Example: cert/key for an entire cabinet:
//   endpoints: ["x1000"], domain: cab
//      key will be for x1000 and have SANs for all possible BMCs in the cab
//
// endpoints(in): List of target BMCs.
// domain(in):    Target domain:
//                    CertDomainCabinet
//                    CertDomainChassis
//                    CertDomainBlade
//                    CertDomainBMC
// fqdn(in):      FQDN, e.g. "rocket.us.cray.com" to use in cert creation.
//                Can be empty.
// retData(out):  Returned TLS cert/key data.  Certs/keys are in JSON-frienly format.
// Return:        nil on succes, error string on error.

func CreateCert(endpoints []string, domain string, fqdn string,
                retData *VaultCertData) error 


// Fetch the CA chain (a.k.a. 'bundle') cert.
//
// uri(in): URI of CA chain data.  Can be a pathname or VaultCAChainURI
// Return:  CA bundle cert in JSON-friendly format.
//          nil on success, error string on error

func FetchCAChain(uri string) (string,error)


// Register for changes to a CA chain.  This is based on a URI, which can be 
// a filename or VaultCAChainURI.
//
// If file, it will put a watch on the file.  If vault URI, it will poll.
// In either case, when the CA has changed, the specified function is called
// passing in the info needed to re-do ones' HTTP connection.
//
// uri(in):  CA chain resource name.  Can be a full pathname (used with
//           configmaps) or the vault URI for the CAChain (VaultCAChainURI).
// cb(in):   Function to call when the CA chain resource changes.  The function
//           must take a string as an argument; this string is the new CA
//           chain data, which can then be used to re-do HTTP transports.
// Return:   nil on success, error info on error.

func CAUpdateRegister(uri string, cb func(string)) error


// Un-register a CA chain change callback function.
//
// uri(in):  CA chain resource name.  Can be a full pathname (used with
//           configmaps) or the vault URI for the CAChain (VaultCAChainURI).
//           This is the "key" used to identify the registration.
// Return:   nil on success, error info on error.

func CAUpdateUnregister(uri string) error

// Take a cert/key pair and store it in Vault.
//
// domainID(in):  Top-of-domain XName (e.g. x1000)
// certData(out): Returned cert info from Vault PKI.
// Return:        nil on success, error info on error.

func StoreCertData(domainID string, certData VaultCertData) error


// Delete a cert from Vault storage.
//
// domainID(in):  Cert domain ID (e.g. x1000 for a cabinet domain)
// force(in):     Non-existent cert is an error unless force=true.
// Return:        nil on success, error info on error.

func DeleteCertData(domainID string, force bool) error


// Fetch a cert/key pair for a given XName within a given domain.
//
// xname(in):  Name of a BMC, OR, domain (e.g. x1000 for a cabinet domain)
// domain(in): BMC domain (e.g. hms_certs.CertDomainCabinet)
// Return:     Cert information for target;
//             nil on success, error info on error.

func FetchCertData(xname string, domain string) (VaultCertData,error)


//Converts a PEM-encoded cert or key with newlines to JSON-friendly 
//format, replacing the actual newlines with literal '\n' tuples.
//
// pemStr(in): PEM-encoded cert or key string with newlines.
// Return:     "Tuplified" cert/key string.

func NewlineToTuple(pemStr string) string


//Converts a PEM-encoded cert or key with newline tuples, replacing
//the newlines tuples with actual newlines.
//
// pemStr(in): "Tuplified" "PEM-encoded cert or key string.
// Return:     Cert/key string with newlines.

func ToTupleToNewline(pemStr string) string


// Given the URI (pathname or vault URI) of a CA cert chain bundle,
// create a secure HTTP client.
//
// timeoutSecs(in): Timeout, in seconds, for HTTP transport/client connections
// caURI(in):       URI of CA chain data.  Can be a pathname or VaultCAChainURI
// Return:          Client for secure HTTP use.
//                  nil on success, non-nil error if something went wrong.

func CreateSecureHTTPClient(timeoutSecs int, caURI string) (*http.Client,error)

// Create a non-cert-verified HTTP transport.
//
// Args:   None.
// Return: Client for secure HTTP use.
//         nil on success, non-nil error if something went wrong.

func CreateInsecureHTTPClient(timeoutSecs int) (*http.Client,error)


// Create a struct containing both a cert-validated and a non-cert-validated
// HTTP client.
//
// caURI(in):       URI of CA chain data.  Can be a pathname or VaultCAChainURI
// timeoutSecs(in): Timeout, in seconds, for HTTP transport/client connections
// Return:          Client for secure HTTP use.
//                  nil on success, non-nil error if something went wrong.

func CreateHTTPClientPair(caURI string, timeoutSecs int) (*HTTPClientPair,error)


// Given the URI (pathname or vault URI) of a CA cert chain bundle,
// create a secure internally retryable HTTP client.
//
// caURI(in):         CA trust bundle URI
// timeoutSecs(in)    Max timeout, in seconds.
// maxRetryCount(in): Max number of times to retry failures.  0 == try once.
// maxRetrySecs(in):  Max back-off time, in seconds, for retries.
// Return:            Retryable validated HTTP client, err string on error, nil on success.

func CreateRetryableSecureHTTPClient(caURI string,
                                     timeoutSecs int,
                                     maxRetryCount int,
                                     maxRetrySecs int) (*retryablehttp.Client,error)

// Create a non-validated internally retryable HTTP client.
//
// timeoutSecs(in)    Max timeout, in seconds.
// maxRetryCount(in): Max number of times to retry failures.  0 == try once.
// maxRetrySecs(in):  Max back-off time, in seconds, for retries.
// Return:            Retryable HTTP non-valided client, err string on error, nil on success.

func CreateRetryableInsecureHTTPClient(timeoutSecs int,
                                       maxRetryCount int,
                                       maxRetrySecs int) (*retryablehttp.Client,error)

// Given the URI (pathname or vault URI) of a CA cert chain bundle,
// create a validated/non-validated internally retryable HTTP client pair.
//
// caURI(in):         CA trust bundle URI
// timeoutSecs(in)    Max timeout, in seconds.
// maxRetryCount(in): Max number of times to retry failures.  0 == try once.
// maxRetrySecs(in):  Max back-off time, in seconds, for retries.
// Return:            Retryable HTTP client pair, err string on error, nil on success.

func CreateRetryableHTTPClientPair(caURI string, 
                                   timeoutSecs int,
                                   maxRetryCount int,
                                   maxRetrySecs int) (*HTTPClientPair,error)

// HTTPClientPair implementation of Golang HTTP Client methods.  These functions
// will use the TLS-secured transport first, and if that fails, will fail over
// to the insecure one.  If there is no TLS-secured transport, only the insecure
// one will be used.

func (p *HTTPClientPair) CloseIdleConnections()

func (p *HTTPClientPair) Do(req *http.Request) (*http.Response,error)

func (p *HTTPClientPair) Get(url string) (*http.Response,error)

func (p *HTTPClientPair) Head(url string) (*http.Response,error)

func (p *HTTPClientPair) Post(url, contentType string, body io.Reader) (*http.Response,error)

func (p *HTTPClientPair) PostForm(url string, data url.Values) (*http.Response,error)
```

## Usage Examples

### Creating A TLS-Secured HTTP Transport

```
...

	//CA URI is typically specified in a config map.  This can be an empty
	//string, meaning the HTTP client pair will only do non-validated requests.

	CA_Uri := os.Getenv("CA_URI") 
	xportTimeoutSecs := 10
	xportMaxRetries := 5
	xportMaxRetrySecs := 5
	hms_certs.InitInstance(myLogger,mySvcName)

	xport,err := hms_certs.CreateRetryableHTTPClientPair(CA_Uri,xportTimeoutSecs,
					xportMaxRetries,xportMaxRetrySecs)
	if (err != nil) {
		//Do error stuff
		return
	}

...

	rsp,rerr := xport.Do(httpReq)
	if (rerr != nil) {
		//Error handling
		return
	}

	//Use response data as needed
```

### Create, Store, Fetch, Delete TLS Certs

The following examples will create TLS certs and do various things with them.

```
	//Get list of BMCs
	targetBMCs = getTargets()	//pseudo routine to get a list of BMCs

	//Validate that all targets are in the desired (cabinet in this case) domain
	domainXName,derr := hms_certs.CheckDomain(targetBMCs, hms_certs.CertDomainCabinet)
	if (derr != nil) {
		//error handling
	}
	log.Printf("Validated BMC list for domain: %s",domainXname)	//e.g. 'x1000'

	//Create a TLS cert for an entire cabinet's worth of BMCs
	var cabCert hms_certs.VaultCertData
	err := hms_certs.CreateCert(targetBMCs,hms_certs.CertDomainCabinet,"",&cabCert)
	if (err != nil) {
		//error handling
	}

	//Store cert in Vault
	err = hms_certs.StoreCertData(domainXName,cabCert)
	if (err != nil) {
		//error handling
	}

	//If desired, at a later time, fetch a cert for a given BMC from Vault
	vcert,err = hms_certs.FetchCertData(bmcName,hms_certs.CertDomainCabinet)
	if (err != nil) {
		//error handling
	}

	//Cert data in 'vcert' can be sent to a BMC.  This is beyond the scope 
	//of this document.

	//Delete cert data from Vault
	err = hms_cert.DeleteCertDataData(domainXName,true)
	if (err != nil) {
		//error handling
	}
```

### Registering For Notification When A CA Trust Chain Changes

When creating an HTTP client pair, the CA trust bundle is fetched and used
to create TLS certs.  If an admin "rolls the certs", this means that CA 
certificates change and new TLS certs must be created for BMCs, and also, 
HTTP client pairs must be re-created.  Note that this typically does not 
happen very often (depends on the customer -- sometimes never, sometimes 
as frequently as weekly), but when it does, running microservices that use 
TLS-validated HTTP connections must update their certificates.

The hms_certs package has a way to get notified when the CA trust bundle 
changes.  This is done by supplying a package function with a callback 
function which is called when the CA trust bundle and/or CA cert changes.

Once the callback function is called, appropriate action must be taken as shown
in the example code below.

```
func caUpdate(arg string) {
	...
	log.Printf("CA bundle has been updated, creating new HTTP transports...")

	caURI := os.Getenv("CA_URI")
	clientPairMutex.Lock()
	defer clientPairMutex.Unlock()

	cp,err := hms_certs.CreateRetryableHTTPClientPair(CA_Uri,xportTimeoutSecs,
						xportMaxRetries,xportMaxRetrySecs)
	if (err != nil) {
		//error handling
		return
	}

	//Only set the application client pair to the new one if creation succeeded.
	globalClientPair = cp
}

func foo() {
...
	//Call directly to initially set up HTTP client pair object
	caUpdate(hms_certs.VaultCAChainURI)

	//Set up callback for future CA bundle changes
	err := hms_certs.CAUpdateRegister(hms_certs.VaultCAChainURI,caHasBeenUpdated)
	if (err != nil) {
		//error handling
	}
...
```

	






