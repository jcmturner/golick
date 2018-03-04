# GoLicK - Go Licence Key

Go Licence Key provides a library and command line tool to implement software licencing in Go applications.

# Usage

## Create Licensing Key Pair
Before you can issue licences for your software a licencing key pair is required.
To generate run the following command:
```
golick -init=<path to save key files>
```
This will return output informing you of the name of your key pair files.
For example:
```
Private key: ./c7ea317a-ed65-fffc-9116-7e10931aa279.key
Public key: ./c7ea317a-ed65-fffc-9116-7e10931aa279.pub
```
It is vital to keep the .key file secret.

## Integrating Licensing
To integrate licensing into your Go application:

Create a constant in your code with the contents of the .pub file:
```go
const (
	licencePublicKey = "3082010a0282010100c405973949ae94f5451b020f686c925a2ca3386f8305a70d4fe91dbf10d18d1416af4ff15a7c08a9803f6891c0d8e7eb0ece0e93d4ebcb3e31cdce5ba4cef22e870cf8b44b594bb6c317cd8137cfa38849ce64db2ffb2c72a6ab2ba416d841601fdb53fd47f03f11922365aba3c8e5b83c7a73660bd50768b4d41b640f5c18bebddaf5c5721f73be682ee3e509ed87b8995570caa2083a0ff25ea5b3106179603382fc26ce36a1dc04b187e492cf5c732e1d97d955c328a4c6f1f0d68df02dfa2c21be58fa0db64449ea2f9ce7a51b76cd8027943e685a2d394ef74b9660c60987c260f0c05917c013af063647ac2eb7dce4c62e399f396160160916b12c3b1d0203010001"
)
```
Your application will need to provide a mechanism for the user to provide a licence string.
In the example below this is held in the variable "licenceStr"
```go
	if licenceStr == "" {
		return errors.New("no licence provided")
	}
	pubBytes, err := hex.DecodeString(licencePublicKey)
	if err != nil {
		return err
	}
	pubkey, err := x509.ParsePKCS1PublicKey(pubBytes)
	if err != nil {
		return err
	}
	l, err := licence.Load(licenceStr)
	if err != nil {
		return err
	}
	ok, err := l.Valid(pubkey)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("invalid licence")
	}
	return nil
```
The Licence struct has fields you will need to check as part of your code and act accordingly.
* ValidFrom and ValidUntil - if the current time is outside of these dates you may want to refuse to run or return an error to requests.
* MaxCount - you may track a count of something and refuse to run or return an error if the count exceeds this value. Use a value of 0 as unlimited.
* UUID - this is a unique value for the licence. You may want to track this value to prevent reuse of the same licence.

Below is an example of implementing a HTTP hander wrapper function to that checks the licence status before serving requests.
```go
func licenceCheck(inner http.Handler, l *licence.Licence) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if time.Now().UTC().After(l.ValidUntil) {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, "Licence expired")
			return
		}
		inner.ServeHTTP(w, r)
	})
}
```
## Generate Licences
To generate licences run the following command:
```
golick -key=./c7ea317a-ed65-fffc-9116-7e10931aa279.key -duration 356
```
This will generate a licence valid for 356 days and output the following:
```
Licence Information:
UUID: 92598005-ab86-0ea6-0895-1ea009e75183
Valid From: 2018-03-04 15:37:41.203905437 +0000 UTC
Valid Until: 2019-03-04 15:37:41.203905526 +0000 UTC
Limit: 0
Key:
Wv+BAwEBB0xpY2VuY2UB/4IAAQUBBFVVSUQBDAABCVZhbGlkRnJvbQH/hAABClZhbGlkVW50aWwB/4QAAQtSdW5EdXJhdGlvbgEEAAEITWF4Q291bnQBBAAAABD/gwUBAQRUaW1lAf+EAAAAS/+CASQ5MjU5ODAwNS1hYjg2LTBlYTYtMDg5NS0xZWEwMDllNzUxODMBDwEAAAAO0i4JxQwnWZ3//wEPAQAAAA7UDz1FDCdZ9v//AA==
```
This is the licence information that you should provide to the user.
The user will need to configure your application to run with the licence key value that is the last line of this output.

### Trial Licences
Trial licences are ones that are configured with a limited runtime duration (in minutes).
```
golick -key=./c7ea317a-ed65-fffc-9116-7e10931aa279.key -runduration 60
```
When this kind of licence is validated the ValidUntil field is dynamically populated with the current time plus the runtime duration.
