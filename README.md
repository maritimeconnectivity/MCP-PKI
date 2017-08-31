[![Build Status](https://travis-ci.org/MaritimeCloud/MC-PKI.svg?branch=master)](https://travis-ci.org/MaritimeCloud/MC-PKI)

# Maritime Cloud PKI

This is a library / cmdline tool used to manage and check certificates in the Maritime Cloud Public Key Infrastructure.

Building using maven should be as simple as running `mvn install`.

## Using the lib
The primary function of this software is to make it easy/easier to use the Maritime Cloud PKI for (Java) developers. 

There is javadocs available here: <https://maritimecloud.github.io/MC-PKI/apidocs/>

Use PKIConfiguration for setting up configuration about Keystore and/or Truststore, use KeystoreHandler to load them and the you most like want to use CertificateHandler to, well, handle certificates...

A short example of use can be seen below:
```java
    // Setup MC PKI
    PKIConfiguration pkiConf = new PKIConfiguration();
    pkiConf.setTruststorePath("/path/to/mc-truststore.jks");
    pkiConf.setTruststorePassword("changeit");
    KeystoreHandler kh = new KeystoreHandler(pkiConf);
    // Get the certificate that should be validated
    X509Certificate cert = getUserCertificate();
    // Validate certificate
    CertificateHandler.verifyCertificateChain(cert, kh.getTrustStore());
    // Extract Identity information from the certificate
    PKIIdentity user = CertificateHandler.getIdentityFromCert(cert);
```

## Commandline interface
The secondary function of this software is to provide a (relatively) easy to use interface for the PKI manager. How to use is will be described below.

If you have build using maven you should now have a `mc-pki-0.4.99-SNAPSHOT.jar` and a `mc-pki-0.4.99-SNAPSHOT-jar-with-dependencies.jar` (or similar). It is the latter we will be using since it can easily be runned from the commandline.

### Initializing the PKI
To use the PKI we must first initialize it, which means create a root Certificate Authority (CA). This can be done with this command:
```sh
java -jar mc-pki-0.4.99-SNAPSHOT-jar-with-dependencies.jar \
    --init \
    --truststore-path mc-truststore.jks \
    --truststore-password changeit \
    --root-keystore-path root-ca-keystore.jks \
    --root-keystore-password changeit \
    --root-key-password changeit \
    --x500-name "C=DK, ST=Denmark, L=Copenhagen, O=MaritimeCloud Test, OU=MaritimeCloud Test, CN=MaritimeCloud Test Root Certificate, E=info@maritimecloud.net" \
    --crl-endpoint "https://localhost/x509/api/certificates/crl/urn:mrn:mcl:ca:maritimecloud"
```
Note that the truststore and root-keystore will be overwritten! Also note that crl-endpoint should end with `urn:mrn:mcl:ca:maritimecloud`, as this is the expected by the Maritime Cloud Identity Registry!

Change the passwords as you see fit.

### Create root Certificate Revocation List
We must also create a root Certificate Revocation List to be able to tell if any sub CA has been revoked. This can be done with this command: 
```sh
java -jar mc-pki-0.4.99-SNAPSHOT-jar-with-dependencies.jar \
    --generate-root-crl \
    --root-keystore-path root-ca-keystore.jks \
    --root-keystore-password changeit \
    --root-key-password changeit \
    --revoked-subca-file revoked-subca.csv \
    --root-crl-path root-ca.crl
```
The revoked-subca-file CSV file must either be empty or have a format like this:
```csv
345678954765889809876543;cacompromise;2017-04-31
```
That is `<serial-number>;<revocation-reason>;<revocation-date>`

The revocation reason can be one of the following: unspecified, keycompromise, cacompromise, affiliationchanged, superseded, cessationofoperation, certificatehold, removefromcrl, privilegewithdrawn or aacompromise.

The revocation date must be be of the format: YYYY-MM-DD.

Remember to keep the list of revoked sub ca. Each time a new sub CA is revoked you must add it to the CSV file and generate a new CRL. Note that a CRL is valid for exactly on year.

### Create sub CA
Create a sub CA like this:
```sh
java -jar mc-pki-0.4.99-SNAPSHOT-jar-with-dependencies.jar \
    --create-subca \
    --root-keystore-path root-ca-keystore.jks \
    --root-keystore-password changeit \
    --root-key-password changeit \
    --truststore-path mc-truststore.jks \
    --truststore-password changeit \
    --subca-keystore subca-keystore.jks \
    --subca-keystore-password changeit \
    --subca-key-password changeit \
    --x500-name "UID=urn:mrn:mcl:ca:maritimecloud-idreg, C=DK, ST=Denmark, L=Copenhagen, O=MaritimeCloud Test, OU=MaritimeCloud Test, CN=MaritimeCloud Test Identity Registry, E=info@maritimecloud.net" \
    --crl-endpoint "https://localhost/x509/api/certificates/crl/urn:mrn:mcl:ca:maritimecloud-idreg" \
    --ocsp-endpoint "https://localhost/x509/api/certificates/ocsp/urn:mrn:mcl:ca:maritimecloud-idreg"
```

The UID will be used as alias when stored in the truststore and subca-keystore. The root-keystore and truststore is expected to exists, while the subca-keystore will be created if it does not exists.

## License
This software is distributed under the Apache License, Version 2.0.

This project includes code from the Apache Xcf project (Apache License, Version 2.0), and the [POReID project](https://github.com/poreid/poreid) (MIT License). 


## Building
Build the jar using maven like this:
```sh
mvn clean test install
```

Sign (requires a gpg key):
```sh
mvn -Dskip.signing=false install
```

Deploy (requires a gpg key registered at sonatype):
```sh
mvn -Dskip.signing=false clean deploy -Psonatype
```

Build the javadocs used for the documentation available at https://maritimecloud.github.io/MC-PKI/
```sh
./javadocs.sh docs
```

Build the javadocs used for the documentation available at https://maritimecloud.github.io/MC-PKI/ and push to github:
```sh
./javadocs.sh site
```
