/*
 * Copyright 2017 Danish Maritime Authority.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package net.maritimeconnectivity.pki;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;


class CertificateHandlerTest {

    @BeforeAll
    static void setUp() {
        Security.addProvider(new BouncyCastleProvider()); // Before Bouncy Castle as crypto provider
    }

    @Test
    void verifyCertificateChain1() {
        X509Certificate cert = TestUtils.getMyBoatCert();
        PKIConfiguration pkiConf = new PKIConfiguration(TestUtils.getRootCAAlias());
        pkiConf.setTruststorePassword("changeit");
        pkiConf.setTruststorePath("src/test/resources/mcp-truststore-password-is-changeit.jks");
        KeystoreHandler kh = new KeystoreHandler(pkiConf);

        boolean valid = false;
        try {
            valid = CertificateHandler.verifyCertificateChain(cert, kh.getTrustStore());
        } catch (KeyStoreException | CertPathValidatorException | InvalidAlgorithmParameterException |
                 CertificateException | NoSuchAlgorithmException e) {
            fail("Could not successfully verify certificate", e);
        }
        assertTrue(valid);
    }

    @Test
    void verifyCertificateChain2() {
//        X509Certificate cert = TestUtils.getEcdisCert();
        String pemCert = TestUtils.loadTxtFile("src/test/resources/no_trust_anchor.pem");
        X509Certificate cert = CertificateHandler.getCertFromPem(pemCert);
        PKIConfiguration pkiConf = new PKIConfiguration(TestUtils.getRootCAAlias());
        pkiConf.setTruststorePassword("changeit");
        pkiConf.setTruststorePath("src/test/resources/mcp-truststore-password-is-changeit.jks");
        KeystoreHandler kh = new KeystoreHandler(pkiConf);

        boolean valid = false;
        String exception = "None";
        String reason = "None";
        try {
            valid = CertificateHandler.verifyCertificateChain(cert, kh.getTrustStore());
        } catch (KeyStoreException | InvalidAlgorithmParameterException | CertificateException |
                 NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertPathValidatorException e) {
            reason = e.getReason().toString();
            exception = "CertPathValidatorException";
        }
        assertFalse(valid);
        assertEquals("CertPathValidatorException", exception);
        assertEquals("NO_TRUST_ANCHOR", reason);
    }


    @Test
    void verifyCertificate() {
        X509Certificate cert = TestUtils.getMyBoatCert();
        PKIConfiguration pkiConf = new PKIConfiguration(TestUtils.getRootCAAlias());
        pkiConf.setTruststorePassword("changeit");
        pkiConf.setTruststorePath("src/test/resources/mcp-truststore-password-is-changeit.jks");
        KeystoreHandler kh = new KeystoreHandler(pkiConf);

        boolean valid = CertificateHandler.verifyCertificate(kh.getPubKey("urn:mrn:mcp:ca:idp1:mcp-idreg"), cert, null);
        assertTrue(valid);
    }

    @Test
    void getPemFromEncoded() {
        X509Certificate cert = TestUtils.getMyBoatCert();
        try {
            String newlineChar = System.lineSeparator();
            String pemCertificate = CertificateHandler.getPemFromEncoded("CERTIFICATE", cert.getEncoded());
            assertEquals(pemCertificate, String.format("-----BEGIN CERTIFICATE-----%1$s" +
                    "MIIEVDCCA9qgAwIBAgIUCyyYKfQz/XJCDcjuXITjmOQkogAwCgYIKoZIzj0EAwMw%1$s" +
                    "gdwxLTArBgoJkiaJk/IsZAEBDB11cm46bXJuOm1jcDpjYTppZHAxOm1jcC1pZHJl%1$s" +
                    "ZzELMAkGA1UEBhMCREsxEDAOBgNVBAgMB0Rlbm1hcmsxEzARBgNVBAcMCkNvcGVu%1$s" +
                    "aGFnZW4xETAPBgNVBAoMCE1DUCBUZXN0MREwDwYDVQQLDAhNQ1AgVGVzdDEjMCEG%1$s" +
                    "A1UEAwwaTUNQIFRlc3QgSWRlbnRpdHkgUmVnaXN0cnkxLDAqBgkqhkiG9w0BCQEW%1$s" +
                    "HWluZm9AbWFyaXRpbWVjb25uZWN0aXZpdHkubmV0MB4XDTIyMTAxODE0MDYxNFoX%1$s" +
                    "DTIyMTIxODE0MDYxNFowgZMxCzAJBgNVBAYTAkRLMScwJQYDVQQKDB51cm46bXJu%1$s" +
                    "Om1jcDpvcmc6aWRwMTpib290c3RyYXAxDzANBgNVBAsMBnZlc3NlbDEQMA4GA1UE%1$s" +
                    "AwwHTXkgQm9hdDE4MDYGCgmSJomT8ixkAQEMKHVybjptcm46bWNwOnZlc3NlbDpp%1$s" +
                    "ZHAxOmJvb3RzdHJhcDpteWJvYXQwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQjbHqv%1$s" +
                    "cLCjOkj8Y8DErPcMUsWcFg7VtUFEK7nzffOrB7U/8SFajYo/WGqX/h0AHj4Wk8X4%1$s" +
                    "AAb2uND9TcOQNLIGq2TdWj6uGlDpr15WtvGFQZ+0JB8+YvaBbUH3WaKv4tujggGi%1$s" +
                    "MIIBnjCBjwYDVR0RBIGHMIGEoCIGFGmDtqOX2Juv+MfLmeyAgKqu14oboAoMCDEy%1$s" +
                    "MzQ1Njc4oBoGFGmChru7yJuwqMfLntmAgKqu14oboAIMAKBCBhRpg5i818Ce8PDH%1$s" +
                    "y6qdgICqrteKG6AqDCh1cm46bXJuOm1jcDp2ZXNzZWw6aWRwMTpib290c3RyYXA6%1$s" +
                    "bXlib2F0MB8GA1UdIwQYMBaAFNDmgGDMsQd7eNwgru9Pj42j8CJAMB0GA1UdDgQW%1$s" +
                    "BBSuLJtLOqF+x0hQkbisCAXRl7Z1kTBeBgNVHR8EVzBVMFOgUaBPhk1odHRwOi8v%1$s" +
                    "bG9jYWxob3N0Ojg4ODgveDUwOS9hcGkvY2VydGlmaWNhdGVzL2NybC91cm46bXJu%1$s" +
                    "Om1jcDpjYTppZHAxOm1jcC1pZHJlZzBqBggrBgEFBQcBAQReMFwwWgYIKwYBBQUH%1$s" +
                    "MAGGTmh0dHA6Ly9sb2NhbGhvc3Q6ODg4OC94NTA5L2FwaS9jZXJ0aWZpY2F0ZXMv%1$s" +
                    "b2NzcC91cm46bXJuOm1jcDpjYTppZHAxOm1jcC1pZHJlZzAKBggqhkjOPQQDAwNo%1$s" +
                    "ADBlAjBhoTf8Kw5l3siiSS7ZXiA2pCDoWTnVhYy2qZVBhqNdvkPULG5GU8a/vhci%1$s" +
                    "9HVRrXsCMQCanvviGQQywvnNCxad0Vvfg/+ZqRjkRkiSTj+rkvupK5a2wyRrMelg%1$s" +
                    "3YTirrupnYQ=%1$s" +
                    "-----END CERTIFICATE-----%1$s", newlineChar));
        } catch (CertificateEncodingException e) {
            fail("Unexpected Exception", e);
        }

    }

    @Test
    void createOutputKeystore1() {
        FileInputStream is;
        try {
            is = new FileInputStream("src/test/resources/mcp-sub-ca-keystore.jks");
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
        KeyStore keystore;
        X509Certificate cert;
        PrivateKey privateKey;
        try {
            keystore = KeyStore.getInstance("JKS");
            keystore.load(is, "changeit".toCharArray());
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection("changeit".toCharArray());
            KeyStore.PrivateKeyEntry key = (KeyStore.PrivateKeyEntry) keystore.getEntry("urn:mrn:mcp:ca:idp1:mcp-idreg", protParam);
            cert = (X509Certificate) key.getCertificate();
            privateKey = key.getPrivateKey();
        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException |
                 UnrecoverableEntryException e) {
            throw new RuntimeException(e.getMessage(), e);
        }

        byte[] p12Keystore = CertificateHandler.createOutputKeystore("PKCS12", "urn:mrn:mcp:ca:idp1:mcp-idreg", "changeit", privateKey, cert);
        try {
            ByteArrayInputStream inputStream = new ByteArrayInputStream(p12Keystore);
            keystore = KeyStore.getInstance("PKCS12");
            keystore.load(inputStream, "changeit".toCharArray());
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection("changeit".toCharArray());
            KeyStore.PrivateKeyEntry key = (KeyStore.PrivateKeyEntry) keystore.getEntry("urn:mrn:mcp:ca:idp1:mcp-idreg", protParam);
            X509Certificate certP12 = (X509Certificate) key.getCertificate();
            assertEquals(certP12.getSubjectDN().toString(), cert.getSubjectDN().toString());

        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException |
                 UnrecoverableEntryException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Test
    void createOutputKeystore2() {
        FileInputStream is;
        try {
            is = new FileInputStream("src/test/resources/mcp-sub-ca-keystore.jks");
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
        KeyStore keystore;
        X509Certificate cert;
        PrivateKey privateKey;
        try {
            keystore = KeyStore.getInstance("JKS");
            keystore.load(is, "changeit".toCharArray());
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection("changeit".toCharArray());
            KeyStore.PrivateKeyEntry key = (KeyStore.PrivateKeyEntry) keystore.getEntry("urn:mrn:mcp:ca:idp1:mcp-idreg", protParam);
            cert = (X509Certificate) key.getCertificate();
            privateKey = key.getPrivateKey();
        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException |
                 UnrecoverableEntryException e) {
            throw new RuntimeException(e.getMessage(), e);
        }

        byte[] jksKeystore = CertificateHandler.createOutputKeystore("JKS", "urn:mrn:mcp:ca:idp1:mcp-idreg", "changeit", privateKey, cert);
        try {
            ByteArrayInputStream inputStream = new ByteArrayInputStream(jksKeystore);
            keystore = KeyStore.getInstance("JKS");
            keystore.load(inputStream, "changeit".toCharArray());
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection("changeit".toCharArray());
            KeyStore.PrivateKeyEntry key = (KeyStore.PrivateKeyEntry) keystore.getEntry("urn:mrn:mcp:ca:idp1:mcp-idreg", protParam);
            X509Certificate certJks = (X509Certificate) key.getCertificate();
            assertEquals(certJks.getSubjectDN().toString(), cert.getSubjectDN().toString());

        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException |
                 UnrecoverableEntryException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }


    @Test
    void getCertFromNginxHeader() {
        String nginxFormatedPemCert = TestUtils.loadTxtFile("src/test/resources/thc-cert-nginx-format.pem");
        X509Certificate cert = null;
        try {
            cert = CertificateHandler.getCertFromNginxHeader(nginxFormatedPemCert);
        } catch (UnsupportedEncodingException e) {
            fail("Could not decode certificate", e);
        }
        assertNotNull(cert);
        assertEquals("EMAILADDRESS=thc@dma.dk, UID=urn:mrn:mcl:user:dma:thc, CN=Thomas Christensen, OU=user, O=urn:mrn:mcl:org:dma, C=DK", cert.getSubjectDN().getName());
    }

    @Test
    void getCertFromPem1() {
        String certPem = TestUtils.getMyBoatCertPem();
        X509Certificate cert = CertificateHandler.getCertFromPem(certPem);
        assertNotNull(cert);
        assertEquals(new BigInteger("63793386611437832114147118341345457695264907776"), cert.getSerialNumber());
    }

    @Test
    void getCertFromPem2() {
        String certPem = TestUtils.getEcdisCertPem();
        X509Certificate cert = CertificateHandler.getCertFromPem(certPem);
        assertNotNull(cert);
        assertEquals(new BigInteger("247125697494810758010619089255453560510776717949"), cert.getSerialNumber());
    }

    @Test
    void getIdentityFromCert() {
        X509Certificate cert = TestUtils.getMyBoatCert();

        PKIIdentity identity = CertificateHandler.getIdentityFromCert(cert);
        assertNotNull(identity);
        assertEquals("UID=urn:mrn:mcp:vessel:idp1:bootstrap:myboat,CN=My Boat,OU=vessel,O=urn:mrn:mcp:org:idp1:bootstrap,C=DK", identity.getDn());
        assertEquals("urn:mrn:mcp:org:idp1:bootstrap", identity.getO());
        assertEquals("My Boat", identity.getCn());
        assertEquals("12345678", identity.getImoNumber());
        assertEquals("urn:mrn:mcp:vessel:idp1:bootstrap:myboat", identity.getMrn());
        assertNull(identity.getPermissions());
    }

    @Test
    void getIdentityFromCertWithEscapedCharacters() {
        X509Certificate cert = TestUtils.getTestUserCert();

        String certDN = cert.getSubjectX500Principal().getName();
        X500Name x500Name = new X500Name(certDN);
        String email = CertificateHandler.getElement(x500Name, BCStyle.EmailAddress);
        assertEquals("info\\+test@maritimeconnectivity.net", email);

        PKIIdentity identity = CertificateHandler.getIdentityFromCert(cert);
        assertNotNull(identity);
        assertEquals("info+test@maritimeconnectivity.net", identity.getEmail());
    }

}
