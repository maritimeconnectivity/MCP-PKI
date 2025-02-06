/*
 * Copyright 2017 Danish Maritime Authority.
 * Copyright 2020 Maritime Connectivity Platform Consortium
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
            String pemCertificate = CertificateHandler.getPemFromEncoded("CERTIFICATE", cert.getEncoded());
            assertEquals("""
                    -----BEGIN CERTIFICATE-----
                    MIIENjCCA7ugAwIBAgIUII+9IChj/7XTKj6SyeSkyDtIhe0wCgYIKoZIzj0EAwMw
                    gdwxLTArBgoJkiaJk/IsZAEBDB11cm46bXJuOm1jcDpjYTppZHAxOm1jcC1pZHJl
                    ZzELMAkGA1UEBhMCREsxEDAOBgNVBAgMB0Rlbm1hcmsxEzARBgNVBAcMCkNvcGVu
                    aGFnZW4xETAPBgNVBAoMCE1DUCBUZXN0MREwDwYDVQQLDAhNQ1AgVGVzdDEjMCEG
                    A1UEAwwaTUNQIFRlc3QgSWRlbnRpdHkgUmVnaXN0cnkxLDAqBgkqhkiG9w0BCQEW
                    HWluZm9AbWFyaXRpbWVjb25uZWN0aXZpdHkubmV0MB4XDTI1MDIwNjEwNDUzMloX
                    DTI3MDIwNjEwNDUzMlowgZMxCzAJBgNVBAYTAkRLMScwJQYDVQQKDB51cm46bXJu
                    Om1jcDpvcmc6aWRwMTpib290c3RyYXAxDzANBgNVBAsMBnZlc3NlbDEQMA4GA1UE
                    AwwHTXkgQm9hdDE4MDYGCgmSJomT8ixkAQEMKHVybjptcm46bWNwOnZlc3NlbDpp
                    ZHAxOmJvb3RzdHJhcDpteWJvYXQwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASERM5l
                    LR9sm2hLuRf+Ol6sPtuiieUFJCZO4iF/JPNOu18uSPsSjE2CmTBUrEu0I9TlC/bC
                    yMadd1t/h+oeupgYllMq0Owv7mUdGGAyTcTSUqBVIoUoWUvt23xoW1S9bcGjggGD
                    MIIBfzBxBgNVHREEajBooCIGFGmDtqOX2Juv+MfLmeyAgKqu14oboAoMCDEyMzQ1
                    Njc4oEIGFGmDmLzXwJ7w8MfLqp2AgKqu14oboCoMKHVybjptcm46bWNwOnZlc3Nl
                    bDppZHAxOmJvb3RzdHJhcDpteWJvYXQwHwYDVR0jBBgwFoAU0OaAYMyxB3t43CCu
                    70+PjaPwIkAwHQYDVR0OBBYEFFupEEv3dswll3YO0SKNthRerPkWMF4GA1UdHwRX
                    MFUwU6BRoE+GTWh0dHA6Ly9sb2NhbGhvc3Q6ODg4OC94NTA5L2FwaS9jZXJ0aWZp
                    Y2F0ZXMvY3JsL3Vybjptcm46bWNwOmNhOmlkcDE6bWNwLWlkcmVnMGoGCCsGAQUF
                    BwEBBF4wXDBaBggrBgEFBQcwAYZOaHR0cDovL2xvY2FsaG9zdDo4ODg4L3g1MDkv
                    YXBpL2NlcnRpZmljYXRlcy9vY3NwL3Vybjptcm46bWNwOmNhOmlkcDE6bWNwLWlk
                    cmVnMAoGCCqGSM49BAMDA2kAMGYCMQD64oFdOsTnI0CDtiuFkhKgpgwFWGRBiJrP
                    KLoCS9AgUzBbORfGXB3xLs/CCfs53ecCMQCjTQuzcWg3UL2eCl6xIlMaOch8aJhM
                    Dov9qgY7AYzP7o7MJUTUOLNXb9KGQb43PVE=
                    -----END CERTIFICATE-----
                    """, pemCertificate);
        } catch (CertificateEncodingException | IOException e) {
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
        X509Certificate cert = CertificateHandler.getCertFromNginxHeader(nginxFormatedPemCert);
        assertNotNull(cert);
        assertEquals("EMAILADDRESS=thc@dma.dk, UID=urn:mrn:mcl:user:dma:thc, CN=Thomas Christensen, OU=user, O=urn:mrn:mcl:org:dma, C=DK", cert.getSubjectDN().getName());
    }

    @Test
    void getCertFromPem1() {
        String certPem = TestUtils.getMyBoatCertPem();
        X509Certificate cert = CertificateHandler.getCertFromPem(certPem);
        assertNotNull(cert);
        assertEquals(new BigInteger("185893186394517931681837591107919652652484953581"), cert.getSerialNumber());
    }

    @Test
    void getCertFromPem2() {
        String certPem = TestUtils.getEcdisCertPem();
        X509Certificate cert = CertificateHandler.getCertFromPem(certPem);
        assertNotNull(cert);
        assertEquals(new BigInteger("682123668671150200528178418440390652882987258659"), cert.getSerialNumber());
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

        assertEquals("E=info+test@maritimeconnectivity.net,UID=urn:mrn:mcp:user:mcc-test:core:test,CN=Test Test,OU=user,O=urn:mrn:mcp:org:mcc-test:core,C=DK", identity.getDn());
    }

}
