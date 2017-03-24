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
package net.maritimecloud.pki;


import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static net.maritimecloud.pki.PKIConstants.*;

@Slf4j
@AllArgsConstructor
public class BootStrap {

    private CertificateBuilder certificateBuilder;
    private PKIConfiguration pkiConfiguration;

    /**
     * Generates a self-signed certificate based on the keypair and saves it in the keystore.
     * Should only be used to init the CA.
     */
    public void initCA(String rootCertX500Name, String mcidregCertX500Name, String crlUrl, String ocspUrl, String outputCaCrlPath) {
        if (pkiConfiguration.getKeystorePassword() == null) {
            pkiConfiguration.setKeystorePassword("changeit");
        }
        if (pkiConfiguration.getRootCaKeystorePath() == null) {
            pkiConfiguration.setRootCaKeystorePath("mc-root-keystore.jks");
        }
        if (pkiConfiguration.getSubCaKeystorePath() == null) {
            pkiConfiguration.setSubCaKeystorePath("mc-it-keystore.jks");
        }
        if (pkiConfiguration.getTruststorePassword() == null) {
            pkiConfiguration.setTruststorePassword("changeit");
        }
        if (pkiConfiguration.getTruststorePath() == null) {
            pkiConfiguration.setTruststorePath("mc-truststore.jks");
        }
        KeyPair cakp = certificateBuilder.generateKeyPair();
        KeyPair imkp = certificateBuilder.generateKeyPair();
        KeyStore rootks = null;
        KeyStore itks;
        KeyStore ts;
        FileOutputStream rootfos = null;
        FileOutputStream itfos = null;
        FileOutputStream tsfos = null;
        try {
            rootks = KeyStore.getInstance(KEYSTORE_TYPE); // KeyStore.getDefaultType()
            rootks.load(null, pkiConfiguration.getKeystorePassword().toCharArray());
            itks = KeyStore.getInstance(KEYSTORE_TYPE); // KeyStore.getDefaultType()
            itks.load(null, pkiConfiguration.getKeystorePassword().toCharArray());
            // Store away the keystore.
            rootfos = new FileOutputStream(pkiConfiguration.getRootCaKeystorePath());
            itfos = new FileOutputStream(pkiConfiguration.getSubCaKeystorePath());
            X509Certificate cacert;
            try {
                cacert = certificateBuilder.buildAndSignCert(certificateBuilder.generateSerialNumber(), cakp.getPrivate(), cakp.getPublic(), cakp.getPublic(),
                        new X500Name(rootCertX500Name), new X500Name(rootCertX500Name), null, "ROOTCA", ocspUrl, crlUrl);
            } catch (Exception e) {
                throw new RuntimeException(e.getMessage(), e);
            }
            X509Certificate imcert;
            try {
                imcert = certificateBuilder.buildAndSignCert(certificateBuilder.generateSerialNumber(), cakp.getPrivate(), cakp.getPublic(), imkp.getPublic(),
                        new X500Name(rootCertX500Name), new X500Name(mcidregCertX500Name), null, "INTERMEDIATE", ocspUrl, crlUrl);
            } catch (Exception e) {
                throw new RuntimeException(e.getMessage(), e);
            }
            Certificate[] certChain = new Certificate[1];
            certChain[0] = cacert;
            rootks.setKeyEntry(ROOT_CERT_ALIAS, cakp.getPrivate(), pkiConfiguration.getKeystorePassword().toCharArray(), certChain);
            rootks.store(rootfos, pkiConfiguration.getKeystorePassword().toCharArray());
            rootks = KeyStore.getInstance(KeyStore.getDefaultType());
            rootks.load(null, pkiConfiguration.getKeystorePassword().toCharArray());

            certChain = new Certificate[2];
            certChain[0] = imcert;
            certChain[1] = cacert;
            itks.setKeyEntry(INTERMEDIATE_CERT_ALIAS, imkp.getPrivate(), pkiConfiguration.getKeystorePassword().toCharArray(), certChain);
            itks.store(itfos, pkiConfiguration.getKeystorePassword().toCharArray());

            // Store away the truststore.
            ts = KeyStore.getInstance(KeyStore.getDefaultType());
            ts.load(null, pkiConfiguration.getTruststorePassword().toCharArray());
            tsfos = new FileOutputStream(pkiConfiguration.getTruststorePath());
            ts.setCertificateEntry(ROOT_CERT_ALIAS, cacert);
            ts.setCertificateEntry(INTERMEDIATE_CERT_ALIAS, imcert);
            ts.store(tsfos, pkiConfiguration.getTruststorePassword().toCharArray());
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new RuntimeException(e.getMessage(), e);
        } finally {
            safeClose(rootfos);
            safeClose(itfos);
            safeClose(tsfos);

            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(pkiConfiguration.getKeystorePassword().toCharArray());
            KeyStore.PrivateKeyEntry rootCertEntry;
            try {
                if (rootks != null) {
                    rootCertEntry = (KeyStore.PrivateKeyEntry) rootks.getEntry(ROOT_CERT_ALIAS, protParam);
                    Revocation.generateRootCACRL(rootCertX500Name, null, rootCertEntry, outputCaCrlPath);
                }
            } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
                // todo, I think is an irrecoverable state, but we should not throw exception from finally, perhaps this code should not be in a finally block
                log.error("unable to generate RootCACRL", e);
            }

        }
    }

    private void safeClose(FileOutputStream stream) {
        if (stream != null) {
            try {
                stream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

}
