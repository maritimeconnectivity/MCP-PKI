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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import static net.maritimecloud.pki.PKIConstants.KEYSTORE_TYPE;
import static net.maritimecloud.pki.PKIConstants.ROOT_CERT_ALIAS;

@Slf4j
@AllArgsConstructor
public class KeystoreHandler {

    private PKIConfiguration pkiConfiguration;

    /**
     * Loads the MaritimeCloud certificate used for signing from the (jks) keystore
     *
     * @return a keyStore containing
     */
    public KeyStore.PrivateKeyEntry getSigningCertEntry(String alias) {
        FileInputStream is;
        try {
            is = new FileInputStream(pkiConfiguration.getSubCaKeystorePath());
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
        KeyStore keystore;
        try {
            keystore = KeyStore.getInstance(KEYSTORE_TYPE);
            keystore.load(is, pkiConfiguration.getKeystorePassword().toCharArray());
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(pkiConfiguration.getKeystorePassword().toCharArray());
            KeyStore.PrivateKeyEntry signingCertEntry = (KeyStore.PrivateKeyEntry) keystore.getEntry(alias, protParam);
            return signingCertEntry;

        } catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException | UnrecoverableEntryException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    /**
     * Returns a Maritime Cloud certificate from the truststore
     * @param alias Either ROOT_CERT_ALIAS or INTERMEDIATE_CERT_ALIAS
     * @return a certificate
     */
    public Certificate getMCCertificate(String alias) {
        log.debug(pkiConfiguration.getTruststorePath());
        FileInputStream is;
        try {
            is = new FileInputStream(pkiConfiguration.getTruststorePath());
        } catch (FileNotFoundException e) {
            log.error("Could not open truststore", e);
            throw new RuntimeException(e.getMessage(), e);
        }
        KeyStore keystore;
        try {
            keystore = KeyStore.getInstance(KEYSTORE_TYPE);
            keystore.load(is, pkiConfiguration.getTruststorePassword().toCharArray());
            Certificate rootCert = keystore.getCertificate(alias);
            return rootCert;

        } catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException e) {
            log.error("Could not load root certificate", e);
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    public KeyStore getTrustStore() {
        FileInputStream is;
        try {
            is = new FileInputStream(pkiConfiguration.getTruststorePath());
        } catch (FileNotFoundException e) {
            log.error("Could not open truststore", e);
            throw new RuntimeException(e.getMessage(), e);
        }
        KeyStore keystore;
        try {
            keystore = KeyStore.getInstance(KEYSTORE_TYPE);
            keystore.load(is, pkiConfiguration.getTruststorePassword().toCharArray());
            return keystore;

        } catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException e) {
            log.error("Could not load truststore!", e);
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    public PublicKey getRootPubKey() {
        Certificate rootCert = getMCCertificate(ROOT_CERT_ALIAS);
        PublicKey rootPubKey = rootCert.getPublicKey();
        return rootPubKey;
    }

    public PublicKey getPubKey(String alias) {
        Certificate cert = getMCCertificate(alias);
        PublicKey publicKey = cert.getPublicKey();
        return publicKey;
    }

}
