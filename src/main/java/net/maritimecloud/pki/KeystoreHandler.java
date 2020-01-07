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


import lombok.extern.slf4j.Slf4j;
import net.maritimecloud.pki.exception.PKIRuntimeException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import static net.maritimecloud.pki.PKIConstants.KEYSTORE_TYPE;
import static net.maritimecloud.pki.PKIConstants.ROOT_CERT_ALIAS;

@Slf4j
public class KeystoreHandler {

    private PKIConfiguration pkiConfiguration;

    public KeystoreHandler(PKIConfiguration pkiConfiguration) {
        this.pkiConfiguration = pkiConfiguration;
        // Set Bouncy Castle as Provider, used for Certificates.
        Security.addProvider(new BouncyCastleProvider());

    }
    /**
     * Loads the MCP certificate used for signing from the (jks) keystore
     *
     * @param alias Alias of the signing certificate
     * @return a PrivateKeyEntry of the signing certificate
     */
    public KeyStore.PrivateKeyEntry getSigningCertEntry(String alias) {
        try (FileInputStream is = new FileInputStream(pkiConfiguration.getSubCaKeystorePath())) {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            keyStore.load(is, pkiConfiguration.getSubCaKeystorePassword().toCharArray());
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(pkiConfiguration.getSubCaKeyPassword().toCharArray());
            return (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, protParam);
        } catch (FileNotFoundException e) {
            log.error("Could not open CA keystore", e);
            throw new PKIRuntimeException(e.getMessage(), e);
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException e) {
            log.error("Could not get CA entry", e);
            throw new PKIRuntimeException(e.getMessage(), e);
        }
    }

    /**
     * Returns a MCP certificate from the truststore
     *
     * @param alias Either ROOT_CERT_ALIAS or INTERMEDIATE_CERT_ALIAS
     * @return a certificate
     */
    public Certificate getMCCertificate(String alias) {
        log.debug(pkiConfiguration.getTruststorePath());
        try (FileInputStream is = new FileInputStream(pkiConfiguration.getTruststorePath())) {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            keyStore.load(is, pkiConfiguration.getTruststorePassword().toCharArray());
            return keyStore.getCertificate(alias);
        } catch (FileNotFoundException e) {
            log.error("Could not open truststore", e);
            throw new PKIRuntimeException(e.getMessage(), e);
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            log.error("Could not load CA certificate", e);
            throw new PKIRuntimeException(e.getMessage(), e);
        }
    }

    /**
     * Returns the truststore defined in PKIConfiguration.
     *
     * @return a truststore
     */
    public KeyStore getTrustStore() {
        try (FileInputStream is = new FileInputStream(pkiConfiguration.getTruststorePath())) {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            keyStore.load(is, pkiConfiguration.getTruststorePassword().toCharArray());
            return keyStore;
        } catch (FileNotFoundException e) {
            log.error("Could not open truststore", e);
            throw new PKIRuntimeException(e.getMessage(), e);
        } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException e) {
            log.error("Could not load truststore", e);
            throw new PKIRuntimeException(e.getMessage(), e);
        }
    }

    /**
     * Returns the public key of the root certificate
     *
     * @return public key
     */
    public PublicKey getRootPubKey() {
        Certificate rootCert = getMCCertificate(ROOT_CERT_ALIAS);
        return rootCert.getPublicKey();
    }

    /**
     * Returns the public key of the sub CA certificate with the given alias
     *
     * @param alias Alias of a sub CA
     * @return
     */
    public PublicKey getPubKey(String alias) {
        Certificate cert = getMCCertificate(alias);
        return cert.getPublicKey();
    }

}
