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
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CRLReason;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static net.maritimecloud.pki.PKIConstants.*;

@Slf4j
@AllArgsConstructor
public class CAHandler {

    private CertificateBuilder certificateBuilder;
    private PKIConfiguration pkiConfiguration;

    public void createSubCa(String subCaCertDN,String crlUrl, String ocspUrl) {

        // Open the various keystores
        KeyStore rootKeystore;
        InputStream rootKeystoreIS = null;
        KeyStore subCaKeystore;
        KeyStore truststore;
        FileInputStream subCaFis = null;
        FileInputStream trustFis = null;
        try {
            // Open the root keystore
            rootKeystore = KeyStore.getInstance(KEYSTORE_TYPE);
            rootKeystoreIS = new FileInputStream(pkiConfiguration.getRootCaKeystorePath());
            rootKeystore.load(rootKeystoreIS, pkiConfiguration.getRootCaKeystorePassword().toCharArray());

            // Open or create the sub CA keystore
            subCaKeystore = KeyStore.getInstance(KEYSTORE_TYPE);
            if (new File(pkiConfiguration.getSubCaKeystorePath()).exists()) {
                subCaFis = new FileInputStream(pkiConfiguration.getSubCaKeystorePath());
                subCaKeystore.load(subCaFis, pkiConfiguration.getSubCaKeystorePassword().toCharArray());
            } else {
                subCaKeystore.load(null, pkiConfiguration.getSubCaKeystorePassword().toCharArray());
            }

            // Open the truststore
            trustFis = new FileInputStream(pkiConfiguration.getTruststorePath());
            truststore = KeyStore.getInstance(KeyStore.getDefaultType());
            truststore.load(trustFis, pkiConfiguration.getTruststorePassword().toCharArray());

        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            throw new RuntimeException(e);
        } finally {
            safeClose(rootKeystoreIS);
            safeClose(trustFis);
            safeClose(subCaFis);
        }

        // Extract the root certificate
        KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(pkiConfiguration.getRootCaKeystorePassword().toCharArray());
        KeyStore.PrivateKeyEntry rootCertEntry;
        X500Name rootCertX500Name;
        try {
            rootCertEntry = (KeyStore.PrivateKeyEntry) rootKeystore.getEntry(ROOT_CERT_ALIAS, protParam);
            rootCertX500Name = new JcaX509CertificateHolder((X509Certificate) rootCertEntry.getCertificate()).getSubject();
        } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException | CertificateEncodingException e) {
            throw new RuntimeException(e);
        }

        // Create the sub CA certificate
        KeyPair subCaKeyPair = CertificateBuilder.generateKeyPair();
        X509Certificate subCaCert;
        X500Name subCaCertX500Name = new X500Name(subCaCertDN);
        String alias = CertificateHandler.getElement(subCaCertX500Name, BCStyle.UID);
        if (alias == null || alias.trim().isEmpty()) {
            throw new RuntimeException("UID must be defined for sub CA! It will be used as the sub CA alias.");
        }
        try {
            subCaCert = certificateBuilder.buildAndSignCert(certificateBuilder.generateSerialNumber(), rootCertEntry.getPrivateKey(), rootCertEntry.getCertificate().getPublicKey(),
                    subCaKeyPair.getPublic(), rootCertX500Name, subCaCertX500Name, null, "INTERMEDIATE", ocspUrl, crlUrl);
        } catch (Exception e) {
            throw new RuntimeException("Could not create sub CA certificate!", e);
        }

        // Store the sub CA certificate in the Sub CA keystore and the MC truststore
        FileOutputStream trustFos = null;
        FileOutputStream subCaFos = null;
        try {
            Certificate[] certChain = new Certificate[2];
            certChain[0] = subCaCert;
            certChain[1] = rootCertEntry.getCertificate();
            subCaFos = new FileOutputStream(pkiConfiguration.getSubCaKeystorePath());
            subCaKeystore.setKeyEntry(alias, subCaKeyPair.getPrivate(), pkiConfiguration.getSubCaKeyPassword().toCharArray(), certChain);
            subCaKeystore.store(subCaFos, pkiConfiguration.getSubCaKeystorePassword().toCharArray());

            trustFos = new FileOutputStream(pkiConfiguration.getTruststorePath());
            truststore.setCertificateEntry(alias, subCaCert);
            truststore.store(trustFos, pkiConfiguration.getTruststorePassword().toCharArray());

        } catch (NoSuchAlgorithmException | KeyStoreException | CertificateException | IOException e) {
            throw new RuntimeException(e);
        } finally {
            safeClose(trustFos);
            safeClose(subCaFos);
        }

    }

    /**
     * Generates a self-signed certificate based on the keypair and saves it in the keystore.
     * Should only be used to init the root CA.
     */
    public void initRootCA(String rootCertX500Name, String crlUrl) {
        KeyPair cakp = CertificateBuilder.generateKeyPair();
        KeyStore rootks;
        KeyStore ts;
        FileOutputStream rootfos = null;
        FileOutputStream tsfos = null;
        try {
            rootks = KeyStore.getInstance(KEYSTORE_TYPE);
            rootks.load(null, pkiConfiguration.getRootCaKeystorePassword().toCharArray());
            // Store away the keystore.
            rootfos = new FileOutputStream(pkiConfiguration.getRootCaKeystorePath());
            X509Certificate cacert;
            try {
                cacert = certificateBuilder.buildAndSignCert(certificateBuilder.generateSerialNumber(), cakp.getPrivate(), cakp.getPublic(), cakp.getPublic(),
                        new X500Name(rootCertX500Name), new X500Name(rootCertX500Name), null, "ROOTCA", null, crlUrl);
            } catch (Exception e) {
                throw new RuntimeException(e.getMessage(), e);
            }
            System.out.println("org x500-name: " + rootCertX500Name);
            System.out.println("out x500-name: " + (new X500Name(rootCertX500Name)).toString());
            System.out.println("out x500-name: " + cacert.getSubjectDN().getName());
            //System.out.println("out x500-name: " + cacert.getSubjectX500Principal().getName());
            System.out.println("out x500-name: " + new JcaX509CertificateHolder(cacert).getSubject());

            Certificate[] certChain = new Certificate[1];
            certChain[0] = cacert;
            rootks.setKeyEntry(ROOT_CERT_ALIAS, cakp.getPrivate(), pkiConfiguration.getRootCaKeyPassword().toCharArray(), certChain);
            rootks.store(rootfos, pkiConfiguration.getRootCaKeystorePassword().toCharArray());
            rootks = KeyStore.getInstance(KeyStore.getDefaultType());
            rootks.load(null, pkiConfiguration.getRootCaKeystorePassword().toCharArray());

            // Store away the truststore.
            ts = KeyStore.getInstance(KeyStore.getDefaultType());
            ts.load(null, pkiConfiguration.getTruststorePassword().toCharArray());
            tsfos = new FileOutputStream(pkiConfiguration.getTruststorePath());
            ts.setCertificateEntry(ROOT_CERT_ALIAS, cacert);
            ts.store(tsfos, pkiConfiguration.getTruststorePassword().toCharArray());
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new RuntimeException(e.getMessage(), e);
        } finally {
            safeClose(rootfos);
            safeClose(tsfos);
        }
    }

    private void safeClose(InputStream stream) {
        if (stream != null) {
            try {
                stream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private void safeClose(OutputStream stream) {
        if (stream != null) {
            try {
                stream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public List<RevocationInfo> loadRevocationFile(String revocationFile) {
        String csvLine;
        String cvsSplitBy = ";";
        List<RevocationInfo> revocationInfos = new ArrayList<>();
        DateFormat format = new SimpleDateFormat("yyyy-MM-dd");
        try (BufferedReader br = new BufferedReader(new FileReader(revocationFile))) {
            while ((csvLine = br.readLine()) != null) {
                if (csvLine.trim().isEmpty()) {
                    continue;
                }
                String[] revocationInfoSplit = csvLine.split(cvsSplitBy);
                if (revocationInfoSplit.length != 3) {
                    throw new RuntimeException("Missing info from line: " + csvLine);
                }
                RevocationInfo info = new RevocationInfo();
                info.setSerialNumber(new BigInteger(revocationInfoSplit[0].trim()));
                info.setRevokeReason(CRLReason.values()[Revocation.getCRLReasonFromString(revocationInfoSplit[1].trim().toLowerCase())]);
                Date revokedAt = format.parse(revocationInfoSplit[2].trim());
                if (revokedAt == null) {
                    throw new RuntimeException("Invalid date format!");
                }
                info.setRevokedAt(revokedAt);
                revocationInfos.add(info);
            }
        } catch (FileNotFoundException e) {
            throw new RuntimeException("Could not find the revocation info file!", e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (ParseException e) {
            throw new RuntimeException("Invalid date format!", e);
        }

        return revocationInfos;
    }

    public void generateRootCRL(String outputCaCrlPath, String revocationFile) {
        List<RevocationInfo> revocationInfos = loadRevocationFile(revocationFile);

        try {
            KeyStore rootks = KeyStore.getInstance("JKS");
            InputStream readStream = new FileInputStream(pkiConfiguration.getRootCaKeystorePath());
            rootks.load(readStream, pkiConfiguration.getRootCaKeystorePassword().toCharArray());
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(pkiConfiguration.getRootCaKeystorePassword().toCharArray());
            KeyStore.PrivateKeyEntry rootCertEntry;
            rootCertEntry = (KeyStore.PrivateKeyEntry) rootks.getEntry(ROOT_CERT_ALIAS, protParam);
            String rootCertX500Name = new JcaX509CertificateHolder((X509Certificate) rootCertEntry.getCertificate()).getSubject().toString();
            Revocation.generateRootCACRL(rootCertX500Name, revocationInfos, rootCertEntry, outputCaCrlPath);
        } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
            throw new RuntimeException("Unable to generate RootCACRL", e);
        } catch (CertificateException e) {
            throw new RuntimeException("Could not load root certificate!", e);
        } catch (FileNotFoundException e) {
            throw new RuntimeException("Could not find root keystore!", e);
        } catch (IOException e) {
            throw new RuntimeException("Could not load root keystore!", e);
        }
    }
}
