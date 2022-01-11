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

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.maritimeconnectivity.pki.exception.PKIRuntimeException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.List;

import static org.bouncycastle.asn1.x500.style.IETFUtils.rDNsFromString;
import static org.bouncycastle.asn1.x500.style.IETFUtils.valueToString;

/**
 * Class that holds functions for handling certificates.
 */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class CertificateHandler {

    /**
     * Verify a single certificate against the public key of the issueing certificate. Does *not* check revocation
     * status against CRL/OCSP.
     * In most cases you should probably use
     * {@link #verifyCertificateChain(X509Certificate, KeyStore) verifyCertificateChain} instead to verify the
     * complete chain.
     *
     * @param verificationPubKey Public key of the issuing certificate
     * @param certToVerify The certificate to verify
     * @param verificationDate Date the certificate must be valid. If null the present day is used.
     * @return true if valid else false
     */
    public static boolean verifyCertificate(PublicKey verificationPubKey, X509Certificate certToVerify, Date verificationDate) {
        JcaX509CertificateHolder certHolder;
        try {
            certHolder = new JcaX509CertificateHolder(certToVerify);
        } catch (CertificateEncodingException e) {
            log.error("Could not create JcaX509CertificateHolder", e);
            return false;
        }

        ContentVerifierProvider contentVerifierProvider;
        try {
            contentVerifierProvider = new JcaContentVerifierProviderBuilder().setProvider(PKIConstants.BC_PROVIDER_NAME).build(verificationPubKey);
        } catch (OperatorCreationException e) {
            log.error("Could not create ContentVerifierProvider from public key", e);
            return false;
        }
        if (contentVerifierProvider == null) {
            log.error("Created ContentVerifierProvider from root public key is null");
            return false;
        }
        boolean signatureValidity;
        try {
            signatureValidity = certHolder.isSignatureValid(contentVerifierProvider);
        } catch (CertException e) {
            log.error("Error when trying to validate signature", e);
            return false;
        }

        if (signatureValidity) {
            if (verificationDate == null) {
                verificationDate = Date.from(Instant.now());
            }
            if (verificationDate.after(certToVerify.getNotBefore()) && verificationDate.before(certToVerify.getNotAfter())) {
                return true;
            }
            else {
                log.debug("Out of certificate validity period.");
                return false;
            }
        }

        log.debug("Certificate does not seem to be valid!");
        return false;
    }

    /**
     * Verify a single certificate against trust chain in the keystore. If the certificate is invalid a
     * CertPathValidatorException is thrown. Checks certificate validity and revocation status.
     *
     * @param certificate The certificate to verify
     * @param ks The truststore that contains the trust chain
     * @return true if valid.
     * @throws KeyStoreException if keystore loading fails
     * @throws NoSuchAlgorithmException if PKIX initialization fails
     * @throws CertificateException if certificate cannot be loaded
     * @throws InvalidAlgorithmParameterException if keystore loading fails
     * @throws CertPathValidatorException if certificate is invalid.
     */
    public static boolean verifyCertificateChain(X509Certificate certificate, KeyStore ks) throws KeyStoreException,
            NoSuchAlgorithmException, CertificateException, InvalidAlgorithmParameterException, CertPathValidatorException {

        // Create the certificate path to verify - in this case just the given certificate
        List<Certificate> certList = Collections.singletonList(certificate);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        CertPath certPath = cf.generateCertPath(certList);

        // Create validator and revocation checker
        CertPathValidator validator = CertPathValidator.getInstance("PKIX");
        PKIXRevocationChecker rc = (PKIXRevocationChecker)validator.getRevocationChecker();
        rc.setOptions(EnumSet.of(PKIXRevocationChecker.Option.SOFT_FAIL));
        PKIXParameters pkixp = new PKIXParameters(ks);
        pkixp.addCertPathChecker(rc);
        pkixp.setRevocationEnabled(true);

        // Do the actual validation!
        PKIXCertPathValidatorResult pcpvr = (PKIXCertPathValidatorResult)validator.validate(certPath, pkixp);
        return (pcpvr != null);
    }

    /**
     * Convert a cert/key to PEM from "encoded" format (byte[])
     *
     * @param type The type, currently "CERTIFICATE", "PUBLIC KEY", "PRIVATE KEY" or "X509 CRL" are used
     * @param encoded The encoded byte[]
     * @return The PEM formatted cert/key
     */
    public static String getPemFromEncoded(String type, byte[] encoded) {
        String pemFormat = "";
        // Write certificate to PEM
        StringWriter perStrWriter = new StringWriter();
        PemWriter pemWrite = new PemWriter(perStrWriter);
        try {
            pemWrite.writeObject(new PemObject(type, encoded));
            pemWrite.flush();
            pemFormat = perStrWriter.toString();
            pemWrite.close();
        } catch (IOException e) {
            throw new PKIRuntimeException(e);
        }
        return pemFormat;
    }

    /**
     * Place a cert/key in a PKCS12 or JKS keystore
     *
     * @param type The keystore type to use (PKCS12 or JKS)
     * @param alias The alias of the certificate in the keystore
     * @param password The password used to protect the key
     * @param privateKey Private key of the certificate
     * @param certificate The certificate
     * @return Byte array of the p12 keystore.
     */
    public static byte[] createOutputKeystore(String type, String alias, String password, PrivateKey privateKey, X509Certificate certificate) {
        // Put them into a JKS keystore and write it to a byte[]
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            KeyStore ks;
            if (type.equals("JKS")) {
                ks = KeyStore.getInstance(type);
            } else {
                ks = KeyStore.getInstance(type, PKIConstants.BC_PROVIDER_NAME);
            }
            ks.load(null);
            ks.setKeyEntry(alias, privateKey, password.toCharArray(), new java.security.cert.Certificate[]{certificate});
            ks.store(bos, password.toCharArray());
            return bos.toByteArray();
        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException | NoSuchProviderException e) {
            throw new PKIRuntimeException(e);
        }
    }

    /**
     * Extract a certificate from a nginx header containing a PEM formatted certificate
     *
     * @param certificateHeader The header containing the certificate
     * @return The extracted certificate. Returns null on failure.
     * @throws UnsupportedEncodingException if given certificate cannot be URL decoded
     */
    public static X509Certificate getCertFromNginxHeader(String certificateHeader) throws UnsupportedEncodingException {
        String certificateContent = URLDecoder.decode(certificateHeader, StandardCharsets.UTF_8);
        // make sure that the + characters in the base64 encoded part have not been converted to spaces
        if (certificateContent.startsWith(PKIConstants.CERT_HEADER) && certificateContent.contains(PKIConstants.CERT_FOOTER)) {
            String middle = certificateContent.split(PKIConstants.CERT_HEADER)[1].split(PKIConstants.CERT_FOOTER)[0];
            if (middle.contains(" ")) {
                middle = middle.replace(" ", "+");
                certificateContent = PKIConstants.CERT_HEADER + middle + PKIConstants.CERT_FOOTER;
            }
        }
        if (certificateContent.trim().isEmpty() || certificateContent.length() < 10) {
            log.debug("No certificate content found");
            return null;
        }
        return getCertFromPem(certificateContent);
    }

    /**
     * Converts a PEM encoded certificate to a X509Certificate
     *
     * @param pemCertificate String containing the PEM encoded certificate
     * @return The converted certificate
     */
    public static X509Certificate getCertFromPem(String pemCertificate) {
        CertificateFactory certificateFactory;
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            log.error("Exception while creating CertificateFactory", e);
            return null;
        }

        X509Certificate userCertificate;
        try {
            userCertificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(pemCertificate.getBytes(StandardCharsets.UTF_8)));
        } catch (CertificateException e) {
            log.error("Exception while converting certificate extracted from header", e);
            return null;
        }
        log.debug("Certificate was extracted from the header");
        return userCertificate;
    }

    /**
     * Extracts a PKIIdentity from a certificate using the MCP PKI certificate "format"
     *
     * @param userCertificate The certificate
     * @return The extracted identity
     */
    public static PKIIdentity getIdentityFromCert(X509Certificate userCertificate) {
        PKIIdentity identity = new PKIIdentity();
        String certDN = userCertificate.getSubjectDN().getName();
        RDN[] rdns = rDNsFromString(certDN, BCStyle.INSTANCE);
        String name = getElement(rdns, BCStyle.CN);
        String uid = getElement(rdns, BCStyle.UID);
        identity.setMrn(uid);
        identity.setDn(certDN);
        identity.setCn(name);
        identity.setSn(name);
        identity.setO(getElement(rdns, BCStyle.O));
        identity.setOu(getElement(rdns, BCStyle.OU));
        identity.setCountry(getElement(rdns, BCStyle.C));
        identity.setEmail(getElement(rdns, BCStyle.EmailAddress));
        // Extract first and last name from full name
        String lastName = "";
        String firstName = "";
        if (name != null && name.split("\\w +\\w").length > 1) {
            lastName = name.substring(name.lastIndexOf(' ')+1);
            firstName = name.substring(0, name.lastIndexOf(' '));
        } else {
            firstName = name;
        }
        identity.setFirstName(firstName);
        identity.setLastName(lastName);
        log.debug("Parsed certificate, name: " + name);

        // Extract info from Subject Alternative Name extension
        Collection<List<?>> san = null;
        try {
            san = userCertificate.getSubjectAlternativeNames();
        } catch (CertificateParsingException e) {
            log.warn("could not extract info from Subject Alternative Names - will be ignored.");
        }
        // Check that the certificate includes the SubjectAltName extension
        if (san != null) {
            // Use the type OtherName to search for the certified server name
            StringBuilder permissions = new StringBuilder();
            for (List<?> item : san) {
                Integer type = (Integer) item.get(0);
                if (type == 0) {
                    // Type OtherName found so return the associated value
                    String oid;
                    String value;
                    try (ASN1InputStream decoder = new ASN1InputStream((byte[]) item.toArray()[1])) {
                        // Value is encoded using ASN.1 so decode it to get it out again
                        DLSequence seq = (DLSequence) decoder.readObject();
                        ASN1ObjectIdentifier asnOID = (ASN1ObjectIdentifier) seq.getObjectAt(0);
                        ASN1Encodable encoded = seq.getObjectAt(1);
                        oid = asnOID.getId();
                        // For some weird reason we need to do this 2 times - otherwise we get a
                        // ClassCastException when extracting the value.
                        encoded = ((ASN1TaggedObject) encoded).getObject();
                        encoded = ((ASN1TaggedObject) encoded).getObject();
                        value = ((DERUTF8String) encoded).getString();
                    } catch (IOException e) {
                        log.error("Error decoding subjectAltName" + e.getLocalizedMessage(), e);
                        continue;
                    }
                    log.debug("oid: " + oid + ", value: " + value);
                    switch (oid) {
                        case PKIConstants.MC_OID_FLAGSTATE:
                            identity.setFlagState(value);
                            break;
                        case PKIConstants.MC_OID_CALLSIGN:
                            identity.setCallSign(value);
                            break;
                        case PKIConstants.MC_OID_IMO_NUMBER:
                            identity.setImoNumber(value);
                            break;
                        case PKIConstants.MC_OID_MMSI_NUMBER:
                            identity.setMmsiNumber(value);
                            break;
                        case PKIConstants.MC_OID_AIS_SHIPTYPE:
                            identity.setAisShipType(value);
                            break;
                        case PKIConstants.MC_OID_PORT_OF_REGISTER:
                            identity.setPortOfRegister(value);
                            break;
                        case PKIConstants.MC_OID_MRN: // primary MRN
                            identity.setMrn(value);
                            break;
                        case PKIConstants.MC_OID_MRN_SUBSIDIARY:
                            identity.setMrnSubsidiary(value);
                            break;
                        case PKIConstants.MC_OID_HOME_MMS_URL:
                            identity.setHomeMmsUrl(value);
                            break;
                        case PKIConstants.MC_OID_SHIP_MRN:
                            identity.setShipMrn(value);
                            break;
                        case PKIConstants.MC_OID_URL:
                            identity.setUrl(value);
                            break;
                        case PKIConstants.MC_OID_PERMISSIONS:
                            if (value != null && !value.trim().isEmpty()) {
                                if (permissions.length() == 0) {
                                    permissions = new StringBuilder(value);
                                } else {
                                    permissions.append(',').append(value);
                                }
                            }
                            break;
                        default:
                            log.error("Unknown OID!");
                            break;
                    }
                } else {
                    // Other types are not supported so ignore them
                    log.warn("SubjectAltName of invalid type found: " + type);
                }
            }
            if (permissions.length() > 0) {
                identity.setPermissions(permissions.toString());
            }
        }
        return identity;
    }

    /**
     * Extract a value from the DN extracted from a certificate
     *
     * @param x500name The full DN from certificate
     * @param objectId The Identifier to find
     * @return the value of the identifier, or null if not found.
     */
    public static String getElement(X500Name x500name, ASN1ObjectIdentifier objectId) {
        try {
            RDN cn = x500name.getRDNs(objectId)[0];
            return valueToString(cn.getFirst().getValue());
        } catch (ArrayIndexOutOfBoundsException e) {
            return null;
        }
    }

    /**
     * Extract a value from the DN extracted from a certificate
     *
     * @param rdns The full DN from certificate
     * @param objectId The Identifier to find
     * @return the value of the identifier, or null if not found.
     */
    public static String getElement(RDN[] rdns, ASN1ObjectIdentifier objectId) {
        for (RDN rdn : rdns) {
            if (rdn.getFirst().getType().equals(objectId)) {
                return ((ASN1String) rdn.getFirst().getValue()).getString();
            }
        }
        return null;
    }
}
