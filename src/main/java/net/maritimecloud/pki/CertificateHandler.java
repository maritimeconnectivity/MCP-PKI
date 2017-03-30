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
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERTaggedObject;
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
import java.io.IOException;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
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
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;


import static net.maritimecloud.pki.PKIConstants.BC_PROVIDER_NAME;
import static net.maritimecloud.pki.PKIConstants.MC_OID_FLAGSTATE;
import static net.maritimecloud.pki.PKIConstants.MC_OID_CALLSIGN;
import static net.maritimecloud.pki.PKIConstants.MC_OID_IMO_NUMBER;
import static net.maritimecloud.pki.PKIConstants.MC_OID_MMSI_NUMBER;
import static net.maritimecloud.pki.PKIConstants.MC_OID_AIS_SHIPTYPE;
import static net.maritimecloud.pki.PKIConstants.MC_OID_MRN;
import static net.maritimecloud.pki.PKIConstants.MC_OID_PERMISSIONS;
import static net.maritimecloud.pki.PKIConstants.MC_OID_PORT_OF_REGISTER;
import static org.bouncycastle.asn1.x500.style.IETFUtils.valueToString;


@Slf4j
public class CertificateHandler {

    /*private KeystoreHandler keystoreHandler;

    public CertificateHandler(KeystoreHandler keystoreHandler) {
        this.keystoreHandler = keystoreHandler;
    }*/


    public static boolean verifyCertificate(PublicKey verificationPubKey, X509Certificate certToVerify) {
        //Certificate rootCert = keystoreHandler.getMCCertificate(INTERMEDIATE_CERT_ALIAS);
        JcaX509CertificateHolder certHolder;
        try {
            certHolder = new JcaX509CertificateHolder(certToVerify);
        } catch (CertificateEncodingException e) {
            log.error("Could not create JcaX509CertificateHolder", e);
            return false;
        }

        ContentVerifierProvider contentVerifierProvider;
        try {
            contentVerifierProvider = new JcaContentVerifierProviderBuilder().setProvider(BC_PROVIDER_NAME).build(verificationPubKey);
        } catch (OperatorCreationException e) {
            log.error("Could not create ContentVerifierProvider from public key", e);
            return false;
        }
        if (contentVerifierProvider == null) {
            log.error("Created ContentVerifierProvider from root public key is null");
            return false;
        }
        try {
            if (certHolder.isSignatureValid(contentVerifierProvider)) {
                return true;
            }
        } catch (CertException e) {
            log.error("Error when trying to validate signature", e);
            return false;
        }
        log.debug("Certificate does not seem to be valid!");
        return false;
    }

    public static boolean verifyCertificateChain(X509Certificate certificate, KeyStore ks) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, InvalidAlgorithmParameterException, CertPathValidatorException {

        // Create the certificate path to verify - in this case just the given certificate
        List<Certificate> certList = Collections.singletonList(certificate);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        CertPath certPath = cf.generateCertPath(certList);

        // Create validator and revocation checker
        CertPathValidator validator = CertPathValidator.getInstance("PKIX");
        PKIXRevocationChecker rc = (PKIXRevocationChecker)validator.getRevocationChecker();
        rc.setOptions(EnumSet.of(PKIXRevocationChecker.Option.NO_FALLBACK));
        PKIXParameters pkixp = new PKIXParameters(ks);
        pkixp.addCertPathChecker(rc);
        pkixp.setRevocationEnabled(false);

        // Do the actual validation!
        PKIXCertPathValidatorResult pcpvr =  (PKIXCertPathValidatorResult)validator.validate(certPath, pkixp);
        return (pcpvr != null);
    }

    /**
     * Convert a cert/key to pem from "encoded" format (byte[])
     *
     * @param type The type, currently "CERTIFICATE", "PUBLIC KEY", "PRIVATE KEY" or "X509 CRL" are used
     * @param encoded The encoded byte[]
     * @return The Pem formated cert/key
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
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return pemFormat;
    }

    public static X509Certificate getCertFromNginxHeader(String certificateHeader) {
        // nginx forwards the certificate in a header by replacing new lines with whitespaces
        // (2 or more). Also replace tabs, which nginx sometimes sends instead of whitespaces.
        String certificateContent = certificateHeader.replaceAll("\\s{2,}", System.lineSeparator()).replaceAll("\\t+", System.lineSeparator());
        if (certificateContent == null || certificateContent.length() < 10) {
            log.debug("No certificate content found");
            return null;
        }
        return getCertFromPem(certificateContent);
    }

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
            userCertificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(pemCertificate.getBytes("ISO-8859-11")));
        } catch (CertificateException | UnsupportedEncodingException e) {
            log.error("Exception while converting certificate extracted from header", e);
            return null;
        }
        log.debug("Certificate was extracted from the header");
        return userCertificate;
    }

    public static PKIIdentity getIdentityFromCert(X509Certificate userCertificate) {
        PKIIdentity identity = new PKIIdentity();
        String certDN = userCertificate.getSubjectDN().getName();
        X500Name x500name = new X500Name(certDN);
        String name = getElement(x500name, BCStyle.CN);
        String uid = getElement(x500name, BCStyle.UID);
        identity.setMrn(uid);
        identity.setDn(certDN);
        identity.setCn(name);
        identity.setSn(name);
        identity.setO(getElement(x500name, BCStyle.O));
        identity.setOu(getElement(x500name, BCStyle.OU));
        identity.setCountry(getElement(x500name, BCStyle.C));
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
            for (List item : san) {
                Integer type = (Integer) item.get(0);
                if (type == 0) {
                    // Type OtherName found so return the associated value
                    ASN1InputStream decoder = null;
                    String oid;
                    String value;
                    try {
                        // Value is encoded using ASN.1 so decode it to get it out again
                        decoder = new ASN1InputStream((byte[]) item.toArray()[1]);
                        DLSequence seq = (DLSequence) decoder.readObject();
                        ASN1ObjectIdentifier asnOID = (ASN1ObjectIdentifier) seq.getObjectAt(0);
                        ASN1Encodable encoded = seq.getObjectAt(1);
                        oid = asnOID.getId();
                        // For some weird reason we need to do this 2 times - otherwise we get a
                        // ClassCastException when extracting the value.
                        encoded = ((DERTaggedObject) encoded).getObject();
                        encoded = ((DERTaggedObject) encoded).getObject();
                        value = ((DERUTF8String) encoded).getString();
                    } catch (UnsupportedEncodingException e) {
                        log.error("Error decoding subjectAltName" + e.getLocalizedMessage(), e);
                        continue;
                    } catch (Exception e) {
                        log.error("Error decoding subjectAltName" + e.getLocalizedMessage(), e);
                        continue;
                    } finally {
                        if (decoder != null) {
                            try {
                                decoder.close();
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }
                    }
                    log.debug("oid: " + oid + ", value: " + value);
                    switch (oid) {
                        case MC_OID_FLAGSTATE:
                            identity.setFlagState(value);
                            break;
                        case MC_OID_CALLSIGN:
                            identity.setCallSign(value);
                            break;
                        case MC_OID_IMO_NUMBER:
                            identity.setImoNumber(value);
                            break;
                        case MC_OID_MMSI_NUMBER:
                            identity.setMmsiNumber(value);
                            break;
                        case MC_OID_AIS_SHIPTYPE:
                            identity.setAisShipType(value);
                            break;
                        case MC_OID_PORT_OF_REGISTER:
                            identity.setPortOfRegister(value);
                            break;
                        case MC_OID_MRN:
                            // We only support 1 mrn
                            identity.setMrn(value);
                            break;
                        case MC_OID_PERMISSIONS:
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
}
