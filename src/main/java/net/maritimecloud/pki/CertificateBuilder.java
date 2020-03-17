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


import net.maritimecloud.pki.exception.PKIRuntimeException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;

import static net.maritimecloud.pki.PKIConstants.BC_PROVIDER_NAME;
import static net.maritimecloud.pki.PKIConstants.CERT_EXPIRE_YEAR;
import static net.maritimecloud.pki.PKIConstants.ELLIPTIC_CURVE;
import static net.maritimecloud.pki.PKIConstants.SIGNER_ALGORITHM;

public class CertificateBuilder {

    private KeystoreHandler keystoreHandler;
    private SecureRandom random;

    public CertificateBuilder(KeystoreHandler keystoreHandler) {
        this.keystoreHandler = keystoreHandler;
        this.random = new SecureRandom();
    }

    /**
     * Builds and signs a certificate. The certificate will be build on the given subject-public-key and signed with
     * the given issuer-private-key. The issuer and subject will be identified in the strings provided.
     *
     * @param serialNumber The serialnumber of the new certificate.
     * @param signerPrivateKey Private key for signing the certificate
     * @param signerPublicKey Public key of the signing certificate
     * @param subjectPublicKey Public key for the new certificate
     * @param issuer DN of the signing certificate
     * @param subject DN of the new certificate
     * @param customAttrs The custom MC attributes to include in the certificate
     * @param type Type of certificate, can be "ROOT", "INTERMEDIATE" or "ENTITY".
     * @param ocspUrl OCSP endpoint
     * @param crlUrl CRL endpoint - can be null
     * @return A signed X509Certificate
     * @throws Exception Throws exception on certificate generation errors.
     */
    public X509Certificate buildAndSignCert(BigInteger serialNumber, PrivateKey signerPrivateKey, PublicKey signerPublicKey, PublicKey subjectPublicKey, X500Name issuer, X500Name subject,
                                            Map<String, String> customAttrs, String type, String ocspUrl, String crlUrl) throws NoSuchAlgorithmException, CertIOException, OperatorCreationException, CertificateException {
        // Dates are converted to GMT/UTC inside the cert builder
        Calendar cal = Calendar.getInstance();
        Date now = cal.getTime();
        Date expire = new GregorianCalendar(CERT_EXPIRE_YEAR, 0, 1).getTime();
        X509v3CertificateBuilder certV3Bldr = new JcaX509v3CertificateBuilder(issuer,
                serialNumber,
                now, // Valid from now...
                expire, // until CERT_EXPIRE_YEAR
                subject,
                subjectPublicKey);
        JcaX509ExtensionUtils extensionUtil = new JcaX509ExtensionUtils();
        // Create certificate extensions
        if ("ROOTCA".equals(type)) {
            certV3Bldr = certV3Bldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
                    .addExtension(Extension.keyUsage, true, new X509KeyUsage(X509KeyUsage.digitalSignature |
                            X509KeyUsage.nonRepudiation   |
                            X509KeyUsage.keyEncipherment  |
                            X509KeyUsage.keyCertSign      |
                            X509KeyUsage.cRLSign));
        } else if ("INTERMEDIATE".equals(type)) {
            certV3Bldr = certV3Bldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
                    .addExtension(Extension.keyUsage, true, new X509KeyUsage(X509KeyUsage.digitalSignature |
                            X509KeyUsage.nonRepudiation   |
                            X509KeyUsage.keyEncipherment  |
                            X509KeyUsage.keyCertSign      |
                            X509KeyUsage.cRLSign));
        } else {
            // Subject Alternative Name
            GeneralName[] genNames = null;
            if (customAttrs != null && !customAttrs.isEmpty()) {
                genNames = new GeneralName[customAttrs.size()];
                Iterator<Map.Entry<String,String>> it = customAttrs.entrySet().iterator();
                int idx = 0;
                while (it.hasNext()) {
                    Map.Entry<String,String> pair = it.next();
                    if (PKIConstants.X509_SAN_DNSNAME.equals(pair.getKey())) {
                        genNames[idx] = new GeneralName(GeneralName.dNSName, pair.getValue());
                    } else {
                        //genNames[idx] = new GeneralName(GeneralName.otherName, new DERUTF8String(pair.getKey() + ";" + pair.getValue()));
                        DERSequence othernameSequence = new DERSequence(new ASN1Encodable[]{
                                new ASN1ObjectIdentifier(pair.getKey()), new DERTaggedObject(true, 0, new DERUTF8String(pair.getValue()))});
                        genNames[idx] = new GeneralName(GeneralName.otherName, othernameSequence);
                    }
                    idx++;
                }
            }
            if (genNames != null) {
                certV3Bldr = certV3Bldr.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(genNames));
            }
        }
        // Basic extension setup
        certV3Bldr = certV3Bldr.addExtension(Extension.authorityKeyIdentifier, false, extensionUtil.createAuthorityKeyIdentifier(signerPublicKey))
                .addExtension(Extension.subjectKeyIdentifier, false, extensionUtil.createSubjectKeyIdentifier(subjectPublicKey));
        // CRL Distribution Points
        DistributionPointName distPointOne = new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl)));
        DistributionPoint[] distPoints = new DistributionPoint[1];
        distPoints[0] = new DistributionPoint(distPointOne, null, null);
        certV3Bldr.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(distPoints));
        // OCSP endpoint - is not available for the CAs
        if (ocspUrl != null) {
            GeneralName ocspName = new GeneralName(GeneralName.uniformResourceIdentifier, ocspUrl);
            AuthorityInformationAccess authorityInformationAccess = new AuthorityInformationAccess(X509ObjectIdentifiers.ocspAccessMethod, ocspName);
            certV3Bldr.addExtension(Extension.authorityInfoAccess, false, authorityInformationAccess);
        }
        // Create the key signer
        JcaContentSignerBuilder builder = new JcaContentSignerBuilder(SIGNER_ALGORITHM);
        builder.setProvider(BC_PROVIDER_NAME);
        ContentSigner signer = builder.build(signerPrivateKey);
        return new JcaX509CertificateConverter().setProvider(BC_PROVIDER_NAME).getCertificate(certV3Bldr.build(signer));
    }

    /**
     * Generates a signed certificate for an entity.
     *
     * @param country The country of org/entity
     * @param orgName The name of the organization the entity belongs to
     * @param type The type of the  entity
     * @param callName The name of the entity
     * @param email The email of the entity
     * @param publickey The public key of the entity
     * @param baseCrlOcspURI The base URI used for the CRL and OCSP endpoint. This will be prepended: (ocsp|crl)/urn:mrn:mcl:ca:...
     * @return Returns a signed X509Certificate
     */
    public X509Certificate generateCertForEntity(BigInteger serialNumber, String country, String orgName, String type,
                                                 String callName, String email, String uid, PublicKey publickey,
                                                 Map<String, String> customAttr, String signingAlias, String baseCrlOcspURI) throws CertificateException, OperatorCreationException, CertIOException, NoSuchAlgorithmException {
        KeyStore.PrivateKeyEntry signingCertEntry = keystoreHandler.getSigningCertEntry(signingAlias);
        Certificate signingCert = signingCertEntry.getCertificate();
        X509Certificate signingX509Cert = (X509Certificate) signingCert;
        // Try to find the correct country code, else we just use the country name as code
        String orgCountryCode = country;
        String[] locales = Locale.getISOCountries();
        for (String countryCode : locales) {
            Locale loc = new Locale("", countryCode);
            if (loc.getDisplayCountry(Locale.ENGLISH).equals(orgCountryCode)) {
                orgCountryCode = loc.getCountry();
                break;
            }
        }

        Map<String, String> commasConverted = convertCommas(orgName, type, callName, uid);

        String orgSubjectDn = "C=" + orgCountryCode + ", " +
                "O=" + commasConverted.get("orgName") + ", " +
                "OU=" + commasConverted.get("type") + ", " +
                "CN=" + commasConverted.get("callName") + ", " +
                "UID=" + commasConverted.get("uid");
        if (email != null && !email.isEmpty()) {
            orgSubjectDn += ", E=" + email;
        }
        X500Name subCaCertX500Name = new X500Name(signingX509Cert.getSubjectDN().getName());
        String alias = CertificateHandler.getElement(subCaCertX500Name, BCStyle.UID);
        String ocspUrl  = baseCrlOcspURI + "ocsp/" + alias;
        String crlUrl = baseCrlOcspURI + "crl/" + alias;
        return buildAndSignCert(serialNumber, signingCertEntry.getPrivateKey(), signingX509Cert.getPublicKey(),
                    publickey, new JcaX509CertificateHolder(signingX509Cert).getSubject(), new X500Name(orgSubjectDn), customAttr, "ENTITY",
                    ocspUrl, crlUrl);
    }

    /**
     * Generates a keypair (public and private) based on Elliptic curves.
     *
     * @return The generated keypair
     */
    public static KeyPair generateKeyPair() {
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(ELLIPTIC_CURVE);
        KeyPairGenerator g;
        try {
            g = KeyPairGenerator.getInstance("ECDSA", BC_PROVIDER_NAME);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new PKIRuntimeException(e.getMessage(), e);
        }
        try {
            g.initialize(ecGenSpec, new SecureRandom());
        } catch (InvalidAlgorithmParameterException e) {
            throw new PKIRuntimeException(e.getMessage(), e);
        }
        return g.generateKeyPair();
    }

    /**
     * Generate a unique serial number to uniquely identify certificates.
     *
     * @return a unique serialnumber
     */
    public BigInteger generateSerialNumber() {
        // BigInteger => NUMERICAL(50) MySQL
        // Max number supported in X509 serial number 2^159-1 = 730750818665451459101842416358141509827966271487
        BigInteger maxValue = new BigInteger("730750818665451459101842416358141509827966271487");
        // Min number 2^32-1 = 4294967296 - we set a minimum value to avoid collisions with old certificates that has used seq numbers
        BigInteger minValue = new BigInteger("4294967296");
        return BigIntegers.createRandomInRange(minValue, maxValue, random);
        //return new BigInteger(159, random).abs();
    }

    /**
     * Converts any commas in the given strings to something that looks like a comma, but isn't
     *
     * @return a HashMap of the converted strings
     */
    public Map<String, String> convertCommas(String orgName, String type, String callName, String uid) {
        HashMap<String, String> commasConverted = new HashMap<>();
        String[] values = new String[] {orgName, type, callName, uid};
        for (int i = 0; i < values.length; i++) {
            values[i] = values[i].replaceAll(",", "\u201A");
        }

        commasConverted.put("orgName", values[0]);
        commasConverted.put("type", values[1]);
        commasConverted.put("callName", values[2]);
        commasConverted.put("uid", values[3]);

        return commasConverted;
    }
}
