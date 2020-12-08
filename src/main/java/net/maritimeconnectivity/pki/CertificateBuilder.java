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


import net.maritimeconnectivity.pki.exception.PKIRuntimeException;
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
import sun.security.pkcs11.SunPKCS11;

import java.math.BigInteger;
import java.security.AuthProvider;
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
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class CertificateBuilder {

    private KeystoreHandler keystoreHandler;
    private SecureRandom random;

    private final Set<Character> reservedCharacters = new HashSet<>(Arrays.asList(',', '+', '"', '\\', '<', '>', ';', '\f', '\r', '=', '/'));

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
                                            Map<String, String> customAttrs, String type, String ocspUrl, String crlUrl, AuthProvider p11AuthProvider, int validityPeriod) throws NoSuchAlgorithmException, CertIOException, OperatorCreationException, CertificateException {
        // Dates are converted to GMT/UTC inside the cert builder
        Calendar cal = Calendar.getInstance();
        Date now = cal.getTime();
        if (validityPeriod <= 0) {
            throw new IllegalArgumentException("The validity period length should be a positive integer number.");
        }
        cal.add(Calendar.MONTH, validityPeriod);
        Date expire = cal.getTime();
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
        JcaContentSignerBuilder builder = new JcaContentSignerBuilder(PKIConstants.SIGNER_ALGORITHM);
        if (p11AuthProvider != null) {
            builder.setProvider(p11AuthProvider);
        } else {
            builder.setProvider(PKIConstants.BC_PROVIDER_NAME);
        }
        ContentSigner signer = builder.build(signerPrivateKey);
        return new JcaX509CertificateConverter().setProvider(PKIConstants.BC_PROVIDER_NAME).getCertificate(certV3Bldr.build(signer));
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
                                                 String callName, String email, String uid, int validityPeriod, PublicKey publickey,
                                                 Map<String, String> customAttr, String signingAlias, String baseCrlOcspURI,
                                                 AuthProvider p11AuthProvider) throws CertificateException, OperatorCreationException, CertIOException, NoSuchAlgorithmException {
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

        String orgSubjectDn = "C=" + orgCountryCode + ", " +
                "O=" + escapeSpecialCharacters(orgName) + ", " +
                "OU=" + escapeSpecialCharacters(type) + ", " +
                "CN=" + escapeSpecialCharacters(callName) + ", " +
                "UID=" + escapeSpecialCharacters(uid);
        if (email != null && !email.isEmpty()) {
            orgSubjectDn += ", E=" + email;
        }
        X500Name subCaCertX500Name = new X500Name(signingX509Cert.getSubjectDN().getName());
        String alias = CertificateHandler.getElement(subCaCertX500Name, BCStyle.UID);
        String ocspUrl  = baseCrlOcspURI + "ocsp/" + alias;
        String crlUrl = baseCrlOcspURI + "crl/" + alias;
        return buildAndSignCert(serialNumber, signingCertEntry.getPrivateKey(), signingX509Cert.getPublicKey(),
                    publickey, new JcaX509CertificateHolder(signingX509Cert).getSubject(), new X500Name(orgSubjectDn),
                    customAttr, "ENTITY", ocspUrl, crlUrl, p11AuthProvider, validityPeriod);
    }

    /**
     * Generates a keypair (public and private) based on Elliptic curves.
     *
     * @return The generated keypair
     */
    public static KeyPair generateKeyPair(AuthProvider provider) {
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(PKIConstants.ELLIPTIC_CURVE);
        KeyPairGenerator g;
        try {
            g = KeyPairGenerator.getInstance("ECDSA", PKIConstants.BC_PROVIDER_NAME);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new PKIRuntimeException(e.getMessage(), e);
        }
        try {
            SecureRandom secureRandom;
            if (provider instanceof SunPKCS11) {
                secureRandom = SecureRandom.getInstance(PKIConstants.PKCS11, provider);
            } else {
                secureRandom = new SecureRandom();
            }
            g.initialize(ecGenSpec, secureRandom);
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            throw new PKIRuntimeException(e.getMessage(), e);
        }
        return g.generateKeyPair();
    }

    /**
     * Generates a keypair (public and private) based on Elliptic curves on a HSM using PKCS#11
     * @return The generated keypair
     */
    public static KeyPair generateKeyPairPKCS11(AuthProvider provider) {
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(PKIConstants.ELLIPTIC_CURVE);
        KeyPairGenerator g;
        try {
            g = KeyPairGenerator.getInstance("EC", provider);
            g.initialize(ecGenSpec, SecureRandom.getInstance(PKIConstants.PKCS11, provider));
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new PKIRuntimeException(e.getMessage(), e);
        }
        return g.generateKeyPair();
    }

    /**
     * Generate a unique serial number to uniquely identify certificates.
     *
     * @return a unique serialnumber
     */
    public BigInteger generateSerialNumber(AuthProvider p11AuthProvider) {
        // BigInteger => NUMERICAL(50) MySQL
        // Max number supported in X509 serial number 2^159-1 = 730750818665451459101842416358141509827966271487
        BigInteger maxValue = new BigInteger("730750818665451459101842416358141509827966271487");
        // Min number 2^32-1 = 4294967296 - we set a minimum value to avoid collisions with old certificates that has used seq numbers
        BigInteger minValue = BigInteger.ZERO;
        if (p11AuthProvider instanceof SunPKCS11) {
            try {
                return BigIntegers.createRandomInRange(minValue, maxValue, SecureRandom.getInstance("PKCS11", p11AuthProvider));
            } catch (NoSuchAlgorithmException e) {
                throw new PKIRuntimeException(e.getMessage(), e);
            }
        }
        return BigIntegers.createRandomInRange(minValue, maxValue, random);
    }

    /**
     * Escapes characters that are reserved for DN attributes.
     *
     * @param string The string that is going to be escaped
     * @return A string where reserved characters are escaped
     */
    public String escapeSpecialCharacters(String string) {
        String escapedString = string.trim();
        char[] stringChars = escapedString.toCharArray();
        StringBuilder stringBuilder = new StringBuilder();
        for (char c : stringChars) {
            String escaped = "";
            if (reservedCharacters.contains(c)) {
                escaped = "\\" + c;
            } else {
                escaped += c;
            }
            stringBuilder.append(escaped);
        }
        escapedString = stringBuilder.toString();
        if (escapedString.startsWith("#")) {
            escapedString = escapedString.replaceFirst("#", "\\#");
        }
        return escapedString;
    }
}
