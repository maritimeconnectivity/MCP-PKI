package net.maritimeconnectivity.pki;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;


class CertificateBuilderTest {

    private PKIConfiguration pkiConf;

    private KeystoreHandler kh;

    private CertificateBuilder cb;

    @BeforeEach
    void setUp() {
        pkiConf = new PKIConfiguration(TestUtils.getRootCAAlias());
        pkiConf.setTruststorePassword("changeit");
        pkiConf.setTruststorePath("src/test/resources/ca/mc-truststore.jks");
        pkiConf.setSubCaKeystorePath("src/test/resources/ca/subca-keystore.jks");
        pkiConf.setSubCaKeystorePassword("changeit");
        pkiConf.setSubCaKeyPassword("changeit");
        kh = new KeystoreHandler(pkiConf);
        cb = new CertificateBuilder(kh);
    }

    @Test
    void generateCertForEntity() {
        KeyPair certKeyPair = CertificateBuilder.generateKeyPair(null);
        String userMrn = "urn:mrn:mcl:user:dma:thc";
        String permissions = "NONE";
        String baseCrlOcspPath = "https://localhost/x509/api/certificates/";
        String signingAlias = "urn:mrn:mcl:ca:maritimecloud-idreg";
        int validityPeriod = 12;
        Map<String, String> attrs= new HashMap<>();
        attrs.put(PKIConstants.MC_OID_MRN, userMrn);
        attrs.put(PKIConstants.MC_OID_PERMISSIONS, permissions);
        attrs.put(PKIConstants.MC_OID_MRN_SUBSIDIARY, "urn:mrn:stm:user:dmc:thc");
        attrs.put(PKIConstants.MC_OID_HOME_MMS_URL, "http://smartnav.org/");
        X509Certificate userCert;
        try {
            userCert = cb.generateCertForEntity(BigInteger.ONE, "DK", "urn:mrn:mcl:org:dma", "user", "Thomas Christensen", "thc@dma.dk", userMrn, validityPeriod, certKeyPair.getPublic(), attrs, signingAlias, baseCrlOcspPath, null);
        } catch (Exception e) {
            e.printStackTrace();
            fail("An exception was thrown!");
            return;
        }
        assertNotNull(userCert);
        assertEquals("C=DK,O=urn:mrn:mcl:org:dma,OU=user,CN=Thomas Christensen,UID=urn:mrn:mcl:user:dma:thc,E=thc@dma.dk", userCert.getSubjectDN().getName());

        // check the validity period
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.MONTH, validityPeriod); // add one year to have an invalid date
        Date outOfBorder = cal.getTime();
        cal.add(Calendar.DAY_OF_MONTH, -1); // and minus one day from the invalid date to make it valid.
        Date withinBorder = cal.getTime();
        boolean withinBorderResult = CertificateHandler.verifyCertificate(kh.getPubKey(signingAlias), userCert, withinBorder);
        assertTrue(withinBorderResult);
        boolean outOfBorderResult = CertificateHandler.verifyCertificate(kh.getPubKey(signingAlias), userCert, outOfBorder);
        assertFalse(outOfBorderResult);
    }

    @Test
    void generateCertWithReservedCharactersForEntity() {
        KeyPair certKeyPair = CertificateBuilder.generateKeyPair(null);
        String userMrn = "urn:mrn:mcl:user:dma:thc";
        String permissions = "NONE";
        String baseCrlOcspPath = "https://localhost/x509/api/certificates/";
        String signingAlias = "urn:mrn:mcl:ca:maritimecloud-idreg";
        int validityPeriod = 12;
        Map<String, String> attrs= new HashMap<>();
        attrs.put(PKIConstants.MC_OID_MRN, userMrn);
        attrs.put(PKIConstants.MC_OID_PERMISSIONS, permissions);
        attrs.put(PKIConstants.MC_OID_MRN_SUBSIDIARY, "urn:mrn:stm:user:dmc:thc");
        attrs.put(PKIConstants.MC_OID_HOME_MMS_URL, "http://smartnav.org/");
        X509Certificate userCert;
        try {
            // include reserved characters in some of the attributes
            userCert = cb.generateCertForEntity(BigInteger.ONE, "DK", "urn:mrn:mcl:org:dma", "user", "#Thomas Christensen, extra content ", "thc+bla@dma.dk", userMrn, validityPeriod, certKeyPair.getPublic(), attrs, signingAlias, baseCrlOcspPath, null);
        } catch (Exception e) {
            e.printStackTrace();
            fail("An exception was thrown!");
            return;
        }
        assertNotNull(userCert);
        // assert that the reserved characters have been escaped
        assertEquals("C=DK,O=urn:mrn:mcl:org:dma,OU=user,CN=\\#Thomas Christensen\\, extra content\\ ,UID=urn:mrn:mcl:user:dma:thc,E=thc\\+bla@dma.dk", userCert.getSubjectDN().getName());

        // check the validity period
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.MONTH, validityPeriod); // add one year to have an invalid date
        Date outOfBorder = cal.getTime();
        cal.add(Calendar.DAY_OF_MONTH, -1); // and minus one day from the invalid date to make it valid.
        Date withinBorder = cal.getTime();
        boolean withinBorderResult = CertificateHandler.verifyCertificate(kh.getPubKey(signingAlias), userCert, withinBorder);
        assertTrue(withinBorderResult);
        boolean outOfBorderResult = CertificateHandler.verifyCertificate(kh.getPubKey(signingAlias), userCert, outOfBorder);
        assertFalse(outOfBorderResult);
    }

    @Test
    void generateKeyPairTest() {
        KeyPair keyPair = CertificateBuilder.generateKeyPair(null);
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
    }

    @Test
    void generateSerialNumber() {
        BigInteger sn = cb.generateSerialNumber(null);
        assertNotNull(sn);
    }

}
