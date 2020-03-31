package net.maritimecloud.pki;

import net.maritimecloud.pki.PKIConfiguration;
import net.maritimecloud.pki.PKIConstants;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;


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
        KeyPair certKeyPair = CertificateBuilder.generateKeyPair();
        String userMrn = "urn:mrn:mcl:user:dma:thc";
        String permissions = "NONE";
        String baseCrlOcspPath = "https://localhost/x509/api/certificates/";
        String signingAlias = "urn:mrn:mcl:ca:maritimecloud-idreg";
        Map<String, String> attrs= new HashMap<String, String>();
        attrs.put(PKIConstants.MC_OID_MRN, userMrn);
        attrs.put(PKIConstants.MC_OID_PERMISSIONS, permissions);
        attrs.put(PKIConstants.MC_OID_MRN_SUBSIDIARY, "urn:mrn:stm:user:dmc:thc");
        attrs.put(PKIConstants.MC_OID_HOME_MMS_URL, "http://smartnav.org/");
        X509Certificate userCert;
        try {
            userCert = cb.generateCertForEntity(BigInteger.ONE, "DK", "urn:mrn:mcl:org:dma", "user", "Thomas Christensen", "thc@dma.dk", userMrn, certKeyPair.getPublic(), attrs, signingAlias, baseCrlOcspPath);
        } catch (Exception e) {
            e.printStackTrace();
            fail("An exception was thrown!");
            return;
        }
        assertNotNull(userCert);
        assertEquals("C=DK,O=urn:mrn:mcl:org:dma,OU=user,CN=Thomas Christensen,UID=urn:mrn:mcl:user:dma:thc,E=thc@dma.dk", userCert.getSubjectDN().getName());
    }

    @Test
    void generateKeyPairTest() {
        KeyPair keyPair = CertificateBuilder.generateKeyPair();
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
