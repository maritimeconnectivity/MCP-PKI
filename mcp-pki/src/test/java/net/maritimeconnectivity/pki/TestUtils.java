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


import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.stream.Collectors;

import static net.maritimeconnectivity.pki.CertificateHandler.getCertFromPem;
import static org.junit.jupiter.api.Assertions.fail;

public class TestUtils {

    public static String getRootCAAlias() {
        return "urn:mrn:mcl:ca:maritimecloud";
    }

    public static String getMyBoatCertPem() {
        String certFile = "src/test/resources/Certificate_Myboat.pem";
        return loadTxtFile(certFile);
    }

    public static X509Certificate getMyBoatCert() {
        return getCertFromPem(getMyBoatCertPem());
    }

    public static String getEcdisCertPem() {
        String certFile = "src/test/resources/Certificate_Ecdis.pem";
        return loadTxtFile(certFile);
    }

    public static X509Certificate getEcdisCert() {
        return getCertFromPem(getEcdisCertPem());
    }

    public static String getTestUserCertPem() {
        String certFile = "src/test/resources/Certificate_TestUser.pem";
        return loadTxtFile(certFile);
    }

    public static X509Certificate getTestUserCert() {
        return getCertFromPem(getTestUserCertPem());
    }

    public static String loadTxtFile(String path) {
        try {
            return Files.lines(Paths.get(path)).collect(Collectors.joining("\n"));
        } catch (IOException e) {
            e.printStackTrace();
            fail("Loading Certificate from file failed!");
            throw new RuntimeException(e);
        }
    }


}
