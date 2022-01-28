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

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CAHandlerTest {
    @Test
    void loadRevocationFile1() {
        String revocationCSV = "src/test/resources/revoked-subca-valid.csv";
        CAHandler caHandler = new CAHandler(null, null);
        List<RevocationInfo> info = caHandler.loadRevocationFile(revocationCSV);
        assertEquals(1, info.size());
    }

    @Test
    void loadRevocationFile2() {
        String revocationCSV = "src/test/resources/revoked-subca-invalid-date.csv";
        CAHandler caHandler = new CAHandler(null, null);
        Throwable exception = assertThrows(RuntimeException.class, () -> caHandler.loadRevocationFile(revocationCSV));
        assertEquals("Invalid date format!", exception.getMessage());
    }

    @Test
    void loadRevocationFile3() {
        String revocationCSV = "src/test/resources/revoked-subca-invalid-line.csv";
        CAHandler caHandler = new CAHandler(null, null);
        Throwable exception = assertThrows(RuntimeException.class, () -> caHandler.loadRevocationFile(revocationCSV));
        assertEquals("Missing info from line: 3456789876543;cacompromise;", exception.getMessage());
    }

    @Test
    void loadRevocationFile4() {
        String revocationCSV = "src/test/resources/non-existing-file.csv";
        CAHandler caHandler = new CAHandler(null, null);
        Throwable exception = assertThrows(RuntimeException.class, () -> caHandler.loadRevocationFile(revocationCSV));
        assertEquals("Could not find the revocation info file!", exception.getMessage());
    }

    @Test
    void loadRevocationFile5() {
        String revocationCSV = "src/test/resources/revoked-subca-empty.csv";
        CAHandler caHandler = new CAHandler(null, null);
        List<RevocationInfo> info = caHandler.loadRevocationFile(revocationCSV);
        assertEquals(0, info.size());
    }

}
