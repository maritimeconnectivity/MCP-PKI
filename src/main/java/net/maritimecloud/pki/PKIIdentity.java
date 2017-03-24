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

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class PKIIdentity {
    private String uid;
    private String dn;
    private String cn;
    private String sn;
    private String o;
    private String ou;
    private String permissions;
    private String country;
    // The values below are only relevant for ships
    private String flagState;
    private String callSign;
    private String imoNumber;
    private String mmsiNumber;
    private String aisShipType;
    private String portOfRegister;

}
