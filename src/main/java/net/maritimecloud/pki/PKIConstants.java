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


public class PKIConstants {

    public static final int CERT_EXPIRE_YEAR = 2025;
    //public static final String ROOT_CERT_ALIAS = "urn:mrn:mcl:ca:maritimecloud"; // removed for distributed MIR
    public static final String BC_PROVIDER_NAME = "BC";
    public static final String KEYSTORE_TYPE = "jks";
    public static final String SIGNER_ALGORITHM = "SHA384withECDSA";
    public static final String ELLIPTIC_CURVE = "secp384r1";

    // OIDs used for the extra info stored in the SubjectAlternativeName extension
    // Generate more random OIDs at http://www.itu.int/en/ITU-T/asn1/Pages/UUID/generate_uuid.aspx
    public static final String MC_OID_FLAGSTATE        = "2.25.323100633285601570573910217875371967771";
    public static final String MC_OID_CALLSIGN         = "2.25.208070283325144527098121348946972755227";
    public static final String MC_OID_IMO_NUMBER       = "2.25.291283622413876360871493815653100799259";
    public static final String MC_OID_MMSI_NUMBER      = "2.25.328433707816814908768060331477217690907";
    // See http://www.shipais.com/doc/Pifaq/1/22/ and https://help.marinetraffic.com/hc/en-us/articles/205579997-What-is-the-significance-of-the-AIS-SHIPTYPE-number-
    public static final String MC_OID_AIS_SHIPTYPE     = "2.25.107857171638679641902842130101018412315";
    public static final String MC_OID_MRN              = "2.25.271477598449775373676560215839310464283";
    public static final String MC_OID_SHIP_MRN         = "2.25.268095117363717005222833833642941669792";
    public static final String MC_OID_PERMISSIONS      = "2.25.174437629172304915481663724171734402331";
    public static final String MC_OID_PORT_OF_REGISTER = "2.25.285632790821948647314354670918887798603";
    public static final String MC_OID_MRN_SUBSIDIARY   = "2.25.133833610339604538603087183843785923701";
    public static final String MC_OID_HOME_MMS_URL     = "2.25.171344478791913547554566856023141401757";
    public static final String MC_OID_URL              = "2.25.245076023612240385163414144226581328607";


    // Used to identify the DNSName attribute in the X509 Extension: Subject Alternative Name.
    // String representation of org.bouncycastle.asn1.x509.GeneralName.dNSName
    public static final String X509_SAN_DNSNAME = "2";
}
