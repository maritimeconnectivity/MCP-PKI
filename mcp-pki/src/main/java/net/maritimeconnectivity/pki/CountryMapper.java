/*
 * Copyright 2026 Maritime Connectivity Platform Consortium
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.maritimeconnectivity.pki;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.util.Map;

/**
 * Utility class that contains a map from country names that are different from the ones that are built into the JDK
 * to ISO 3166-1 alpha-2 country codes
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class CountryMapper {

    /**
     * The map from country names to ISO 3166-1 alpha-2 country codes
     */
    public static final Map<String, String> ISO_TITLE_OVERRIDES = Map.<String, String>ofEntries(
            Map.entry("Antigua and Barbuda", "AG"),
            Map.entry("Bahamas (the)", "BS"),
            Map.entry("Bolivia (Plurinational State of)", "BO"),
            Map.entry("Bonaire, Sint Eustatius and Saba", "BQ"),
            Map.entry("Bosnia and Herzegovina", "BA"),
            Map.entry("British Indian Ocean Territory (the)", "IO"),
            Map.entry("Brunei Darussalam", "BN"),
            Map.entry("Cabo Verde", "CV"),
            Map.entry("Cayman Islands (the)", "KY"),
            Map.entry("Central African Republic (the)", "CF"),
            Map.entry("Cocos (Keeling) Islands (the)", "CC"),
            Map.entry("Comoros (the)", "KM"),
            Map.entry("Congo (the Democratic Republic of the)", "CD"),
            Map.entry("Congo (the)", "CG"),
            Map.entry("Cook Islands (the)", "CK"),
            Map.entry("Côte d'Ivoire", "CI"),
            Map.entry("Dominican Republic (the)", "DO"),
            Map.entry("Falkland Islands (the) [Malvinas]", "FK"),
            Map.entry("Faroe Islands (the)", "FO"),
            Map.entry("French Southern Territories (the)", "TF"),
            Map.entry("Gambia (the)", "GM"),
            Map.entry("Heard Island and McDonald Islands", "HM"),
            Map.entry("Holy See (the)", "VA"),
            Map.entry("Hong Kong", "HK"),
            Map.entry("Iran (Islamic Republic of)", "IR"),
            Map.entry("Korea (the Democratic People's Republic of)", "KP"),
            Map.entry("Korea (the Republic of)", "KR"),
            Map.entry("Lao People's Democratic Republic (the)", "LA"),
            Map.entry("Macao", "MO"),
            Map.entry("Marshall Islands (the)", "MH"),
            Map.entry("Micronesia (Federated States of)", "FM"),
            Map.entry("Moldova (the Republic of)", "MD"),
            Map.entry("Myanmar", "MM"),
            Map.entry("Netherlands (the)", "NL"),
            Map.entry("Niger (the)", "NE"),
            Map.entry("Northern Mariana Islands (the)", "MP"),
            Map.entry("Palestine, State of", "PS"),
            Map.entry("Philippines (the)", "PH"),
            Map.entry("Pitcairn", "PN"),
            Map.entry("Republic of Korea", "KR"),
            Map.entry("Republic of North Macedonia", "MK"),
            Map.entry("Russian Federation", "RU"),
            Map.entry("Russian Federation (the)", "RU"),
            Map.entry("Saint Barthélemy", "BL"),
            Map.entry("Saint Helena, Ascension and Tristan da Cunha", "SH"),
            Map.entry("Saint Kitts and Nevis", "KN"),
            Map.entry("Saint Lucia", "LC"),
            Map.entry("Saint Martin (French part)", "MF"),
            Map.entry("Saint Pierre and Miquelon", "PM"),
            Map.entry("Saint Vincent and the Grenadines", "VC"),
            Map.entry("Sao Tome and Principe", "ST"),
            Map.entry("Sint Maarten (Dutch part)", "SX"),
            Map.entry("South Georgia and the South Sandwich Islands", "GS"),
            Map.entry("Sudan (the)", "SD"),
            Map.entry("Suriname", "SR"),
            Map.entry("Svalbard and Jan Mayen", "SJ"),
            Map.entry("Syrian Arab Republic", "SY"),
            Map.entry("Tanzania, United Republic of", "TZ"),
            Map.entry("Trinidad and Tobago", "TT"),
            Map.entry("Turkey", "TR"),
            Map.entry("Turks and Caicos Islands (the)", "TC"),
            Map.entry("United Arab Emirates (the)", "AE"),
            Map.entry("United Kingdom of Great Britain and Northern Ireland (the)", "GB"),
            Map.entry("United States Minor Outlying Islands (the)", "UM"),
            Map.entry("United States of America (the)", "US"),
            Map.entry("Venezuela (Bolivarian Republic of)", "VE"),
            Map.entry("Viet Nam", "VN"),
            Map.entry("Virgin Islands (British)", "VG"),
            Map.entry("Virgin Islands (U.S.)", "VI"),
            Map.entry("Wallis and Futuna", "WF")
    );
}
