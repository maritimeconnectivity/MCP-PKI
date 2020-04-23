package net.maritimeconnectivity.pki;

import lombok.extern.slf4j.Slf4j;
import net.maritimeconnectivity.pki.pkcs11.P11PKIConfiguration;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import java.io.Console;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;

@Slf4j
public class Main {

    private static final String HELP = "help";
    private static final String INIT = "init";
    private static final String TRUSTSTORE = "truststore-path";
    private static final String TRUSTSTORE_PASSWORD = "truststore-password";
    private static final String ROOT_KEYSTORE = "root-keystore-path";
    private static final String ROOT_KEYSTORE_PASSWORD = "root-keystore-password";
    private static final String ROOT_KEY_PASSWORD = "root-key-password";
    private static final String CRL_ENDPOINT = "crl-endpoint";
    private static final String X500_NAME = "x500-name";
    private static final String GENERATE_ROOT_CRL = "generate-root-crl";
    private static final String ROOT_CRL_PATH = "root-crl-path";
    private static final String REVOKED_SUBCA_FILE = "revoked-subca-file";
    private static final String CREATE_SUBCA = "create-subca";
    private static final String SUBCA_KEYSTORE = "subca-keystore";
    private static final String SUBCA_KEYSTORE_PASSWORD = "subca-keystore-password";
    private static final String SUBCA_KEY_PASSWORD = "subca-key-password";
    private static final String VERIFY_CERTIFICATE = "verify-certificate";
    private static final String PRINT_OUT_CERTIFICATE = "print-certificate";
    private static final String ROOT_CA_ALIAS = "root-ca-alias";
    private static final String NO_ROOT_CA_ALIAS_REQUIRED = "";
    private static final String PKCS11 = "pkcs11";
    private static final String PKCS11_CONFIG = "pkcs11-conf";
    private static final String PKCS11_PIN = "pkcs11-pin";
    private static final String PKCS11_ROOT_CONFIG = "pkcs11-root-conf";
    private static final String PKCS11_ROOT_PIN = "pkcs11-root-pin";
    private static final String PKCS11_SUB_CONFIG = "pkcs11-sub-conf";
    private static final String PKCS11_SUB_PIN = "pkcs11-sub-pin";

    private Options setupOptions() {
        // Create Options object
        Options options = new Options();
        // Help output
        options.addOption("h", HELP, false, "Show this help message");

        // CA root init
        options.addOption("i", INIT, false, "Initialize PKI - creates root CA. Requires the parameters: " + String.join(", ", TRUSTSTORE, TRUSTSTORE_PASSWORD, ROOT_KEYSTORE, ROOT_KEYSTORE_PASSWORD, ROOT_KEY_PASSWORD, X500_NAME, CRL_ENDPOINT, ROOT_CA_ALIAS));
        options.addOption("t",TRUSTSTORE, true, "Output truststore path.");
        options.addOption("tp",TRUSTSTORE_PASSWORD, true, "Truststore password");
        options.addOption("rk", ROOT_KEYSTORE, true, "Output keystore path.");
        options.addOption("rkp", ROOT_KEYSTORE_PASSWORD, true, "Keystore password.");
        options.addOption("kp", ROOT_KEY_PASSWORD, true, "Key password.");
        options.addOption("xn", X500_NAME, true, "Key password.");
        options.addOption("crl", CRL_ENDPOINT, true, "CRL endpoint");
        options.addOption("rt", ROOT_CA_ALIAS, true, "Root CA alias");

        // Generate root CRL
        options.addOption("grc", GENERATE_ROOT_CRL, false, "Generate CRL for root CA. Requires the parameters: " + String.join(", ", ROOT_KEYSTORE, ROOT_KEYSTORE_PASSWORD, ROOT_KEY_PASSWORD, ROOT_CRL_PATH, REVOKED_SUBCA_FILE));
        options.addOption("rcp", ROOT_CRL_PATH, true, "Root CRL path output path");
        options.addOption("rsf", REVOKED_SUBCA_FILE, true, "CSV file containing a semi-colon separated list (serialnumber;reason;date) of revoked sub-CAs.");

        // Create sub CA
        options.addOption("csca", CREATE_SUBCA, false, "Create sub CA. Requires the parameters: " + String.join(", ", ROOT_KEYSTORE, ROOT_KEYSTORE_PASSWORD, ROOT_KEY_PASSWORD, TRUSTSTORE, TRUSTSTORE_PASSWORD, SUBCA_KEYSTORE, SUBCA_KEYSTORE_PASSWORD, SUBCA_KEY_PASSWORD, X500_NAME));
        options.addOption("sk", SUBCA_KEYSTORE, true, "Sub CA keystore path.");
        options.addOption("skp", SUBCA_KEYSTORE_PASSWORD, true, "Sub CA keystore password.");
        options.addOption("sp", SUBCA_KEY_PASSWORD, true, "Sub CA key password.");

        // Verify certificate in PEM format
        options.addOption("vc", VERIFY_CERTIFICATE, true, "Verify a certificate. Requires a path to a certificate in PEM format amd the parameters: " + String.join(", ", TRUSTSTORE, TRUSTSTORE_PASSWORD));

        // Print out a certificate
        options.addOption("pc", PRINT_OUT_CERTIFICATE, true, "Print out a certificate in human readable text");

        // Use HSM using PKCS#11
        options.addOption("p11", PKCS11, false, "Use PKCS#11 to interact with an HSM.");
        options.addOption("p11c", PKCS11_CONFIG, true, "Path to a PKCS#11 config file.");
        options.addOption("pin", PKCS11_PIN, true, "PIN for HSM slot. If not given when using a HSM, it will be requested on runtime.");
        options.addOption("p11r", PKCS11_ROOT_CONFIG, true, "Path to a PKCS#11 config file for root CA.");
        options.addOption("pinr", PKCS11_ROOT_PIN, true, "PIN for root CA HSM slot. If not given when using a HSM, it will be requested on runtime.");
        options.addOption("p11s", PKCS11_SUB_CONFIG, true, "Path to a PKCS#11 config for intermediate CA.");
        options.addOption("pins", PKCS11_SUB_PIN, true, "PIN for intermediate CA HSM slot. If not given when using a HSM, it will be requested on runtime.");
        return options;
    }

    private void initCA(CommandLine cmd) {
        if (!cmd.hasOption(TRUSTSTORE) || !cmd.hasOption(TRUSTSTORE_PASSWORD) || !cmd.hasOption(ROOT_KEYSTORE) || !cmd.hasOption(ROOT_KEYSTORE_PASSWORD) || !cmd.hasOption(ROOT_KEY_PASSWORD) || !cmd.hasOption(CRL_ENDPOINT) || !cmd.hasOption(X500_NAME) || !cmd.hasOption(ROOT_CA_ALIAS)) {
            log.error("The init requires the parameters: " + String.join(", ", TRUSTSTORE, TRUSTSTORE_PASSWORD, ROOT_KEYSTORE, ROOT_KEYSTORE_PASSWORD, ROOT_KEY_PASSWORD, X500_NAME, CRL_ENDPOINT, ROOT_CA_ALIAS));
            return;
        }
        PKIConfiguration pkiConfiguration = new PKIConfiguration(cmd.getOptionValue(ROOT_CA_ALIAS));
        pkiConfiguration.setTruststorePath(cmd.getOptionValue(TRUSTSTORE));
        pkiConfiguration.setTruststorePassword(cmd.getOptionValue(TRUSTSTORE_PASSWORD));
        pkiConfiguration.setRootCaKeystorePath(cmd.getOptionValue(ROOT_KEYSTORE));
        pkiConfiguration.setRootCaKeystorePassword(cmd.getOptionValue(ROOT_KEYSTORE_PASSWORD));
        pkiConfiguration.setRootCaKeyPassword(cmd.getOptionValue(ROOT_KEY_PASSWORD));

        KeystoreHandler keystoreHandler = new KeystoreHandler(pkiConfiguration);
        CertificateBuilder certificateBuilder = new CertificateBuilder(keystoreHandler);
        CAHandler caHandler = new CAHandler(certificateBuilder, pkiConfiguration);
        caHandler.initRootCA(cmd.getOptionValue(X500_NAME), cmd.getOptionValue(CRL_ENDPOINT), cmd.getOptionValue(ROOT_CA_ALIAS));
    }

    private void initCAPKCS11(CommandLine cmd) {
        if (!cmd.hasOption(TRUSTSTORE) || !cmd.hasOption(TRUSTSTORE_PASSWORD) || !cmd.hasOption(CRL_ENDPOINT) || !cmd.hasOption(X500_NAME) || !cmd.hasOption(ROOT_CA_ALIAS) || !cmd.hasOption(PKCS11_CONFIG)) {
            log.error("The init with PKCS#11 requires the parameters: " + String.join(", ", TRUSTSTORE, TRUSTSTORE_PASSWORD, X500_NAME, CRL_ENDPOINT, ROOT_CA_ALIAS, PKCS11_CONFIG));
            return;
        }
        PKIConfiguration pkiConfiguration = new P11PKIConfiguration(cmd.getOptionValue(ROOT_CA_ALIAS), cmd.getOptionValue(PKCS11_CONFIG), cmd.getOptionValue(PKCS11_PIN));
        pkiConfiguration.setTruststorePath(cmd.getOptionValue(TRUSTSTORE));
        pkiConfiguration.setTruststorePassword(cmd.getOptionValue(TRUSTSTORE_PASSWORD));

        KeystoreHandler keystoreHandler = new KeystoreHandler(pkiConfiguration);
        CertificateBuilder certificateBuilder = new CertificateBuilder(keystoreHandler);
        CAHandler caHandler = new CAHandler(certificateBuilder, pkiConfiguration);
        caHandler.initRootCAPKCS11(cmd.getOptionValue(X500_NAME), cmd.getOptionValue(CRL_ENDPOINT), cmd.getOptionValue(ROOT_CA_ALIAS));
    }

    private void genRootCRL(CommandLine cmd) {
        if (!cmd.hasOption(ROOT_KEYSTORE) || !cmd.hasOption(ROOT_KEYSTORE_PASSWORD) || !cmd.hasOption(ROOT_KEY_PASSWORD) || !cmd.hasOption(ROOT_CRL_PATH) || !cmd.hasOption(REVOKED_SUBCA_FILE) || !cmd.hasOption(ROOT_CA_ALIAS)) {
            log.error("Generating the root CRL requires the parameters: " + String.join(", ", ROOT_KEYSTORE, ROOT_KEYSTORE_PASSWORD, ROOT_KEY_PASSWORD, ROOT_CRL_PATH, REVOKED_SUBCA_FILE, ROOT_CA_ALIAS));
            return;
        }
        PKIConfiguration pkiConfiguration = new PKIConfiguration(cmd.getOptionValue(ROOT_CA_ALIAS));
        pkiConfiguration.setRootCaKeystorePath(cmd.getOptionValue(ROOT_KEYSTORE));
        pkiConfiguration.setRootCaKeystorePassword(cmd.getOptionValue(ROOT_KEYSTORE_PASSWORD));
        pkiConfiguration.setRootCaKeyPassword(cmd.getOptionValue(ROOT_KEY_PASSWORD));

        KeystoreHandler keystoreHandler = new KeystoreHandler(pkiConfiguration);
        CertificateBuilder certificateBuilder = new CertificateBuilder(keystoreHandler);
        CAHandler caHandler = new CAHandler(certificateBuilder, pkiConfiguration);
        caHandler.generateRootCRL(cmd.getOptionValue(ROOT_CRL_PATH), cmd.getOptionValue(REVOKED_SUBCA_FILE), cmd.getOptionValue(ROOT_CA_ALIAS));
    }

    private void genRootCRLPKCS11(CommandLine cmd) {
        if (!cmd.hasOption(ROOT_CRL_PATH) || !cmd.hasOption(REVOKED_SUBCA_FILE) || !cmd.hasOption(ROOT_CA_ALIAS) || !cmd.hasOption(PKCS11_CONFIG)) {
            log.error("Generating the root CA with PKCS#11 requires the parameters: " + String.join(", ", ROOT_CRL_PATH, REVOKED_SUBCA_FILE, ROOT_CA_ALIAS, PKCS11_CONFIG));
            return;
        }
        PKIConfiguration pkiConfiguration = new P11PKIConfiguration(cmd.getOptionValue(ROOT_CA_ALIAS), cmd.getOptionValue(PKCS11_CONFIG), cmd.getOptionValue(PKCS11_PIN));

        KeystoreHandler keystoreHandler = new KeystoreHandler(pkiConfiguration);
        CertificateBuilder certificateBuilder = new CertificateBuilder(keystoreHandler);
        CAHandler caHandler = new CAHandler(certificateBuilder, pkiConfiguration);
        caHandler.generateRootCRLP11(cmd.getOptionValue(ROOT_CRL_PATH), cmd.getOptionValue(REVOKED_SUBCA_FILE), cmd.getOptionValue(ROOT_CA_ALIAS));
    }

    private void createSubCA(CommandLine cmd) {
        if (!cmd.hasOption(ROOT_KEYSTORE) || !cmd.hasOption(ROOT_KEYSTORE_PASSWORD) || !cmd.hasOption(ROOT_KEY_PASSWORD) || !cmd.hasOption(TRUSTSTORE) || !cmd.hasOption(TRUSTSTORE_PASSWORD) || !cmd.hasOption(SUBCA_KEYSTORE) || !cmd.hasOption(SUBCA_KEYSTORE_PASSWORD) || !cmd.hasOption(SUBCA_KEY_PASSWORD) || !cmd.hasOption(X500_NAME) || !cmd.hasOption(ROOT_CA_ALIAS)) {
            log.error("Creating a sub CA requires the parameters: " + String.join(", ", ROOT_KEYSTORE, ROOT_KEYSTORE_PASSWORD, ROOT_KEY_PASSWORD, TRUSTSTORE, TRUSTSTORE_PASSWORD, SUBCA_KEYSTORE, SUBCA_KEYSTORE_PASSWORD, SUBCA_KEY_PASSWORD, X500_NAME, ROOT_CA_ALIAS));
            return;
        }
        PKIConfiguration pkiConfiguration = new PKIConfiguration(cmd.getOptionValue(ROOT_CA_ALIAS));
        pkiConfiguration.setTruststorePath(cmd.getOptionValue(TRUSTSTORE));
        pkiConfiguration.setTruststorePassword(cmd.getOptionValue(TRUSTSTORE_PASSWORD));
        pkiConfiguration.setRootCaKeystorePath(cmd.getOptionValue(ROOT_KEYSTORE));
        pkiConfiguration.setRootCaKeystorePassword(cmd.getOptionValue(ROOT_KEYSTORE_PASSWORD));
        pkiConfiguration.setRootCaKeyPassword(cmd.getOptionValue(ROOT_KEY_PASSWORD));
        pkiConfiguration.setSubCaKeystorePath(cmd.getOptionValue(SUBCA_KEYSTORE));
        pkiConfiguration.setSubCaKeystorePassword(cmd.getOptionValue(SUBCA_KEYSTORE_PASSWORD));
        pkiConfiguration.setSubCaKeyPassword(cmd.getOptionValue(SUBCA_KEY_PASSWORD));

        KeystoreHandler keystoreHandler = new KeystoreHandler(pkiConfiguration);
        CertificateBuilder certificateBuilder = new CertificateBuilder(keystoreHandler);
        CAHandler caHandler = new CAHandler(certificateBuilder, pkiConfiguration);

        caHandler.createSubCa(cmd.getOptionValue(X500_NAME), cmd.getOptionValue(ROOT_CA_ALIAS));
    }

    private void createSubCAPKCS11(CommandLine cmd) {
        if (!cmd.hasOption(TRUSTSTORE) || !cmd.hasOption(TRUSTSTORE_PASSWORD) || !cmd.hasOption(X500_NAME) || !cmd.hasOption(ROOT_CA_ALIAS) || !cmd.hasOption(PKCS11_ROOT_CONFIG) || !cmd.hasOption(PKCS11_SUB_CONFIG)) {
            log.error("Creating a sub CA requires the parameters: " + String.join(", ", TRUSTSTORE, TRUSTSTORE_PASSWORD, X500_NAME, ROOT_CA_ALIAS, PKCS11_ROOT_CONFIG, PKCS11_SUB_CONFIG));
        }
        char[] rootCaPin;
        char[] subCaPin;
        Console console = System.console();
        // Check if root CA PIN has been given
        if (!cmd.hasOption(PKCS11_ROOT_PIN)) {
            log.error("Please input root CA HSM slot PIN: ");
            rootCaPin = console.readPassword();
        } else {
            rootCaPin = cmd.getOptionValue(PKCS11_ROOT_PIN).toCharArray();
        }
        // Check if sub CA PIN has been given
        if (!cmd.hasOption(PKCS11_SUB_PIN)) {
            log.error("Please input sub CA HSM slot PIN: ");
            subCaPin = console.readPassword();
        } else {
            subCaPin = cmd.getOptionValue(PKCS11_SUB_PIN).toCharArray();
        }
        if (console != null)
            console.flush();

        PKIConfiguration rootPkiConfiguration = new P11PKIConfiguration(cmd.getOptionValue(ROOT_CA_ALIAS), cmd.getOptionValue(PKCS11_ROOT_CONFIG), rootCaPin);
        rootPkiConfiguration.setTruststorePath(cmd.getOptionValue(TRUSTSTORE));
        rootPkiConfiguration.setTruststorePassword(cmd.getOptionValue(TRUSTSTORE_PASSWORD));

        PKIConfiguration subPkiConfiguration = new P11PKIConfiguration(cmd.getOptionValue(ROOT_CA_ALIAS), cmd.getOptionValue(PKCS11_SUB_CONFIG), subCaPin);
        subPkiConfiguration.setTruststorePath(cmd.getOptionValue(TRUSTSTORE));
        subPkiConfiguration.setTruststorePassword(cmd.getOptionValue(TRUSTSTORE_PASSWORD));

        KeystoreHandler keystoreHandler = new KeystoreHandler(rootPkiConfiguration);
        CertificateBuilder certificateBuilder = new CertificateBuilder(keystoreHandler);
        CAHandler caHandler = new CAHandler(certificateBuilder, rootPkiConfiguration);

        caHandler.createSubCAPKCS11(cmd.getOptionValue(X500_NAME), cmd.getOptionValue(ROOT_CA_ALIAS), subPkiConfiguration);
    }

    public void verifyCertificate(CommandLine cmd) {
        if (!cmd.hasOption(TRUSTSTORE) || !cmd.hasOption(TRUSTSTORE_PASSWORD)) {
            log.error("Verifying a certificate requires the parameters: " + String.join(", ", TRUSTSTORE, TRUSTSTORE_PASSWORD));
            return;
        }
        PKIConfiguration pkiConfiguration = new PKIConfiguration(NO_ROOT_CA_ALIAS_REQUIRED);
        pkiConfiguration.setTruststorePath(cmd.getOptionValue(TRUSTSTORE));
        pkiConfiguration.setTruststorePassword(cmd.getOptionValue(TRUSTSTORE_PASSWORD));

        String certPath = cmd.getOptionValue(VERIFY_CERTIFICATE);
        String pemCert;
        try {
            pemCert = new String(Files.readAllBytes(Paths.get(certPath)));
        } catch (IOException e) {
            log.error("Could not load certificate from " + certPath);
            return;
        }
        X509Certificate cert = CertificateHandler.getCertFromPem(pemCert);
        if (cert == null) {
            log.error("Could not load certificate, is it in valid PEM format?");
            return;
        }
        KeystoreHandler keystoreHandler = new KeystoreHandler(pkiConfiguration);
        try {
            CertificateHandler.verifyCertificateChain(cert, keystoreHandler.getTrustStore());
            log.info("Certificate is valid!");
        } catch (Exception e) {
            log.error("Certificate is not valid!\n" + e);
            return;
        }
        PKIIdentity identity = CertificateHandler.getIdentityFromCert(cert);
        log.info(identity.toString());
    }

    public X509Certificate getCertificate(String certPath) throws IOException {
        String pemCert = new String(Files.readAllBytes(Paths.get(certPath)));
        return CertificateHandler.getCertFromPem(pemCert);
    }

    public static void main(String[] args) {
        Main main = new Main();

        CommandLineParser parser = new DefaultParser();
        Options options = main.setupOptions();
        CommandLine cmd;
        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            log.error("Parsing failed. Reason: " + e.getMessage());
            return;
        }
        if (cmd.hasOption(INIT)) {
            if (cmd.hasOption(PKCS11)) {
                main.initCAPKCS11(cmd);
            } else {
                main.initCA(cmd);
            }

        // Generate root CRL
        } else if (cmd.hasOption(GENERATE_ROOT_CRL)) {
            if (cmd.hasOption(PKCS11)) {
                main.genRootCRLPKCS11(cmd);
            } else {
                main.genRootCRL(cmd);
            }

        // Create sub ca
        } else if (cmd.hasOption(CREATE_SUBCA)) {
            if (cmd.hasOption(PKCS11)) {
                main.createSubCAPKCS11(cmd);
            } else {
                main.createSubCA(cmd);
            }

        // Verify certificate
        } else if (cmd.hasOption(VERIFY_CERTIFICATE)) {
            main.verifyCertificate(cmd);
        } else if (cmd.hasOption(PRINT_OUT_CERTIFICATE)) {
            String certPath = cmd.getOptionValue(PRINT_OUT_CERTIFICATE);
            try {
                PKIIdentity identity = CertificateHandler.getIdentityFromCert(main.getCertificate(certPath));
                log.info(identity.toString());
            } catch (IOException e) {
                log.error("Parsing of certificate failed. Reason: " + e.getMessage());
            }

            // Default to show the help message
        } else {
            // Automatically generate the help statement
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp( "mcp-pki", options );
        }
    }
}
