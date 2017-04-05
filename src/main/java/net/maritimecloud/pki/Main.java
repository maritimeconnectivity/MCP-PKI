package net.maritimecloud.pki;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;

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

    private Options setupOptions() {
        // Create Options object
        Options options = new Options();
        // Help output
        options.addOption("h", HELP, false, "Show this help message");

        // CA root init
        options.addOption("i", INIT, false, "Initialize PKI - creates root CA. Requires the parameters: " + String.join(", ", TRUSTSTORE, TRUSTSTORE_PASSWORD, ROOT_KEYSTORE, ROOT_KEYSTORE_PASSWORD, ROOT_KEY_PASSWORD, X500_NAME, CRL_ENDPOINT));
        options.addOption("t",TRUSTSTORE, true, "Output truststore path.");
        options.addOption("tp",TRUSTSTORE_PASSWORD, true, "Truststore password");
        options.addOption("rk", ROOT_KEYSTORE, true, "Output keystore path.");
        options.addOption("rkp", ROOT_KEYSTORE_PASSWORD, true, "Keystore password.");
        options.addOption("kp", ROOT_KEY_PASSWORD, true, "Key password.");
        options.addOption("xn", X500_NAME, true, "Key password.");
        options.addOption("crl", CRL_ENDPOINT, true, "CRL endpoint");

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
        return options;
    }

    private void initCA(CommandLine cmd) {
        if (!cmd.hasOption(TRUSTSTORE) || !cmd.hasOption(TRUSTSTORE_PASSWORD) || !cmd.hasOption(ROOT_KEYSTORE) || !cmd.hasOption(ROOT_KEYSTORE_PASSWORD) || !cmd.hasOption(ROOT_KEY_PASSWORD) || !cmd.hasOption(CRL_ENDPOINT) || !cmd.hasOption(X500_NAME)) {
            System.err.println("The init requires the parameters: " + String.join(", ", TRUSTSTORE, TRUSTSTORE_PASSWORD, ROOT_KEYSTORE, ROOT_KEYSTORE_PASSWORD, ROOT_KEY_PASSWORD, X500_NAME, CRL_ENDPOINT));
            return;
        }
        PKIConfiguration pkiConfiguration = new PKIConfiguration();
        pkiConfiguration.setTruststorePath(cmd.getOptionValue(TRUSTSTORE));
        pkiConfiguration.setTruststorePassword(cmd.getOptionValue(TRUSTSTORE_PASSWORD));
        pkiConfiguration.setRootCaKeystorePath(cmd.getOptionValue(ROOT_KEYSTORE));
        pkiConfiguration.setRootCaKeystorePassword(cmd.getOptionValue(ROOT_KEYSTORE_PASSWORD));
        pkiConfiguration.setRootCaKeyPassword(cmd.getOptionValue(ROOT_KEY_PASSWORD));

        KeystoreHandler keystoreHandler = new KeystoreHandler(pkiConfiguration);
        CertificateBuilder certificateBuilder = new CertificateBuilder(keystoreHandler);
        CAHandler caHandler = new CAHandler(certificateBuilder, pkiConfiguration);
        caHandler.initRootCA(cmd.getOptionValue(X500_NAME), cmd.getOptionValue(CRL_ENDPOINT));
    }

    private void genRootCRL(CommandLine cmd) {
        if (!cmd.hasOption(ROOT_KEYSTORE) || !cmd.hasOption(ROOT_KEYSTORE_PASSWORD) || !cmd.hasOption(ROOT_KEY_PASSWORD) || !cmd.hasOption(ROOT_CRL_PATH) || !cmd.hasOption(REVOKED_SUBCA_FILE)) {
            System.err.println("Generating the root CRL requires the parameters: " + String.join(", ", ROOT_KEYSTORE, ROOT_KEYSTORE_PASSWORD, ROOT_KEY_PASSWORD, ROOT_CRL_PATH, REVOKED_SUBCA_FILE));
            return;
        }
        PKIConfiguration pkiConfiguration = new PKIConfiguration();
        pkiConfiguration.setRootCaKeystorePath(cmd.getOptionValue(ROOT_KEYSTORE));
        pkiConfiguration.setRootCaKeystorePassword(cmd.getOptionValue(ROOT_KEYSTORE_PASSWORD));
        pkiConfiguration.setRootCaKeyPassword(cmd.getOptionValue(ROOT_KEY_PASSWORD));

        KeystoreHandler keystoreHandler = new KeystoreHandler(pkiConfiguration);
        CertificateBuilder certificateBuilder = new CertificateBuilder(keystoreHandler);
        CAHandler caHandler = new CAHandler(certificateBuilder, pkiConfiguration);
        caHandler.generateRootCRL(cmd.getOptionValue(ROOT_CRL_PATH), cmd.getOptionValue(REVOKED_SUBCA_FILE));
    }

    private void createSubCA(CommandLine cmd) {
        if (!cmd.hasOption(ROOT_KEYSTORE) || !cmd.hasOption(ROOT_KEYSTORE_PASSWORD) || !cmd.hasOption(ROOT_KEY_PASSWORD) || !cmd.hasOption(TRUSTSTORE) || !cmd.hasOption(TRUSTSTORE_PASSWORD) || !cmd.hasOption(SUBCA_KEYSTORE) || !cmd.hasOption(SUBCA_KEYSTORE_PASSWORD) || !cmd.hasOption(SUBCA_KEY_PASSWORD) || !cmd.hasOption(X500_NAME)) {
            System.err.println("Creating a sub CA requires the parameters: " + String.join(", ", ROOT_KEYSTORE, ROOT_KEYSTORE_PASSWORD, ROOT_KEY_PASSWORD, TRUSTSTORE, TRUSTSTORE_PASSWORD, SUBCA_KEYSTORE, SUBCA_KEYSTORE_PASSWORD, SUBCA_KEY_PASSWORD, X500_NAME));
            return;
        }
        PKIConfiguration pkiConfiguration = new PKIConfiguration();
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

        caHandler.createSubCa(cmd.getOptionValue(X500_NAME));
    }

    public void verifyCertificate(CommandLine cmd) {
        if (!cmd.hasOption(TRUSTSTORE) || !cmd.hasOption(TRUSTSTORE_PASSWORD)) {
            System.err.println("The init requires the parameters: " + String.join(", ", TRUSTSTORE, TRUSTSTORE_PASSWORD));
            return;
        }
        PKIConfiguration pkiConfiguration = new PKIConfiguration();
        pkiConfiguration.setTruststorePath(cmd.getOptionValue(TRUSTSTORE));
        pkiConfiguration.setTruststorePassword(cmd.getOptionValue(TRUSTSTORE_PASSWORD));

        String certPath = cmd.getOptionValue(VERIFY_CERTIFICATE);
        String pemCert;
        try {
            pemCert = new String(Files.readAllBytes(Paths.get(certPath)));
        } catch (IOException e) {
            System.err.println("Could not load certificate from " + certPath);
            return;
        }
        X509Certificate cert = CertificateHandler.getCertFromPem(pemCert);
        if (cert == null) {
            System.err.println("Could not load certificate, is it in valid PEM format?");
            return;
        }
        KeystoreHandler keystoreHandler = new KeystoreHandler(pkiConfiguration);
        try {
            CertificateHandler.verifyCertificateChain(cert, keystoreHandler.getTrustStore());
            System.out.println("Certificate is valid!");
        } catch (Exception e) {
            System.out.println("Certificate is not valid!\n" + e);
            return;
        }
        PKIIdentity identity = CertificateHandler.getIdentityFromCert(cert);
        System.out.println(identity);
    }

    public static void main(String[] args) {
        Main main = new Main();

        CommandLineParser parser = new DefaultParser();
        Options options = main.setupOptions();
        CommandLine cmd;
        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.err.println("Parsing failed. Reason: " + e.getMessage());
            return;
        }
        if (cmd.hasOption(INIT)) {
            main.initCA(cmd);

        // Generate root CRL
        } else if (cmd.hasOption(GENERATE_ROOT_CRL)) {
            main.genRootCRL(cmd);

        // Create sub ca
        } else if (cmd.hasOption(CREATE_SUBCA)) {
            main.createSubCA(cmd);

        // Verify certificate
        } else if (cmd.hasOption(VERIFY_CERTIFICATE)) {
            main.verifyCertificate(cmd);

        // Default to show the help message
        } else {
            // Automatically generate the help statement
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp( "mc-pki", options );
        }
    }
}
