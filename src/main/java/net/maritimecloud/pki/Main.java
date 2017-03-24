package net.maritimecloud.pki;

public class Main {

    public static void main(String[] args) {
        PKIConfiguration pkiConfiguration = new PKIConfiguration();
        KeystoreHandler keystoreHandler = new KeystoreHandler(pkiConfiguration);
        //CertificateHandler certificateHandler = new CertificateHandler();
        CertificateBuilder certificateBuilder = new CertificateBuilder(keystoreHandler);
        //Revocation revocation = new Revocation(keystoreHandler, pkiConfiguration);
        // write your code here
        BootStrap bootstrap = new BootStrap(certificateBuilder, pkiConfiguration);
        //bootstrap.initCA();
    }
}
