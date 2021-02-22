package com.tesco.encryptionservice.ssh.parser.algorithms;

import com.tesco.encryptionservice.ssh.parser.decode.Ecdsa256SshCertificateDecoder;
import com.tesco.encryptionservice.ssh.parser.encode.EcdsaSshCertificateEncoder;

public class EcdsaSha2Nistp256CertV01 extends EcdsaSshCertificateAlgorithm {

    public EcdsaSha2Nistp256CertV01() {
        super("ecdsa-sha2-nistp256-cert-v01@openssh.com", new EcdsaSshCertificateEncoder(), new Ecdsa256SshCertificateDecoder(), "nistp256");
    }

}
