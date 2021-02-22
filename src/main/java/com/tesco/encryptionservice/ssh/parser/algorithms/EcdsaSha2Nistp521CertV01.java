package com.tesco.encryptionservice.ssh.parser.algorithms;

import com.tesco.encryptionservice.ssh.parser.decode.Ecdsa521SshCertificateDecoder;
import com.tesco.encryptionservice.ssh.parser.encode.EcdsaSshCertificateEncoder;

public class EcdsaSha2Nistp521CertV01 extends EcdsaSshCertificateAlgorithm {

    public EcdsaSha2Nistp521CertV01() {
        super("ecdsa-sha2-nistp521-cert-v01@openssh.com", new EcdsaSshCertificateEncoder(), new Ecdsa521SshCertificateDecoder(), "nistp521");
    }

}
