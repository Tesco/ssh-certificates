package com.tesco.encryptionservice.ssh.parser.algorithms;

import com.tesco.encryptionservice.ssh.parser.decode.Ecdsa384shCertificateDecoder;
import com.tesco.encryptionservice.ssh.parser.encode.EcdsaSshCertificateEncoder;

public class EcdsaSha2Nistp384CertV01 extends EcdsaSshCertificateAlgorithm {

    public EcdsaSha2Nistp384CertV01() {
        super("ecdsa-sha2-nistp384-cert-v01@openssh.com", new EcdsaSshCertificateEncoder(), new Ecdsa384shCertificateDecoder(), "nistp384");
    }

}
