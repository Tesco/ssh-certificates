package com.tesco.encryptionservice.ssh.parser.algorithms;

import com.tesco.encryptionservice.ssh.parser.decode.RsaSshCertificateDecoder;
import com.tesco.encryptionservice.ssh.parser.encode.RsaSshCertificateEncoder;

import java.security.interfaces.RSAPublicKey;

public class SshRsaCertV01 extends SshCertificateAlgorithm<RSAPublicKey> {

    public SshRsaCertV01() {
        super("ssh-rsa-cert-v01@openssh.com", new RsaSshCertificateEncoder(), new RsaSshCertificateDecoder());
    }

}
