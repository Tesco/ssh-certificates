package com.tesco.encryptionservice.ssh.parser.decode;

import com.tesco.encryptionservice.ssh.certificate.EcdsaSshCertificate;
import lombok.SneakyThrows;

public class Ecdsa384shCertificateDecoder extends EcdsaSshCertificateDecoder<EcdsaSshCertificate> {

    private static final String CERTIFICATE_ALGORITHM = "ecdsa-sha2-nistp384-cert-v01@openssh.com";
    private static final String ELLIPTIC_CURVE_KEY_STANDARD = "secp384r1";

    @Override
    @SneakyThrows
    public EcdsaSshCertificate decode(byte[] bytes) {
        return decode(bytes, CERTIFICATE_ALGORITHM, ELLIPTIC_CURVE_KEY_STANDARD);
    }

}
