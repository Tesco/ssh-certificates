package com.tesco.encryptionservice.ssh.parser.decode;

import com.tesco.encryptionservice.ssh.certificate.RsaSshCertificate;
import lombok.Cleanup;
import lombok.SneakyThrows;

public class RsaSshCertificateDecoder extends SshCertificateDecoder<RsaSshCertificate> {

    private static final String CERTIFICATE_ALGORITHM = "ssh-rsa-cert-v01@openssh.com";

    @SneakyThrows
    public RsaSshCertificate decode(byte[] bytes) {
        @Cleanup ByteInputStream byteArrayDecoder = new ByteInputStream(bytes);
        String certificateAlgorithm = byteArrayDecoder.readString();
        if (!certificateAlgorithm.equals(CERTIFICATE_ALGORITHM)) {
            throw new IllegalArgumentException("Unexpected signing algorithm, found: \"" + certificateAlgorithm + "\" expected: \"" + CERTIFICATE_ALGORITHM + "\"");
        }
        RsaSshCertificate certificate = new RsaSshCertificate()
                .nonce(byteArrayDecoder.readByteArray())
                .e(byteArrayDecoder.readBigInteger())
                .n(byteArrayDecoder.readBigInteger());
        decodeCommon(byteArrayDecoder, certificate);
        return certificate;
    }

}
