package com.tesco.encryptionservice.ssh.parser.encode;

import com.tesco.encryptionservice.ssh.certificate.RsaSshCertificate;
import com.tesco.encryptionservice.ssh.certificate.SshCertificate;
import lombok.Cleanup;
import lombok.SneakyThrows;

import java.security.interfaces.RSAPublicKey;

import static com.tesco.encryptionservice.ssh.parser.encode.ByteOutputStream.getInstance;

public class RsaSshCertificateEncoder extends SshCertificateEncoder<RSAPublicKey> {

    @Override
    @SneakyThrows
    public byte[] encodeSignedBytes(SshCertificate<RSAPublicKey> sshCertificate) {
        @Cleanup ByteOutputStream byteOutputStream = getInstance();
        RsaSshCertificate rsaSshCertificate = (RsaSshCertificate) sshCertificate;
        // algorithm
        byteOutputStream.writeString(rsaSshCertificate.sshCertificateAlgorithm().algorithmName());
        // nonce
        byteOutputStream.writeBytes(rsaSshCertificate.nonce());
        // exponent
        byteOutputStream.writeBigInteger(rsaSshCertificate.e());
        // modulus
        byteOutputStream.writeBigInteger(rsaSshCertificate.n());
        // common fields
        encodeCommonSignedBytes(byteOutputStream, rsaSshCertificate);
        return byteOutputStream.toByteArray();
    }

}
