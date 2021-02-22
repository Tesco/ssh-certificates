package com.tesco.encryptionservice.ssh.parser.encode;

import com.tesco.encryptionservice.ssh.certificate.EcdsaSshCertificate;
import com.tesco.encryptionservice.ssh.certificate.SshCertificate;
import lombok.Cleanup;
import lombok.SneakyThrows;
import sun.security.util.ECUtil;

import java.security.interfaces.ECPublicKey;

import static com.tesco.encryptionservice.ssh.parser.encode.ByteOutputStream.getInstance;

public class EcdsaSshCertificateEncoder extends SshCertificateEncoder<ECPublicKey> {

    @Override
    @SneakyThrows
    public byte[] encode(SshCertificate<ECPublicKey> sshCertificate) {
        @Cleanup ByteOutputStream byteOutputStream =
                getInstance(encodeSignedBytes(sshCertificate));
        // signature
        encodeSignature(byteOutputStream, sshCertificate);
        return byteOutputStream.toByteArray();
    }

    @Override
    @SneakyThrows
    public byte[] encodeSignedBytes(SshCertificate<ECPublicKey> sshCertificate) {
        @Cleanup ByteOutputStream byteOutputStream = getInstance();
        EcdsaSshCertificate ecdsaCertificate = (EcdsaSshCertificate) sshCertificate;
        // algorithm
        byteOutputStream.writeString(ecdsaCertificate.sshCertificateAlgorithm().algorithmName());
        // nonce
        byteOutputStream.writeBytes(ecdsaCertificate.nonce());
        // curve
        byteOutputStream.writeString(ecdsaCertificate.curve());
        // public key
        byteOutputStream.writeBytes(encodePublicKey(ecdsaCertificate.publicKey()));
        // common fields
        encodeCommonSignedBytes(byteOutputStream, ecdsaCertificate);
        return byteOutputStream.toByteArray();
    }

    private byte[] encodePublicKey(ECPublicKey ecPublicKey) {
        return ECUtil.encodePoint(ecPublicKey.getW(), ecPublicKey.getParams().getCurve());
    }

}
