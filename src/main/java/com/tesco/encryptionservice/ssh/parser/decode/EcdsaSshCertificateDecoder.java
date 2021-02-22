package com.tesco.encryptionservice.ssh.parser.decode;

import com.tesco.encryptionservice.ssh.certificate.EcdsaSshCertificate;
import com.tesco.encryptionservice.ssh.certificate.SshCertificate;
import com.tesco.encryptionservice.ssh.parser.algorithms.SshCertificateAlgorithm;
import lombok.Cleanup;
import lombok.SneakyThrows;
import sun.security.util.ECUtil;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;

public abstract class EcdsaSshCertificateDecoder<E extends SshCertificate<ECPublicKey>> extends SshCertificateDecoder<EcdsaSshCertificate> {

    @SneakyThrows
    @SuppressWarnings("unchecked")
    EcdsaSshCertificate decode(byte[] bytes, String expectedCertificateAlgorithm, String ellipticCurveKeyStandard) {
        @Cleanup ByteInputStream byteArrayDecoder = new ByteInputStream(bytes);
        String certificateAlgorithm = byteArrayDecoder.readString();
        if (!certificateAlgorithm.equals(expectedCertificateAlgorithm)) {
            throw new IllegalArgumentException("Unexpected signing algorithm, found: \"" + certificateAlgorithm + "\" expected: \"" + expectedCertificateAlgorithm + "\"");
        }

        EcdsaSshCertificate certificate = new EcdsaSshCertificate((SshCertificateAlgorithm<ECPublicKey>) SshCertificateAlgorithm.get(certificateAlgorithm))
                .nonce(byteArrayDecoder.readByteArray())
                .curve(byteArrayDecoder.readString())
                .publicKey(decodePublicKey(byteArrayDecoder.readByteArray(), ellipticCurveKeyStandard));
        decodeCommon(byteArrayDecoder, certificate);
        return certificate;
    }

    @SneakyThrows
    private ECPublicKey decodePublicKey(byte[] keyBlob, String ellipticCurveKeyStandard) {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");

        keyPairGenerator.initialize(new ECGenParameterSpec(ellipticCurveKeyStandard));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        ECParameterSpec ecParameterSpec = ((ECPublicKey) keyPair.getPublic()).getParams();

        ECPoint ecPoint = ECUtil.decodePoint(keyBlob, ecParameterSpec.getCurve());

        KeyFactory factory = KeyFactory.getInstance("EC");
        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
        return (ECPublicKey) factory.generatePublic(ecPublicKeySpec);
    }

}
