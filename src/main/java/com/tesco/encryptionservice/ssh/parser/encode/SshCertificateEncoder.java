package com.tesco.encryptionservice.ssh.parser.encode;

import com.tesco.encryptionservice.ssh.certificate.SshCertificate;
import com.tesco.encryptionservice.ssh.parser.UnsignedInteger64;
import lombok.Cleanup;
import lombok.SneakyThrows;
import sun.security.util.DerInputStream;
import sun.security.util.DerValue;
import sun.security.util.ECUtil;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;

import static com.tesco.encryptionservice.ssh.parser.decode.OpenSSHPublicKeyDecoder.lookupCurveName;
import static com.tesco.encryptionservice.ssh.parser.encode.ByteOutputStream.getInstance;
import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;

@SuppressWarnings("UnusedReturnValue")
public abstract class SshCertificateEncoder<T extends PublicKey> {

    @SneakyThrows
    public byte[] encode(SshCertificate<T> sshCertificate) {
        @Cleanup ByteOutputStream byteOutputStream =
                getInstance(encodeSignedBytes(sshCertificate));
        // signature
        encodeSignature(byteOutputStream, sshCertificate);
        return byteOutputStream.toByteArray();
    }

    public abstract byte[] encodeSignedBytes(SshCertificate<T> parentCertificate);

    @SneakyThrows
    public void encodeToFile(SshCertificate<T> certificate, String comment, File certificateFile) {
        @Cleanup FileWriter writer = new FileWriter(certificateFile, UTF_8);
        writer.write(encodeToString(certificate, comment));
    }

    @SneakyThrows
    public String encodeToString(SshCertificate<T> certificate, String comment) {
        byte[] bytes = encode(certificate);
        String base64EncodedContents = Base64.getEncoder().encodeToString(bytes);
        return format("%s %s %s", certificate.sshCertificateAlgorithm().algorithmName(), base64EncodedContents, comment);
    }

    @SneakyThrows
    protected void encodeSignature(ByteOutputStream byteArrayEncoder, SshCertificate<T> certificate) {
        @Cleanup ByteOutputStream signatureByteArrayDecoder = ByteOutputStream.getInstance();
        // signature algorithm
        signatureByteArrayDecoder.writeString(certificate.signatureAlgorithm());
        // signature
        signatureByteArrayDecoder.writeBytes(certificate.signature());
        byteArrayEncoder.writeBytes(signatureByteArrayDecoder.toByteArray());
    }

    @SneakyThrows
    public void encodeCommonSignedBytes(ByteOutputStream byteOutputStream, SshCertificate<T> certificate) {
        // serial
        byteOutputStream.writeUINT64(new UnsignedInteger64(certificate.serial()));
        // type
        byteOutputStream.writeInt(certificate.type().getType());
        // keyId
        byteOutputStream.writeString(certificate.keyId());
        // principals
        byteOutputStream.writeBytes(encodeValueList(certificate.validPrincipals()));
        // valid after
        byteOutputStream.writeUINT64(certificate.validAfter().getEpochSecond());
        // valid before
        byteOutputStream.writeUINT64(certificate.validBefore().getEpochSecond());
        // critical options
        byteOutputStream.writeBytes(encodeKeyValueList(certificate.criticalOptions()));
        // extensions
        byteOutputStream.writeBytes(encodeKeyValueList(certificate.extensions()));
        // reserved
        byteOutputStream.writeString(certificate.reserved());
        // signing key
        byteOutputStream.writeBytes(encodeSignatureKey(certificate.signatureKey()));
    }

    @SneakyThrows
    private byte[] encodeValueList(LinkedHashSet<String> values) {
        @Cleanup ByteOutputStream valuesBinaryOutputStream = getInstance();
        for (String value : values) {
            valuesBinaryOutputStream.writeString(value);
        }
        return valuesBinaryOutputStream.toByteArray();
    }

    @SneakyThrows
    private byte[] encodeKeyValueList(LinkedHashMap<String, String> keyValues) {
        @Cleanup ByteOutputStream keyValuesBinaryOutputStream = getInstance();
        for (Map.Entry<String, String> option : keyValues.entrySet()) {
            keyValuesBinaryOutputStream.writeString(option.getKey());
            if (option.getValue().isEmpty()) {
                keyValuesBinaryOutputStream.writeBytes(new byte[0]);
            } else {
                @Cleanup ByteOutputStream valueByteOutputStream = getInstance();
                valueByteOutputStream.writeString(option.getValue());
                keyValuesBinaryOutputStream.writeBytes(valueByteOutputStream.toByteArray());
            }
        }
        return keyValuesBinaryOutputStream.toByteArray();
    }

    @SneakyThrows
    public byte[] encodeSignatureKey(PublicKey publicKey) {
        if (publicKey instanceof RSAPublicKey) {
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            @Cleanup ByteOutputStream signatureKeyByteOutputStream = getInstance();
            signatureKeyByteOutputStream.writeString("ssh-rsa");
            signatureKeyByteOutputStream.writeBigInteger(rsaPublicKey.getPublicExponent());
            signatureKeyByteOutputStream.writeBigInteger(rsaPublicKey.getModulus());
            return signatureKeyByteOutputStream.toByteArray();
        } else if (publicKey instanceof ECPublicKey) {
            ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
            @Cleanup ByteOutputStream signatureKeyByteOutputStream = getInstance();
            String curve = lookupCurveName(ecPublicKey);
            signatureKeyByteOutputStream.writeString("ecdsa-sha2-" + curve);
            signatureKeyByteOutputStream.writeString(curve);
            signatureKeyByteOutputStream.writeBytes(ECUtil.encodePoint(ecPublicKey.getW(), ecPublicKey.getParams().getCurve()));
            return signatureKeyByteOutputStream.toByteArray();
        } else {
            throw new IllegalArgumentException("Unsupported signing key type \"" + publicKey.getClass().getSimpleName() + "\" expected RSAPublicKey or ECPublicKey");
        }
    }

    @SneakyThrows
    public byte[] encodeSignature(String algorithm, byte[] signature) {
        if (algorithm.equals("ssh-rsa") || algorithm.startsWith("rsa-sha2")) {
            return signature;
        } else if (algorithm.startsWith("ecdsa-sha2")) {
            @Cleanup ByteOutputStream byteOutputStream = getInstance();
            DerInputStream in = new DerInputStream(signature, 0, signature.length, false);
            DerValue[] values = in.getSequence(2);
            // check number of components in the read sequence and trailing data
            if ((values.length != 2) || (in.available() != 0)) {
                throw new IOException("Invalid encoding for signature");
            }
            // r value of signature
            byteOutputStream.writeBigInteger(values[0].getPositiveBigInteger());
            // s value of signature
            byteOutputStream.writeBigInteger(values[1].getPositiveBigInteger());
            return byteOutputStream.toByteArray();
        } else {
            throw new IllegalArgumentException("Unsupported algorithm \"" + algorithm + "\" expected value starting with \"rsa-sha\" or \"ecdsa-sha\"");
        }
    }
}
