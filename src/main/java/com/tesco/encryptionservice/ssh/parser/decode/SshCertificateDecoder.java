package com.tesco.encryptionservice.ssh.parser.decode;

import com.tesco.encryptionservice.ssh.certificate.SshCertificate;
import com.tesco.encryptionservice.ssh.certificate.SshCertificateType;
import lombok.Cleanup;
import lombok.SneakyThrows;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ECUtil;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.tesco.encryptionservice.ssh.certificate.EcdsaSshCertificate.SUPPORTED_EC_CURVES;
import static java.util.Base64.getDecoder;
import static java.util.regex.Pattern.compile;

public abstract class SshCertificateDecoder<T extends SshCertificate<?>> {

    @SneakyThrows
    public T decode(File file) {
        String certificateFileContents = Files.readString(file.toPath());
        return decode(certificateFileContents);
    }

    @SneakyThrows
    public T decode(String fileContents) {
        Pattern pattern = compile(" (.*?) ");
        Matcher m = pattern.matcher(fileContents);
        if (m.find()) {
            byte[] base64EncodedContent = (new String(m.group().getBytes())).replaceAll(" ", "").getBytes();
            return decode(getDecoder().decode(base64EncodedContent));
        } else {
            throw new IllegalArgumentException("Invalid format, did not find certificate body");
        }
    }

    public abstract T decode(byte[] bytes);

    @SneakyThrows
    void decodeCommon(ByteInputStream byteArrayDecoder, T certificate) {
        certificate
                .serial(byteArrayDecoder.readUINT64())
                .type(SshCertificateType.getType(byteArrayDecoder.readInt()))
                .keyId(byteArrayDecoder.readString())
                .validPrincipals(readValueList(byteArrayDecoder))
                .validAfter(Instant.ofEpochSecond(byteArrayDecoder.readUINT64().longValue()))
                .validBefore(Instant.ofEpochSecond(byteArrayDecoder.readUINT64().longValue()))
                .criticalOptions(readKeyValueList(byteArrayDecoder))
                .extensions(readKeyValueList(byteArrayDecoder))
                .reserved(byteArrayDecoder.readString())
                .signatureKey(decodeSignatureKey(byteArrayDecoder.readByteArray()));

        @Cleanup ByteInputStream signatureByteArrayDecoder = new ByteInputStream(byteArrayDecoder.readByteArray());
        certificate.signatureAlgorithm(signatureByteArrayDecoder.readString());
        certificate.signature(signatureByteArrayDecoder.readByteArray());
    }

    private LinkedHashMap<String, String> readKeyValueList(ByteInputStream byteArrayDecoder) throws IOException {
        @Cleanup ByteInputStream keyValuesBinaryInputStream = new ByteInputStream(byteArrayDecoder.readByteArray());
        LinkedHashMap<String, String> keyValues = new LinkedHashMap<>();
        while (keyValuesBinaryInputStream.available() > 0) {
            String name = keyValuesBinaryInputStream.readString();
            @Cleanup ByteInputStream valueByteInputStream = new ByteInputStream(keyValuesBinaryInputStream.readByteArray());
            if (valueByteInputStream.available() > 0) {
                keyValues.put(name, valueByteInputStream.readString());
            } else {
                keyValues.put(name, "");
            }
        }
        return keyValues;
    }

    private LinkedHashSet<String> readValueList(ByteInputStream byteArrayDecoder) throws IOException {
        @Cleanup ByteInputStream valuesByteInputStream = new ByteInputStream(byteArrayDecoder.readByteArray());
        LinkedHashSet<String> values = new LinkedHashSet<>();
        while (valuesByteInputStream.available() > 0) {
            values.add(valuesByteInputStream.readString());
        }
        return values;
    }

    @SneakyThrows
    protected PublicKey decodeSignatureKey(byte[] bytes) {
        @Cleanup ByteInputStream signatureKeyByteArrayDecoder = new ByteInputStream(bytes);
        String signatureKeyType = signatureKeyByteArrayDecoder.readString();
        if (signatureKeyType.equals("ssh-rsa")) {
            BigInteger publicExponent = signatureKeyByteArrayDecoder.readBigInteger();
            BigInteger modulus = signatureKeyByteArrayDecoder.readBigInteger();
            RSAPublicKeySpec rsaPubKeySpec = new RSAPublicKeySpec(modulus, publicExponent);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(rsaPubKeySpec);
        } else if (signatureKeyType.startsWith("ecdsa-sha2-")) {
            String curveIdentifier = signatureKeyByteArrayDecoder.readString();
            byte[] keyBlob = signatureKeyByteArrayDecoder.readByteArray();

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(new ECGenParameterSpec(SUPPORTED_EC_CURVES.get(curveIdentifier)));
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            ECParameterSpec ecParameterSpec = ((ECPublicKey) keyPair.getPublic()).getParams();

            ECPoint ecPoint = ECUtil.decodePoint(keyBlob, ecParameterSpec.getCurve());

            KeyFactory factory = KeyFactory.getInstance("EC");
            ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
            return factory.generatePublic(ecPublicKeySpec);
        } else {
            throw new IllegalArgumentException("Unsupported signing key type \"" + signatureKeyType + "\" expected RSAPublicKey or ECPublicKey");
        }
    }

    @SneakyThrows
    public byte[] decodeSignature(String algorithm, byte[] signature) {
        if (algorithm.startsWith("ssh-rsa") || algorithm.startsWith("rsa-sha2")) {
            return signature;
        } else if (algorithm.startsWith("ecdsa-sha2")) {
            ByteInputStream byteInputStream = new ByteInputStream(signature);
            DerOutputStream derOutputStream = new DerOutputStream(signature.length + 10);
            // r value of signature
            derOutputStream.putInteger(byteInputStream.readBigInteger());
            // s value of signature
            derOutputStream.putInteger(byteInputStream.readBigInteger());
            DerValue derValue = new DerValue(DerValue.tag_Sequence, derOutputStream.toByteArray());
            return derValue.toByteArray();
        } else {
            throw new IllegalArgumentException("Unsupported algorithm \"" + algorithm + "\" expected value starting with \"rsa-sha\" or \"ecdsa-sha\"");
        }
    }

}
