package com.tesco.encryptionservice.ssh.parser.algorithms;

import com.tesco.encryptionservice.ssh.certificate.SshCertificate;
import com.tesco.encryptionservice.ssh.parser.decode.SshCertificateDecoder;
import com.tesco.encryptionservice.ssh.parser.encode.SshCertificateEncoder;
import lombok.Data;
import lombok.experimental.Accessors;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Data
@Accessors(fluent = true)
public class SshCertificateAlgorithm<T extends PublicKey> {

    public static final List<SshCertificateAlgorithm<?>> SUPPORTED_ALGORITHMS = new ArrayList<>();

    private final String algorithmName;
    private final SshCertificateEncoder<T> encoder;
    private final SshCertificateDecoder<? extends SshCertificate<T>> decoder;

    private static void init() {
        if (SUPPORTED_ALGORITHMS.isEmpty()) {
            SUPPORTED_ALGORITHMS.add(new SshRsaCertV01());
            SUPPORTED_ALGORITHMS.add(new EcdsaSha2Nistp256CertV01());
            SUPPORTED_ALGORITHMS.add(new EcdsaSha2Nistp384CertV01());
            SUPPORTED_ALGORITHMS.add(new EcdsaSha2Nistp521CertV01());
        }
    }

    protected SshCertificateAlgorithm(String algorithmName, SshCertificateEncoder<T> encoder, SshCertificateDecoder<? extends SshCertificate<T>> decoder) {
        this.algorithmName = algorithmName;
        this.encoder = encoder;
        this.decoder = decoder;
    }

    public static SshCertificateAlgorithm<? extends PublicKey> get(String sshCertificateAlgorithm) {
        init();
        for (SshCertificateAlgorithm<?> certificateAlgorithm : SUPPORTED_ALGORITHMS) {
            if (certificateAlgorithm.algorithmName().equals(sshCertificateAlgorithm)) {
                return certificateAlgorithm;
            }
        }
        throw new IllegalArgumentException(sshCertificateAlgorithm + " is an unsupported algorithm, only allowed values are: " + SUPPORTED_ALGORITHMS);
    }

    public static EcdsaSshCertificateAlgorithm getByCurve(String curve) {
        init();
        for (SshCertificateAlgorithm<?> certificateAlgorithm : SUPPORTED_ALGORITHMS) {
            if (certificateAlgorithm instanceof EcdsaSshCertificateAlgorithm && ((EcdsaSshCertificateAlgorithm) certificateAlgorithm).supportedCurves().contains(curve)) {
                return (EcdsaSshCertificateAlgorithm) certificateAlgorithm;
            }
        }
        List<String> curves = SUPPORTED_ALGORITHMS
                .stream()
                .filter(certificateAlgorithm -> certificateAlgorithm instanceof EcdsaSshCertificateAlgorithm)
                .flatMap(certificateAlgorithm -> ((EcdsaSshCertificateAlgorithm) certificateAlgorithm).supportedCurves().stream())
                .collect(Collectors.toList());
        throw new IllegalArgumentException(curve + " is an unsupported curve, only allowed values are: " + curves);
    }

    @SuppressWarnings("unchecked")
    public byte[] encode(SshCertificate<? extends PublicKey> certificate) {
        return encoder.encode((SshCertificate<T>) certificate);
    }

    public SshCertificate<? extends PublicKey> decode(byte[] bytes) {
        return decoder.decode(bytes);
    }
}
