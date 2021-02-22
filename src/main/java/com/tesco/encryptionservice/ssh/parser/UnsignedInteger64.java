package com.tesco.encryptionservice.ssh.parser;

import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.SneakyThrows;

import java.math.BigInteger;

@EqualsAndHashCode(callSuper = true)
public class UnsignedInteger64 extends BigInteger {

    public final static BigInteger MIN_VALUE = BigInteger.ZERO;
    public final static BigInteger MAX_VALUE = new BigInteger(String.format("%.0f", Math.pow(2, 64) - 1));

    public UnsignedInteger64(byte[] valueBytes) {
        super(valueBytes);
        isInRange(this);
    }

    public UnsignedInteger64(BigInteger value) {
        super(value.toByteArray());
        isInRange(this);
    }

    @SneakyThrows
    public static void isInRange(BigInteger bigInteger) {
        if (bigInteger.toByteArray().length > 8) {
            throw new IllegalArgumentException("integer has more than 8 bytes");
        }
        if ((bigInteger.compareTo(MIN_VALUE) < 0) || (bigInteger.compareTo(MAX_VALUE) > 0)) {
            throw new Exception("Integer is outside of expected range");
        }
    }

    @NonNull
    @Override
    @SuppressWarnings("NullableProblems")
    public byte[] toByteArray() {
        byte[] rawUnsignedInteger = super.toByteArray();
        if (rawUnsignedInteger.length > 8) {
            throw new IllegalArgumentException("unsigned integer has more than 8 bytes");
        }
        byte[] paddedUnsignedInteger = new byte[8];
        System.arraycopy(rawUnsignedInteger, 0, paddedUnsignedInteger, paddedUnsignedInteger.length - rawUnsignedInteger.length, rawUnsignedInteger.length);
        return paddedUnsignedInteger;
    }

}
