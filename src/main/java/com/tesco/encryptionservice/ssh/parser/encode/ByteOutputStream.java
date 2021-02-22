package com.tesco.encryptionservice.ssh.parser.encode;

import com.tesco.encryptionservice.ssh.parser.UnsignedInteger64;
import lombok.SneakyThrows;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.math.BigInteger;

public class ByteOutputStream extends DataOutputStream {

    private final ByteArrayOutputStream byteArrayOutputStream;

    public ByteOutputStream(ByteArrayOutputStream byteArrayOutputStream) {
        super(byteArrayOutputStream);
        this.byteArrayOutputStream = byteArrayOutputStream;
    }

    public static ByteOutputStream getInstance() {
        return new ByteOutputStream(new ByteArrayOutputStream());
    }

    @SneakyThrows
    public static ByteOutputStream getInstance(byte[] bytes) {
        ByteOutputStream byteOutputStream = new ByteOutputStream(new ByteArrayOutputStream());
        byteOutputStream.write(bytes);
        return byteOutputStream;
    }

    @SneakyThrows
    public void writeString(String string) {
        if (string == null) {
            writeInt(0);
        } else {
            writeBytes(string.getBytes());
        }
    }

    @SneakyThrows
    public void writeBigInteger(BigInteger bigInteger) {
        if (bigInteger == null) {
            writeInt(0);
        } else {
            writeBytes(bigInteger.toByteArray());
        }

    }

    @SneakyThrows
    public void writeBytes(byte[] bytes) {
        if (bytes == null) {
            writeInt(0);
        } else {
            writeInt(bytes.length);
            write(bytes);
        }
    }

    @SneakyThrows
    public void writeUINT64(UnsignedInteger64 value) {
        byte[] rawUnsignedInteger = value.toByteArray();
        if (rawUnsignedInteger.length > 8) {
            throw new IllegalArgumentException("unsigned integer has more than 8 bytes");
        }
        byte[] paddedUnsignedInteger = new byte[8];
        System.arraycopy(rawUnsignedInteger, 0, paddedUnsignedInteger, paddedUnsignedInteger.length - rawUnsignedInteger.length, rawUnsignedInteger.length);
        // Pad the paddedUnsignedInteger data
        write(paddedUnsignedInteger);
    }

    public void writeUINT64(long value) {
        writeUINT64(new UnsignedInteger64(BigInteger.valueOf(value)));
    }

    public byte[] toByteArray() {
        return byteArrayOutputStream.toByteArray();
    }

}
