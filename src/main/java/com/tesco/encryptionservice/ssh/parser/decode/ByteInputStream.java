package com.tesco.encryptionservice.ssh.parser.decode;

import com.tesco.encryptionservice.ssh.parser.UnsignedInteger64;
import lombok.SneakyThrows;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.math.BigInteger;

public class ByteInputStream extends DataInputStream {

    public ByteInputStream(byte[] bytes) {
        super(new ByteArrayInputStream(bytes));
    }

    @SneakyThrows
    public UnsignedInteger64 readUINT64() {
        byte[] bytes = new byte[9];
        readFully(bytes, 1, 8);
        return new UnsignedInteger64(bytes);
    }

    @SneakyThrows
    public byte[] readByteArray() {
        int length = readInt();
        if (length <= available()) {
            byte[] bytes = new byte[length];
            readFully(bytes);
            return bytes;
        } else {
            throw new IllegalArgumentException("Invalid byte sequence");
        }
    }

    public BigInteger readBigInteger() {
        return new BigInteger(readByteArray());
    }

    public String readString() {
        return new String(readByteArray());
    }
}
