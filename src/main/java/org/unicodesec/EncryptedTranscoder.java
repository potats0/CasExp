package org.unicodesec;

import org.cryptacular.bean.BufferedBlockCipherBean;
import org.cryptacular.bean.CipherBean;
import org.cryptacular.bean.KeyStoreFactoryBean;
import org.cryptacular.generator.sp80038a.RBGNonce;
import org.cryptacular.io.URLResource;
import org.cryptacular.spec.BufferedBlockCipherSpec;
import org.jasig.spring.webflow.plugin.Transcoder;
import payloads.Serializer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.URL;
import java.security.KeyStore;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

public class EncryptedTranscoder implements Transcoder {
    private CipherBean cipherBean;
    private boolean compression = true;

    public EncryptedTranscoder() {
        BufferedBlockCipherBean bufferedBlockCipherBean = new BufferedBlockCipherBean();
        bufferedBlockCipherBean.setBlockCipherSpec(new BufferedBlockCipherSpec("AES", "CBC", "PKCS7"));
        bufferedBlockCipherBean.setKeyStore(this.createAndPrepareKeyStore());
        bufferedBlockCipherBean.setKeyAlias("aes128");
        bufferedBlockCipherBean.setKeyPassword("changeit");
        bufferedBlockCipherBean.setNonce(new RBGNonce());
        this.setCipherBean(bufferedBlockCipherBean);
    }

    public EncryptedTranscoder(CipherBean cipherBean) throws IOException {
        this.setCipherBean(cipherBean);
    }

    public void setCompression(boolean compression) {
        this.compression = compression;
    }

    protected void setCipherBean(CipherBean cipherBean) {
        this.cipherBean = cipherBean;
    }

    public byte[] encode(Object o) throws IOException {
        if (o == null) {
            return new byte[0];
        }

        byte[] out = null;

        if (this.compression) {
            ByteArrayOutputStream byteout = new ByteArrayOutputStream();
            GZIPOutputStream gzip = new GZIPOutputStream(byteout);
            gzip.write(Serializer.serialize(o));
            gzip.close();
            out = byteout.toByteArray();
        } else {
            out = Serializer.serialize(o);
        }
        return this.cipherBean.encrypt(out);

    }

    public Object decode(byte[] encoded) throws IOException {
        byte[] data;
        try {
            data = this.cipherBean.decrypt(encoded);
        } catch (Exception var11) {
            throw new IOException("Decryption error", var11);
        }

        ByteArrayInputStream inBuffer = new ByteArrayInputStream(data);
        ObjectInputStream in = null;

        Object var5;
        try {
            if (this.compression) {
                in = new ObjectInputStream(new GZIPInputStream(inBuffer));
            } else {
                in = new ObjectInputStream(inBuffer);
            }

            var5 = in.readObject();
        } catch (ClassNotFoundException var10) {
            throw new IOException("Deserialization error", var10);
        } finally {
            if (in != null) {
                in.close();
            }

        }

        return var5;
    }

    protected KeyStore createAndPrepareKeyStore() {
        KeyStoreFactoryBean ksFactory = new KeyStoreFactoryBean();
        URL u = this.getClass().getResource("/etc/keystore.jceks");
        ksFactory.setResource(new URLResource(u));
        ksFactory.setType("JCEKS");
        ksFactory.setPassword("changeit");
        return ksFactory.newInstance();
    }
}
