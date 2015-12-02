package net.clarenceho.ssl;

import java.util.List;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;

import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

/**
 * Custom SSL Socket Factory to specify specific cipher suites
 *
 * @author clarenceho at gmail dot com
 *
 */
public class PrefSSLSocketFactory extends SSLSocketFactory {

    private SSLSocketFactory factory;
    private String[] ciphers;

    /**
     * Creates instance of the factory by specifying the protocol
     *
     * @param protocol SSLContext algorithm to use. e.g. SSL, SSLv2, SSLv3, TLS, TLSv1, TLSv1.1, TLSv1.2
     * @throws KeyManagementException
     * @throws NoSuchAlgorithmException
     */
    public PrefSSLSocketFactory(String protocol) throws KeyManagementException, NoSuchAlgorithmException  {

        SSLContext context = SSLContext.getInstance(protocol);
        // use default security providers and random parameter
        context.init(null, null, null);
        this.factory = (context.getSocketFactory());

        setCipher(new ArrayList<String>(
                Arrays.asList(this.factory.getDefaultCipherSuites())));
    }

    /**
     * Creates instance of the factory by providing a delegate factory
     *
     * @param factory The delegate factory
     */
    public PrefSSLSocketFactory(SSLSocketFactory factory) {
        // delegate SSL functions to helper
        this.factory = factory;

        setCipher(new ArrayList<String>(
                Arrays.asList(this.factory.getDefaultCipherSuites())));
    }


    /**
     * Uses ECDHE cipher suites only
     */
    public void useECDHEOnly() {
        String[] currentCiphers = this.factory.getDefaultCipherSuites();
        ArrayList<String> newCiphers = new ArrayList<String>();
        for (String cipher : currentCiphers) {
            if (cipher.contains("_ECDHE_")) {
                newCiphers.add(cipher);
            }
        }
        setCipher(newCiphers);
    }

    /**
     * Doesn't use forward secrecy ciphers.  Note that this is considered to be UNSAFE!!!
     */
    public void useNoForwardSecrecy() {
        String[] currentCiphers = this.factory.getDefaultCipherSuites();
        ArrayList<String> newCiphers = new ArrayList<String>();
        for (String cipher : currentCiphers) {
            if (!(cipher.contains("_ECDHE_") || cipher.contains("_DHE_"))) {
                newCiphers.add(cipher);
            }
        }
        setCipher(newCiphers);

    }

    /**
     * Uses forward secrecy ciphers.
     */
    public void useForwardSecrecy() {
        String[] currentCiphers = this.factory.getDefaultCipherSuites();
        ArrayList<String> newCiphers = new ArrayList<String>();
        for (String cipher : currentCiphers) {
            if ((cipher.contains("_ECDHE_") || cipher.contains("_DHE_"))) {
                newCiphers.add(cipher);
            }
        }
        setCipher(newCiphers);

    }

    /**
     * Specifies the cipher suites to use.  Otherwise, will use the factory default
     *
     * @param ciphers
     */
    public void setCipher(List<String>ciphers) {
        this.ciphers = ciphers.toArray(new String[ciphers.size()]);
    }


    @Override
    public Socket createSocket(Socket arg0, String arg1, int arg2, boolean arg3) throws IOException {
        SSLSocket socket = (SSLSocket)this.factory.createSocket(arg0, arg1, arg2, arg3);
        socket.setEnabledCipherSuites(this.ciphers);
        return socket;
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return this.ciphers;
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return this.ciphers;
    }

    @Override
    public Socket createSocket(String arg0, int arg1) throws IOException, UnknownHostException {
        SSLSocket socket = (SSLSocket)this.factory.createSocket(arg0, arg1);
        socket.setEnabledCipherSuites(this.ciphers);
        return socket;
    }

    @Override
    public Socket createSocket(InetAddress arg0, int arg1) throws IOException {
        SSLSocket socket = (SSLSocket)this.factory.createSocket(arg0, arg1);
        socket.setEnabledCipherSuites(this.ciphers);
        return socket;
    }

    @Override
    public Socket createSocket(String arg0, int arg1, InetAddress arg2, int arg3)
            throws IOException, UnknownHostException {
        SSLSocket socket = (SSLSocket)this.factory.createSocket(arg0, arg1, arg2, arg3);
        socket.setEnabledCipherSuites(this.ciphers);
        return socket;
    }

    @Override
    public Socket createSocket(InetAddress arg0, int arg1, InetAddress arg2, int arg3) throws IOException {
        SSLSocket socket = (SSLSocket)this.factory.createSocket(arg0, arg1, arg2, arg3);
        socket.setEnabledCipherSuites(this.ciphers);
        return socket;
    }
}
