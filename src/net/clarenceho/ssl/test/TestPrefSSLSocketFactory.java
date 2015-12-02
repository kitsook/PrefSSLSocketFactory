package net.clarenceho.ssl.test;

import net.clarenceho.ssl.PrefSSLSocketFactory;

import org.junit.*;
import static org.junit.Assert.*;
import org.junit.runners.MethodSorters;

import java.net.URL;
import java.util.ArrayList;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class TestPrefSSLSocketFactory {

    @BeforeClass
    public static void oneTimeSetup() {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, null, null);
            SSLSocketFactory factory = context.getSocketFactory();
            System.out.println("Default TLS cipher suites:");
            printDefaultCiphers(factory);
        } catch (Exception e) {
            e.printStackTrace(System.err);
        }

    }

    @AfterClass
    public static void oneTimeCleanup() {

    }

    @Test
    public void testCustomDelegate() throws Exception {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            // use default security providers and random parameter
            context.init(null, null, null);
            SSLSocketFactory prefFactory = new PrefSSLSocketFactory(context.getSocketFactory());
            testConnection(prefFactory);
        } catch (Exception e) {
            e.printStackTrace(System.err);
            throw(e);
        }
    }
    
    @Test
    public void testCreateTLS12() throws Exception {
        try {
            SSLSocketFactory prefFactory = new PrefSSLSocketFactory("TLSv1.2");
            testConnection(prefFactory);
        } catch (Exception e) {
            e.printStackTrace(System.err);
            throw(e);
        }
    }
    
    @Test
    public void testCreateSSL3() throws Exception {
        try {
            SSLSocketFactory prefFactory = new PrefSSLSocketFactory("SSLv3");
            testConnection(prefFactory);
        } catch (Exception e) {
            e.printStackTrace(System.err);
            throw(e);
        }
    }
    
    @Test
    public void testECDHEOnly() throws Exception {
        try {
            PrefSSLSocketFactory prefFactory = new PrefSSLSocketFactory("TLS");
            prefFactory.useECDHEOnly();
            String cipher = testConnection(prefFactory);
            assertTrue(cipher.contains("_ECDHE_"));
        } catch (Exception e) {
            e.printStackTrace(System.err);
            throw(e);
        }
    }

    @Test
    public void testNoForwardSecrecy() throws Exception {
        try {
            PrefSSLSocketFactory prefFactory = new PrefSSLSocketFactory("TLS");
            prefFactory.useNoForwardSecrecy();
            String cipher = testConnection(prefFactory);
            assertTrue(!cipher.contains("_ECDHE_"));
            assertTrue(!cipher.contains("_DHE_"));
        } catch (Exception e) {
            e.printStackTrace(System.err);
            throw(e);
        }
    }

    @Test
    public void testForwardSecrecy() throws Exception {
        try {
            PrefSSLSocketFactory prefFactory = new PrefSSLSocketFactory("TLS");
            prefFactory.useForwardSecrecy();
            String cipher = testConnection(prefFactory);
            assertTrue(cipher.contains("_ECDHE_") || cipher.contains("_DHE_"));
        } catch (Exception e) {
            e.printStackTrace(System.err);
            throw(e);
        }
    }
    
    @Test
    public void testSpecificCipher01() throws Exception {
        try {
            PrefSSLSocketFactory prefFactory = new PrefSSLSocketFactory("TLS");
            ArrayList<String> ciphers = new ArrayList<String>();
            ciphers.add("TLS_RSA_WITH_AES_128_CBC_SHA256");
            prefFactory.setCipher(ciphers);
            String cipher = testConnection(prefFactory);
            assertEquals(cipher, "TLS_RSA_WITH_AES_128_CBC_SHA256");
        } catch (Exception e) {
            e.printStackTrace(System.err);
            throw(e);
        }
    }
    
    @Test
    public void testSpecificCipher02() throws Exception {
        try {
            PrefSSLSocketFactory prefFactory = new PrefSSLSocketFactory("TLS");
            ArrayList<String> ciphers = new ArrayList<String>();
            ciphers.add("TLS_RSA_WITH_AES_128_CBC_SHA");
            ciphers.add("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256");
            ciphers.add("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA");
            prefFactory.setCipher(ciphers);
            String cipher = testConnection(prefFactory);
            assertTrue(
                    cipher.contains("TLS_RSA_WITH_AES_128_CBC_SHA") ||
                    cipher.contains("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256") ||
                    cipher.contains("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA")
                    );
        } catch (Exception e) {
            e.printStackTrace(System.err);
            throw(e);
        }
    }
    

    private String testConnection(SSLSocketFactory factory) throws Exception {
        String url = "https://www.google.com/";
        HttpsURLConnection connection = (HttpsURLConnection) (new URL(url)).openConnection();
        connection.setSSLSocketFactory(factory);
        connection.connect();
        String cipherSuite = connection.getCipherSuite();
        System.out.println("SSL connection established with cipher:" + cipherSuite);
        assertEquals(connection.getResponseCode(), 200);
        connection.disconnect();
        return cipherSuite;
    }

    
    private static void printDefaultCiphers(SSLSocketFactory factory) {
        for (String cipher : factory.getDefaultCipherSuites()) {
            System.out.println(cipher);
        }
    }
}
