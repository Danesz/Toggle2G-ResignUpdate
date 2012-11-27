/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.mb.resign;

import sun.misc.BASE64Encoder;
import sun.security.pkcs.ContentInfo;
import sun.security.pkcs.PKCS7;
import sun.security.pkcs.SignerInfo;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X500Name;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.security.DigestOutputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Command line tool to sign JAR files (including APKs and OTA updates) in a way
 * compatible with the mincrypt verifier, using SHA1 and RSA keys.
 */
class SignApkHelper
{
    private static final String CERT_SF_NAME = "META-INF/CERT.SF";
    private static final String CERT_RSA_NAME = "META-INF/CERT.RSA";

    // Files matching this pattern are not copied to the output.
    private static Pattern stripPattern = Pattern.compile("^META-INF/(.*)[.](SF|RSA|DSA)$");

    private static X509Certificate readPublicKey(File file) throws IOException, GeneralSecurityException
    {
        FileInputStream input = new FileInputStream(file);
        try
        {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(input);
        }
        finally
        {
            input.close();
        }
    }

    /**
     * Reads the password from stdin and returns it as a string.
     * 
     * @param keyFile
     *            The file containing the private key. Used to prompt the user.
     */
    private static String readPassword(File keyFile)
    {
        // TODO: use Console.readPassword() when it's available.
        System.out.print("Enter password for " + keyFile + " (password will not be hidden): ");
        System.out.flush();
        BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in));
        try
        {
            return stdin.readLine();
        }
        catch (IOException ex)
        {
            return null;
        }
    }

    /**
     * Decrypt an encrypted PKCS 8 format private key.
     * 
     * Based on ghstark's post on Aug 6, 2006 at
     * http://forums.sun.com/thread.jspa?threadID=758133&messageID=4330949
     * 
     * @param encryptedPrivateKey
     *            The raw data of the private key
     * @param keyFile
     *            The file containing the private key
     */
    private static KeySpec decryptPrivateKey(byte[] encryptedPrivateKey, File keyFile) throws GeneralSecurityException
    {
        EncryptedPrivateKeyInfo epkInfo;
        try
        {
            epkInfo = new EncryptedPrivateKeyInfo(encryptedPrivateKey);
        }
        catch (IOException ex)
        {
            // Probably not an encrypted key.
            return null;
        }

        char[] password = readPassword(keyFile).toCharArray();

        SecretKeyFactory skFactory = SecretKeyFactory.getInstance(epkInfo.getAlgName());
        Key key = skFactory.generateSecret(new PBEKeySpec(password));

        Cipher cipher = Cipher.getInstance(epkInfo.getAlgName());
        cipher.init(Cipher.DECRYPT_MODE, key, epkInfo.getAlgParameters());

        try
        {
            return epkInfo.getKeySpec(cipher);
        }
        catch (InvalidKeySpecException ex)
        {
            System.err.println("signapk: Password for " + keyFile + " may be bad.");
            throw ex;
        }
    }

    /** Read a PKCS 8 format private key. */
    private static PrivateKey readPrivateKey(File file) throws IOException, GeneralSecurityException
    {
        DataInputStream input = new DataInputStream(new FileInputStream(file));
        try
        {
            byte[] bytes = new byte[(int) file.length()];
            input.read(bytes);

            KeySpec spec = decryptPrivateKey(bytes, file);
            if (spec == null)
            {
                spec = new PKCS8EncodedKeySpec(bytes);
            }

            try
            {
                return KeyFactory.getInstance("RSA").generatePrivate(spec);
            }
            catch (InvalidKeySpecException ex)
            {
                return KeyFactory.getInstance("DSA").generatePrivate(spec);
            }
        }
        finally
        {
            input.close();
        }
    }

    /** Add the SHA1 of every file to the manifest, creating it if necessary. */
    private static Manifest addDigestsToManifest(JarFile jar) throws IOException, GeneralSecurityException
    {
        Manifest input = jar.getManifest();
        Manifest output = new Manifest();
        Attributes main = output.getMainAttributes();
        if (input != null)
        {
            main.putAll(input.getMainAttributes());
        }
        else
        {
            main.putValue("Manifest-Version", "1.0");
            main.putValue("Created-By", "1.0 (Android SignApk)");
        }

        BASE64Encoder base64 = new BASE64Encoder();
        MessageDigest md = MessageDigest.getInstance("SHA1");
        byte[] buffer = new byte[4096];
        int num;

        // We sort the input entries by name, and add them to the
        // output manifest in sorted order. We expect that the output
        // map will be deterministic.

        TreeMap<String, JarEntry> byName = new TreeMap<String, JarEntry>();

        for (Enumeration<JarEntry> e = jar.entries(); e.hasMoreElements();)
        {
            JarEntry entry = e.nextElement();
            byName.put(entry.getName(), entry);
        }

        for (JarEntry entry : byName.values())
        {
            String name = entry.getName();
            if (!entry.isDirectory() && !name.equals(JarFile.MANIFEST_NAME) && !name.equals(CERT_SF_NAME) && !name.equals(CERT_RSA_NAME)
                    && (stripPattern == null || !stripPattern.matcher(name).matches()))
            {
                InputStream data = jar.getInputStream(entry);
                while ((num = data.read(buffer)) > 0)
                {
                    md.update(buffer, 0, num);
                }

                Attributes attr = null;
                if (input != null)
                    attr = input.getAttributes(name);
                attr = attr != null ? new Attributes(attr) : new Attributes();
                attr.putValue("SHA1-Digest", base64.encode(md.digest()));
                output.getEntries().put(name, attr);
            }
        }

        return output;
    }

    /** Write to another stream and also feed it to the Signature object. */
    private static class SignatureOutputStream extends FilterOutputStream
    {
        private Signature mSignature;

        public SignatureOutputStream(OutputStream out, Signature sig)
        {
            super(out);
            mSignature = sig;
        }

        @Override
        public void write(int b) throws IOException
        {
            try
            {
                mSignature.update((byte) b);
            }
            catch (SignatureException e)
            {
                throw new IOException("SignatureException: " + e);
            }
            super.write(b);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException
        {
            try
            {
                mSignature.update(b, off, len);
            }
            catch (SignatureException e)
            {
                throw new IOException("SignatureException: " + e);
            }
            super.write(b, off, len);
        }
    }

    /** Write a .SF file with a digest of the specified manifest. */
    private static void writeSignatureFile(Manifest manifest, OutputStream out) throws IOException, GeneralSecurityException
    {
        Manifest sf = new Manifest();
        Attributes main = sf.getMainAttributes();
        main.putValue("Signature-Version", "1.0");
        main.putValue("Created-By", "1.0 (Android SignApk)");

        BASE64Encoder base64 = new BASE64Encoder();
        MessageDigest md = MessageDigest.getInstance("SHA1");
        PrintStream print = new PrintStream(new DigestOutputStream(new ByteArrayOutputStream(), md), true, "UTF-8");

        // Digest of the entire manifest
        manifest.write(print);
        print.flush();
        main.putValue("SHA1-Digest-Manifest", base64.encode(md.digest()));

        Map<String, Attributes> entries = manifest.getEntries();
        
        for (Map.Entry<String, Attributes> entry : entries.entrySet())
        {
            // Digest of the manifest stanza for this entry.
            print.print("Name: " + entry.getKey() + "\r\n");
            for (Map.Entry<Object, Object> att : entry.getValue().entrySet())
            {
                print.print(att.getKey() + ": " + att.getValue() + "\r\n");
            }
            print.print("\r\n");
            print.flush();

            Attributes sfAttr = new Attributes();
            sfAttr.putValue("SHA1-Digest", base64.encode(md.digest()));
            sf.getEntries().put(entry.getKey(), sfAttr);
        }

        sf.write(out);
    }

    /** Write a .RSA file with a digital signature. */
    private static void writeSignatureBlock(Signature signature, X509Certificate publicKey, OutputStream out) throws IOException, GeneralSecurityException
    {
        SignerInfo signerInfo = new SignerInfo(new X500Name(publicKey.getIssuerX500Principal().getName()), publicKey.getSerialNumber(),
                AlgorithmId.get("SHA1"), AlgorithmId.get("RSA"), signature.sign());

        PKCS7 pkcs7 = new PKCS7(new AlgorithmId[] { AlgorithmId.get("SHA1") }, new ContentInfo(ContentInfo.DATA_OID, null),
                new X509Certificate[] { publicKey }, new SignerInfo[] { signerInfo });

        pkcs7.encodeSignedData(out);
    }

    /**
     * Copy all the files in a manifest from input to output. We set the
     * modification times in the output to a fixed time, so as to reduce
     * variation in the output file and make incremental OTAs more efficient.
     * @param align2 
     */
    private static void copyFiles(Manifest manifest, JarFile in, JarOutputStream out, long timestamp, boolean alignApk) throws IOException
    {
        byte[] buffer = new byte[4096];
        int num;

        Map<String, Attributes> entries = manifest.getEntries();
        List<String> names = new ArrayList<String>(entries.keySet());
        Collections.sort(names);
        
        int percent = 0;
        int item = 0;
        for ( int nameIdx = 0 ; nameIdx < names.size() ; nameIdx ++)
        {
            String name = names.get(nameIdx);
            JarEntry inEntry = in.getJarEntry(name);
            
            JarEntry outEntry = null;
            if (inEntry.getMethod() == JarEntry.STORED)
            {
                // Preserve the STORED method of the input entry.
                outEntry = new JarEntry(inEntry);
                outEntry.setExtra(new byte[0]);
            }
            else
            {
                // Create a new entry so that the compressed len is recomputed.
                outEntry = new JarEntry(name);
            }
            outEntry.setTime(timestamp);
            
            // align this element
            if( alignApk )
            {
                if (inEntry.getMethod() == ZipEntry.STORED)
                {
                    out.flush();
                    int size = countOutputBytes.getSize();
                    int headerSize = getHeaderSize(outEntry);
                    int offset = (size + headerSize) % 4;
                    
                    if ( offset != 0 )
                    {
                        int align = 4 - offset;
                        outEntry.setExtra(new byte[align]);
                        //System.out.println("Zip Aligning Data " + inEntry.getName() + " to " + (size +  getHeaderSize(outEntry)) + " off by " + offset + " (" + size + "," + headerSize + "," + getHeaderSize(outEntry) + ")");
                    }
                    else
                    {
                        //System.out.println("Not Zip Aligning Data " + inEntry.getName()+ " to " + (size +  getHeaderSize(outEntry)) );
                    }
                    
                }
                else
                {
                    //System.out.println("Not Zip Aligning Compressed Data " + inEntry.getName());
                }
            }
            
            out.putNextEntry(outEntry);
            out.flush();

            InputStream data = in.getInputStream(inEntry);
            while ((num = data.read(buffer)) > 0)
            {
                out.write(buffer, 0, num);
            }
            out.flush();
            out.closeEntry();
            
            item ++;
            if ( percent < 25 && ( (float)item  /  (float)names.size()  ) >= .25f )
            {
                System.out.print("...25%");
                percent = 25;
            }
            else if ( percent < 50 && ( (float)item  /  (float)names.size()  ) >= .50f )
            {
                System.out.print("...50%");
                percent = 50;
            }
            else if ( percent < 75 && ( (float)item  /  (float)names.size()  ) >= .75f )
            {
                System.out.print("...75%");
                percent = 75;
            }
        }
    }

    private static int getHeaderSize(ZipEntry outEntry) throws IOException
    {
        ByteArrayOutputStream os2 = new ByteArrayOutputStream();
        ZipOutputStream oj2 = new ZipOutputStream(os2);
        oj2.setLevel(9);
        oj2.putNextEntry(outEntry);
        oj2.flush();
        os2.flush();

        return os2.size();
    }

    static CountingOutputStream countOutputBytes;
    public static void resignFile(String pem, String pk8, String input, String output, boolean align)
    {
        JarFile inputJar = null;
        JarOutputStream outputJar = null;
        FileOutputStream outputFile = null;

        try
        {
            X509Certificate publicKey = readPublicKey(new File(pem));

            // Assume the certificate is valid for at least an hour.
            long timestamp = publicKey.getNotBefore().getTime() + 3600L * 1000;

            PrivateKey privateKey = readPrivateKey(new File(pk8));
            inputJar = new JarFile(new File(input), false); // Don't
                                                                         // verify.

            OutputStream outputStream = null;
            outputStream = countOutputBytes = new CountingOutputStream( outputFile = new FileOutputStream(output));
            outputJar = new JarOutputStream(outputStream);
            outputJar.setLevel(9);

            JarEntry je;

            // MANIFEST.MF
            Manifest manifest = addDigestsToManifest(inputJar);
            je = new JarEntry(JarFile.MANIFEST_NAME);
            je.setTime(timestamp);
            outputJar.putNextEntry(je);
            manifest.write(outputJar);

            // CERT.SF
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initSign(privateKey);
            je = new JarEntry(CERT_SF_NAME);
            je.setTime(timestamp);
            outputJar.putNextEntry(je);
            writeSignatureFile(manifest, new SignatureOutputStream(outputJar, signature));

            // CERT.RSA
            je = new JarEntry(CERT_RSA_NAME);
            je.setTime(timestamp);
            outputJar.putNextEntry(je);
            writeSignatureBlock(signature, publicKey, outputJar);

            outputJar.closeEntry();

            // Everything else
            copyFiles(manifest, inputJar, outputJar, timestamp, align);

            outputJar.flush();
            outputJar.close();
            outputJar = null;
            outputStream.flush();
            outputStream.close();
            
            System.out.print("...100%");
        }
        catch (Exception e)
        {
            e.printStackTrace();
            System.exit(1);
        }
        finally
        {
            try
            {
                if (inputJar != null)
                    inputJar.close();
                if (outputFile != null)
                    outputFile.close();
            }
            catch (IOException e)
            {
                e.printStackTrace();
                System.exit(1);
            }
        }
    }

    private static void copy(InputStream input, OutputStream output) throws IOException
    {
        int bytesRead;
        while ((bytesRead = input.read(BUFFER)) != -1)
        {
            output.write(BUFFER, 0, bytesRead);
        }
    }

    private static final byte[] BUFFER = new byte[4096 * 1024];
    private static String pubFile;
    private static String pvtFile;

    public static void signStream(InputStream inputJar, OutputStream outputStream, boolean align) throws IOException, GeneralSecurityException
    {
        if (pubFile == null)
        {
            pubFile = "pem.tmp";
            InputStream resourceAsStream = Resign.class.getClassLoader().getResourceAsStream("injection/platform.x509.pem");
            OutputStream fileSream = new FileOutputStream(pubFile);
            copy(resourceAsStream, fileSream);
            fileSream.flush();
            fileSream.close();

            pvtFile = "pk8.tmp";
            resourceAsStream = Resign.class.getClassLoader().getResourceAsStream("injection/platform.pk8");
            fileSream = new FileOutputStream(pvtFile);
            copy(resourceAsStream, fileSream);
            fileSream.flush();
            fileSream.close();
        }

        String inputFile = "original.tmp";
        String outputFile = "resigned.tmp";

        FileOutputStream fileOutputStream = new FileOutputStream(inputFile);

        copy(inputJar, fileOutputStream);

        fileOutputStream.flush();
        fileOutputStream.close();

        resignFile(pubFile, pvtFile, inputFile, outputFile, align );

        FileInputStream input = new FileInputStream(outputFile);
        copy(input, outputStream);
        outputStream.flush();
        input.close();

        new File(inputFile).delete();
        new File(outputFile).delete();
    }

    private static class CountingOutputStream extends FilterOutputStream
    {
        int size = 0;
        public CountingOutputStream(OutputStream out) throws IOException
        {
            super(out);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException
        {
            // TODO Auto-generated method stub
            size += len;
            out.write(b, off, len);
        }
        
        @Override
        public void write(byte[] b) throws IOException
        {
            size += b.length;
            out.write(b);
        }
        
        @Override
        public void write(int b) throws IOException
        {
            size ++;
            super.write(b);
        }
        
        public int getSize()
        {
            return size;
        }
    }
}
