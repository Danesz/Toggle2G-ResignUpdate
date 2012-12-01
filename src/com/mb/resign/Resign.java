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

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import com.mb.gui.ResignRomApplication;

public class Resign
{
    private static final byte[] BUFFER = new byte[4096 * 1024];

    public static PublicKey get(InputStream is) throws Exception
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int bytesRead;
        while ((bytesRead = is.read(BUFFER)) != -1)
        {
            baos.write(BUFFER, 0, bytesRead);
        }

        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        int bufsize = (int) baos.size() + 1024; // Use big-enough buffer
        BufferedInputStream bis = new BufferedInputStream(new ByteArrayInputStream(baos.toByteArray()), bufsize);
        bis.mark(bufsize);
        CertPath cp = cf.generateCertPath(bis, "PKCS7");
        return cp.getCertificates().get(0).getPublicKey();
    }

    private static String getSigned(ZipFile zf, ZipEntry ze) throws IOException
    {
        InputStream fis = zf.getInputStream(ze);
        JarInputStream jarFile = null;
        try
        {
            jarFile = new JarInputStream(fis, false);
            JarEntry jarEntry;
            while ((jarEntry = jarFile.getNextJarEntry()) != null)
            {
                String name = jarEntry.getName().toLowerCase();
                if (name.startsWith("meta-inf/") && name.endsWith(".rsa"))
                {
                    PublicKey publicKey = get(jarFile);
                    return publicKey.toString();
                }
            }

            fis.close();

        }
        catch (Exception e )
        {
            System.out.println("WARNING: Failed Reading Key from: " + ze.getName());
        }
        finally
        {
            if (jarFile != null)
            {
                try
                {
                    jarFile.close();
                }
                catch (IOException e)
                {
                }
            }
        }
        return null;
    }

    private static void copy(InputStream input, OutputStream output) throws IOException
    {
        int bytesRead;
        while ((bytesRead = input.read(BUFFER)) != -1)
        {
            output.write(BUFFER, 0, bytesRead);
        }
    }

    private static void scanUpdate(File file, Set<String> scanForPhoneApk, List<String> forceApks) throws Exception
    {
        boolean injected = false;
        ZipFile jarFile = null;
        ZipOutputStream zipOutputStream = null;
        String outFile = file.getCanonicalPath() + (all ? "-all" : "") + "-Toggle2G-resigned.zip";
        String tempOutFile = "resigned-rom.tmp";
        try
        {
            zipOutputStream = new ZipOutputStream(new FileOutputStream(tempOutFile));
            zipOutputStream.setLevel(9);

            jarFile = new ZipFile(file);
            @SuppressWarnings("unchecked")
            Enumeration<ZipEntry> entries = (Enumeration<ZipEntry>) jarFile.entries();
            while (entries.hasMoreElements())
            {
                ZipEntry zipEntry = entries.nextElement();
                String name = ((ZipEntry) zipEntry).getName();

                if (!injected)
                {
                    injected = true;
                    System.out.print("system/app/Toggle2G.apk");

                    // rip from jar to physical form
                    String tempFile = "resigned.tmp";
                    InputStream resourceAsStream = Resign.class.getClassLoader().getResourceAsStream("injection/Toggle2G.apk");
                    FileOutputStream fileOutputStream = new FileOutputStream(tempFile);
                    copy(resourceAsStream, fileOutputStream);
                    fileOutputStream.flush();
                    fileOutputStream.close();
                    resourceAsStream.close();

                    // Sign into jar
                    zipOutputStream.putNextEntry(new ZipEntry("system/app/Toggle2G.apk"));
                    SignApkHelper.signStream(new FileInputStream(tempFile), zipOutputStream, true);
                    
                    zipOutputStream.closeEntry();
                    System.out.println(": Injected: Signed: ZipAligned");
                }

                // we will be injecting a new version, so skip this.
                if ( name.toLowerCase().contains( "system/app/toggle2g.apk" ) )
                {
                    continue;
                }

                ZipEntry newZipEntry = new ZipEntry(name);
                zipOutputStream.putNextEntry(newZipEntry);
                if (!zipEntry.isDirectory())
                {
                    if (name.toLowerCase().endsWith(".jar") || name.toLowerCase().endsWith(".apk"))
                    {
                        System.out.print(name);
                        if (all || forceApks.contains(name.toLowerCase()) || scanForPhoneApk.contains(getSigned(jarFile, zipEntry)))
                        {
                            InputStream inputJar = jarFile.getInputStream(zipEntry);
                            SignApkHelper.signStream(inputJar, zipOutputStream, true);
                            System.out.println(": Resigned: ZipAligned");
                        }
                        else
                        {
                            copy(jarFile.getInputStream(zipEntry), zipOutputStream);
                            System.out.println(": Skipped");
                            zipOutputStream.closeEntry();
                        }
                    }
                    else
                    {
                        //otherFiles.add( zipEntry);
                        copy(jarFile.getInputStream(zipEntry), zipOutputStream);
                        zipOutputStream.closeEntry();
                    }
                }
            }
        }
        finally
        {
            if (zipOutputStream != null)
            {
                try
                {
                    zipOutputStream.flush();
                    zipOutputStream.close();
                }
                catch (Exception e)
                {
                }
            }
            if (jarFile != null)
            {
                try
                {
                    jarFile.close();
                }
                catch (Exception e)
                {
                }
            }
        }
        
        System.out.println("");
        
        System.out.print("Signing flashable jar " + outFile);
        FileInputStream inputJar = new FileInputStream(tempOutFile);
        FileOutputStream outputStream = new FileOutputStream(outFile);
        SignApkHelper.signStream(inputJar, outputStream, false);
        System.out.println(": Signed");
        
        
        outputStream.flush();
        outputStream.close();
        inputJar.close();
        new File(tempOutFile).delete();

        
        new File("pem.tmp").delete();
        new File("pk8.tmp").delete();
        
        System.out.println("Sucessfully resigned your ROM to: " + outFile);
        System.out.println("");
    }

    private static String scanForApkKey(String search, File file) throws Exception
    {

        ZipFile jarFile = null;
        try
        {
            jarFile = new ZipFile(file);
            @SuppressWarnings("unchecked")
            Enumeration<ZipEntry> entries = (Enumeration<ZipEntry>) jarFile.entries();
            while (entries.hasMoreElements())
            {
                ZipEntry zipEntry = entries.nextElement();
                String name = ((ZipEntry) zipEntry).getName();
                if (name.equalsIgnoreCase(search))
                {
                    return getSigned(jarFile, zipEntry);
                }
            }
            return null;
        }
        finally
        {
            if (jarFile != null)
            {
                try
                {
                    jarFile.close();
                }
                catch (Exception e)
                {
                }
            }
        }
    }

    public static boolean all = false;

    public static void main(String[] args) throws Exception
    {
        int arg = 0;
        String zipFileName = null;
        List<String> keyFromApks = new ArrayList<String>();
        List<String> forceApks = new ArrayList<String>();

        System.out.println("http://forum.xda-developers.com/showthread.php?t=739530");
        System.out.println("Toggle 2G ROM Resigner v3.0.0");

        while (arg < args.length)
        {
            if (args[arg].equals("-all"))
            {
                all = true;
                arg++;
            }
            else if (args[arg].equals("-keyapk"))
            {
                arg++;
                keyFromApks.add(args[arg]);
                arg++;
            }
            else if (args[arg].equals("-forceapk"))
            {
                arg++;
                forceApks.add(args[arg].toLowerCase());
                arg++;
            }
            else if (zipFileName == null)
            {
                zipFileName = args[arg];
                arg++;
            }
            else
            {
                // what is this?
                zipFileName = null;
                break;
            }
        }

        if (zipFileName == null)
        {
            ResignRomApplication.main(new String[]{});
            /*
            System.out.println("Usage: ResignUpdate <romupdate.zip>");
            System.out.println("");
            System.out.println("  options:");
            System.out.println("    -all : Resigns all APK files in the ROM instead of just the ones needed.");
            System.out.println("           This is last resort command when nothing else works!");
            System.out.println("");
            System.out.println("    -keyapk <apkPath> : Path to an apk using the key needing resigning.");
            System.out.println("                        Use when phone.apk or settings.apk can't be found.");
            System.out.println("                        (Can be specified multiple times for multiple apk files)");
            System.out.println("");
            System.out.println("    -forceapk <apkPath> : Resign this apk in addition to detected ones");
            System.out.println("                          (Can be specified multiple times for multiple apk files)");
            */
            return;
        }

        File file = new File(zipFileName);
        if (!file.exists())
        {
            System.out.println("ROM update zip not found: " + args[0]);
            return;
        }

        System.out.println("");
        System.out.println("Processing ROM update zip: " + file.getCanonicalPath());
        Set<String> scanForPhoneApk = new HashSet<String>();
        if (!all)
        {
            System.out.println("Locating apk's to convert....");
            String sa;
            if ((sa = scanForApkKey("system/app/phone.apk", file)) != null)
            {
                System.out.println("Found Key for system/app/phone.apk");
                scanForPhoneApk.add(sa);
            }
            else if ((sa = scanForApkKey("system/app/settings.apk", file)) != null)
            {
                System.out.println("Found Key for system/app/settings.apk");
                scanForPhoneApk.add(sa);
            }
            else if ((sa = scanForApkKey("system/app/SecPhone.apk", file)) != null)
            {
                System.out.println("Found Key for system/app/SecPhone.apk");
                scanForPhoneApk.add(sa);
            }
            else if ((sa = scanForApkKey("system/app/SecSettings.apk", file)) != null)
            {
                System.out.println("Found Key for system/app/SecSettings.apk");
                scanForPhoneApk.add(sa);
            }
            else
            {
                System.out.println("WARNING: no default APK found for auto keying");
                System.out.println("         not found system/app/phone.apk");
                System.out.println("         not found system/app/settings.apk");
                System.out.println("         not found system/app/SecPhone.apk");
                System.out.println("         not found system/app/SecSettings.apk");
                System.out.println("         If you know where one of these files are in the ROM's zip file");
                System.out.println("         then put the correct path/file.apk in the -keyapk parameter.");
            }

            for (String apk : keyFromApks)
            {
                sa = scanForApkKey(apk, file);
                if (sa != null)
                {
                    System.out.println("Found Key in: " + apk);
                    scanForPhoneApk.add(sa);
                }
            }

            if (scanForPhoneApk.size() == 0)
            {
                throw new RuntimeException("Failed to find any apk with a key");
            }

            System.out.println(scanForPhoneApk);
        }
        System.out.println("");
        System.out.println("Resigning all apk/jar/zip files that share these key(s)");
        scanUpdate(file, scanForPhoneApk, forceApks);
        System.out.println("");
        System.out.println("If this is your first time resigning a ROM,");
        System.out.println("    it's likely you will need to do a Factory Reset.");
        System.out.println("");
        System.out.println("If resigning an update to your already resigned ROM,");
        System.out.println("    no wipe should be needed.");
        System.out.println("");
        System.out.println("PLEASE DONATE!");
        System.out.println("http://forum.xda-developers.com/showthread.php?t=739530");

    }
}
