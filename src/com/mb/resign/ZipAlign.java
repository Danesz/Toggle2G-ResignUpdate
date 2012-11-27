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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

public class ZipAlign
{
    static int num;
    static byte[] buffer = new byte[1024 * 5];
    static File signedFile = new File( "C:/Development/Android/Workspace/Toggle2G/apk/Toggle2G.apk" );
    static File unsignedFile = new File( "C:/Development/Android/Workspace/Toggle2G/apk/Toggle2G.apk-signed-pza.apk" );
    static File newfile = new File("C:/Development/Android/Workspace/Toggle2G/apk/Toggle2G.za.apk");

    public static void main(String[] args) throws Exception
    {

        int size = 0;
        //OutputStream outputStream = new ByteArrayOutputStream();
        OutputStream outputStream = new FileOutputStream(newfile);
        ZipOutputStream outputJar = new ZipOutputStream(outputStream);
        outputJar.setLevel(9);

        ZipFile inputJar = new ZipFile(unsignedFile);

        Enumeration<? extends ZipEntry> entries = inputJar.entries();
        while (entries.hasMoreElements())
        {
            ZipEntry inEntry = entries.nextElement();

            ZipEntry outEntry = null;
            if (inEntry.getMethod() == ZipEntry.STORED)
            {
                // Preserve the STORED method of the input entry.
                outEntry = new ZipEntry(inEntry);
            }
            else
            {
                // Create a new entry so that the compressed len is recomputed.
                outEntry = new ZipEntry(inEntry.getName());
            }

            outEntry.setTime(inEntry.getTime());
            
            int thisSize = getHeaderSize(outEntry);
            if (inEntry.getMethod() == ZipEntry.STORED)
            {
                int align = ( thisSize + size ) % 4;
                if ( align > 0 )
                {
                    // align the data
                    System.out.println("Aligning data for " + inEntry.getName() + " by " + align + " bytes");
                    outEntry.setExtra(new byte[align]);
                }
            }
            size += getHeaderSize(outEntry);
            
            outputJar.putNextEntry(outEntry);
            
            if ( !outEntry.isDirectory() )
            {
                InputStream data = inputJar.getInputStream(inEntry);
                while ((num = data.read(buffer)) > 0)
                {
                    outputJar.write(buffer, 0, num);
                    size += num;
                }
            }
            outputJar.flush();

            //System.out.println(inEntry.getName() + " = " + outputStream.size());
            //System.out.println(inEntry.getSize());
        }
        
//        FileOutputStream fos = new FileOutputStream(newfile);
//        InputStream data = new ByteArrayInputStream(outputStream.toByteArray());
//        while ((num = data.read(buffer)) > 0)
//        {
//            fos.write(buffer, 0, num);
//        }
//        fos.flush();
//        fos.close();
        
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

    public static void grep(File file, byte[] data) throws IOException
    {
        int index = 0;
        Reader in = new FileReader(file);
        // there should be a method something like this in there.
        // I don't have specs with me
        int place = 0;
        byte c;
        while (in.ready())
        {
            c = (byte) in.read();
            index ++;
            if (c == data[place])
            {
                place++;
                if (place == data.length)
                {
                    System.out.println("Found it at " + index);
                    in.close();
                    return;
                }
            }
            else place = 0;
        }
        in.close();
        System.out.println("Didn't find it.");
    }
}
