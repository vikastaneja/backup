/* *******************************************************************
 * Copyright (c) 1999-2001 Xerox Corporation, 
 *               2002 Palo Alto Research Center, Incorporated (PARC).
 * All rights reserved. 
 * This program and the accompanying materials are made available 
 * under the terms of the Eclipse Public License v1.0 
 * which accompanies this distribution and is available at 
 * http://www.eclipse.org/legal/epl-v10.html 
 *  
 * Contributors: 
 *     Xerox/PARC     initial implementation 
 * ******************************************************************/

package identity.util.httplibrary;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.Writer;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * @author Andy Clement
 * @author Kris De Volder
 */
public class FileUtil {
    /** default parent directory File when a file has a null parent */

    /**
     * Returns the contents of this file as a byte[]
     */
    public static byte[] readAsByteArray(File file) throws IOException {
        FileInputStream in = new FileInputStream(file);
        byte[] ret = FileUtil.readAsByteArray(in);
        in.close();
        return ret;
    }

    /**
     * Reads this input stream and returns contents as a byte[]
     */
    public static byte[] readAsByteArray(InputStream inStream) throws IOException {
        int size = 1024;
        byte[] ba = new byte[size];
        int readSoFar = 0;

        while (true) {
            int nRead = inStream.read(ba, readSoFar, size - readSoFar);
            if (nRead == -1) {
                break;
            }
            readSoFar += nRead;
            if (readSoFar == size) {
                int newSize = size * 2;
                byte[] newBa = new byte[newSize];
                System.arraycopy(ba, 0, newBa, 0, size);
                ba = newBa;
                size = newSize;
            }
        }

        byte[] newBa = new byte[readSoFar];
        System.arraycopy(ba, 0, newBa, 0, readSoFar);
        return newBa;
    }

}
