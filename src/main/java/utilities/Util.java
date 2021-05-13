package utilities;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.charset.StandardCharsets.ISO_8859_1;

public class Util {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    public Util(final IBurpExtenderCallbacks callbacks, final IExtensionHelpers helpers) {
        this.callbacks = callbacks;
        this.helpers = helpers;
    }

    public Util(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    public Util() {
    }

    public void sendStdout(String toSend){
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println("[+] "+toSend);
        stdout.close();
    }

    public void sendStderr(String toSend){
        PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
        stderr.println("[-] "+toSend);
        stderr.close();
    }

    public String stringToOtherCharset(String toChange){
        byte[] ptext = toChange.getBytes(ISO_8859_1);
        return new String(ptext, UTF_8);
    }

    public static String removeSpecialCharacters(String str) {
        return str.replace('Á', 'A').replace('À', 'A').replace('Â', 'A').replace('Ä', 'A').replace('Ã', 'A').replace('É', 'E')
                .replace('È', 'E').replace('Ê', 'E').replace('Ë', 'A').replace('Í', 'I').replace('Ì', 'I').replace('Î', 'I')
                .replace('Ï', 'I').replace('Ó', 'O').replace('Ò', 'O').replace('Ô', 'O').replace('Ö', 'O').replace('Õ', 'O')
                .replace('Ú', 'U').replace('Ù', 'U').replace('Û', 'U').replace('Ü', 'U').replace('Ç', 'C').replace('á', 'a')
                .replace('à', 'a').replace('â', 'a').replace('ä', 'a').replace('ã', 'a').replace('é', 'e').replace('è', 'e')
                .replace('ê', 'e').replace('ë', 'e').replace('í', 'i').replace('ì', 'i').replace('î', 'i').replace('ï', 'i')
                .replace('ó', 'o').replace('ò', 'o').replace('ô', 'o').replace('ö', 'o').replace('õ', 'o').replace('ú', 'u')
                .replace('ù', 'u').replace('û', 'u').replace('ü', 'u').replace('ç', 'c');
    }


    public String difference(String str1, String str2) {
        int index = str1.lastIndexOf(str2);
        if (index > -1) {
            return str1.substring(str2.length());
        }
        return str1;
    }


    public File createTempFile(String archiveName, String content){
        try {
            File tempFile = File.createTempFile(archiveName, ".txt");
            Files.writeString(Path.of(tempFile.getAbsolutePath()), content);
            tempFile.deleteOnExit();
            return tempFile;
        } catch (IOException exception) {
            new Util(this.callbacks).sendStderr(exception.toString());
            return null;
        }
    }

}
