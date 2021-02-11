package utilities;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;

import java.io.PrintWriter;
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

    public Util() {
    }

    public void sendStdout(String toSend){
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println("[+] "+toSend);
    }

    public void sendStderr(String toSend){
        PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
        stderr.println("[-] "+toSend);
    }

    public String stringToOtherCharset(String toChange){
        byte[] ptext = toChange.getBytes(ISO_8859_1);
        return new String(ptext, UTF_8);
    }

    public static String removeCaracteresEspeciais(String str) {
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

}
