package utilities;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import com.google.gson.Gson;
import com.google.gson.JsonObject;

import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.charset.StandardCharsets.ISO_8859_1;

public class Util {

    private IBurpExtenderCallbacks callbacks;

    public Util(final IBurpExtenderCallbacks callbacks, final IExtensionHelpers helpers) {
        this.callbacks = callbacks;
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

    public void clearTerminal(){
        for (int i = 0; i < 10; i++) {
            System.out.println("################################################");
        }
    }

    public String getDomainName(String url) throws URISyntaxException {
        URI uri = new URI(url);
        String domain = uri.getHost();
        return domain.startsWith("www.") ? domain.substring(4) : domain;
    }

    public static boolean isColorDark(Color color){
        double darkness = 1-((0.299* color.getRed()) + (0.587*color.getGreen())+ (0.114*color.getBlue()))/255;
        return !(darkness < 0.5);
    }

    public static String prettifyDate(String dateToPrettify){
        String fullDate = dateToPrettify.split("T")[0];
        String[] splittedDate = fullDate.split("-");
        return splittedDate[2] + "-" + splittedDate[1] + "-" + splittedDate[0];
    }

    public static String jsonSafeString(String raw) {
        String escaped = raw;
        escaped = escaped.replace("\\", "\\\\\\\\");
        escaped = escaped.replace("`", "\\`");
        escaped = escaped.replace("\"", "\\\\\\\"");
        escaped = escaped.replace("\b", "\\b");
        escaped = escaped.replace("\f", "\\f");
        escaped = escaped.replace("\n", "\\n");
        escaped = escaped.replace("\r", "\\r");
        escaped = escaped.replace("\t", "\\t");
        return escaped;
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
