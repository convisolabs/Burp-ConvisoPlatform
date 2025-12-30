package models.attachments;

import java.util.Arrays;
import java.util.List;

public class AttachmentArchive {

    private String path;
    private String name;

    public AttachmentArchive() {
    }

    public AttachmentArchive(String path, String name){
        this.path = path;
        this.name = name;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public boolean validateExtension(){
        if(AttachmentFileChooser.acceptedExtensions.contains(this.getName().substring(this.getName().lastIndexOf(".")))){
            return true;
        }else{
            return false;
        }
    }

    @Override
    public String toString() {
        return this.path;
    }
}
