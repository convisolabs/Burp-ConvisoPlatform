package models.evidences;

import java.util.Arrays;
import java.util.List;

public class EvidenceArchive {

    private String path;
    private String name;

    public EvidenceArchive() {
    }

    public EvidenceArchive(String path, String name){
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
        if(EvidenceFileChooser.acceptedExtensions.contains(this.getName().substring(this.getName().lastIndexOf(".")))){
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
