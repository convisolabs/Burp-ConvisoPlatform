package models.analyst;

import java.io.UnsupportedEncodingException;

public class Analyst {
    private Integer id;
    private String email;
    private String name;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void sanitizePortalUser(){
        try {
            this.setName(new String(this.getName().getBytes("ISO-8859-1"), "UTF-8").trim());
        } catch (UnsupportedEncodingException | NullPointerException ignored) {

        }
    }
}
