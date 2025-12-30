package models.asset;

import java.io.UnsupportedEncodingException;
import java.util.Objects;

public class Asset {
    private int id;
    private String name;

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void sanitize() {
        if (this.name == null) {
            return;
        }
        try {
            this.name = new String(this.name.getBytes("ISO-8859-1"), "UTF-8").trim();
        } catch (UnsupportedEncodingException ignored) {
        }
    }

    @Override
    public String toString() {
        if (name == null || name.trim().isEmpty()) {
            return String.valueOf(id);
        }
        return id + " - " + name.trim();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Asset asset = (Asset) o;
        return id == asset.id && Objects.equals(name, asset.name);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, name);
    }
}
