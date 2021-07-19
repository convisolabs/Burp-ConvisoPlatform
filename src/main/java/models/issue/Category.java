package models.issue;

public class Category {
    private int id;
    private String name;
    private int taggings_count;

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

    public int getTaggings_count() {
        return taggings_count;
    }

    public void setTaggings_count(int taggings_count) {
        this.taggings_count = taggings_count;
    }

    @Override
    public String toString() {
        return "Category{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", taggings_count=" + taggings_count +
                '}';
    }
}
