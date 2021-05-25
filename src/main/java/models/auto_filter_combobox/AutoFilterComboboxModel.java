package models.auto_filter_combobox;

import models.vulnerability.Template;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

public class AutoFilterComboboxModel extends DefaultComboBoxModel {

    private List<Template> templatesList;

    public AutoFilterComboboxModel() {
        this.templatesList = new ArrayList<>();
    }

    public void setTemplatesList(List<Template> templatesList) {
        if(!templatesList.isEmpty()){
            this.templatesList = templatesList;
            this.addAll(templatesList);
        }
    }

    public synchronized void filterList(String pattern, boolean setSoloElement){
        List<Template> filteredList = new ArrayList<>();

        if(pattern != null && !pattern.isEmpty()){
            for (Template t :
                    templatesList) {
                if (t.getTitle().toLowerCase().contains(pattern.toLowerCase())){
                    filteredList.add(t);
                }
            }
            this.removeAllElements();
            this.addAll(filteredList);
            if(filteredList.size() == 1 && setSoloElement){
                this.setSelectedItem(filteredList.get(0));
            }
        }else {
            this.removeAllElements();
            this.addAll(templatesList);
        }
    }





}
