package models.auto_filter_combobox;

import models.asset.Asset;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

public class AutoFilterAssetsComboboxModel extends DefaultComboBoxModel {

    private List<Asset> assetsList;

    public AutoFilterAssetsComboboxModel() {
        this.assetsList = new ArrayList<>();
    }

    public void setAssetsList(List<Asset> assetsList) {
        this.assetsList = assetsList;
        this.removeAllElements();
        if (!assetsList.isEmpty()) {
            this.addAll(assetsList);
        }
    }

    public synchronized void filterList(String pattern, boolean setSoloElement) {
        List<Asset> filteredList = new ArrayList<>();

        if (pattern != null && !pattern.isEmpty()) {
            String loweredPattern = pattern.toLowerCase();
            for (Asset asset : assetsList) {
                String label = asset.toString();
                if (label.toLowerCase().contains(loweredPattern)) {
                    filteredList.add(asset);
                }
            }
            this.removeAllElements();
            this.addAll(filteredList);
            if (filteredList.size() == 1 && setSoloElement) {
                this.setSelectedItem(filteredList.get(0));
            }
        } else {
            this.removeAllElements();
            this.addAll(assetsList);
        }
    }
}
