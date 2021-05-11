/*
 * Copyright (C) 2021 Max 'Libra' Kersten [@Libranalysis, https://maxkersten.nl]
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package malshareapi;

import java.util.ArrayList;
import java.util.List;

/**
 * This class is meant to store the details of a sample.
 *
 * @author Max 'Libra' Kersten [@Libranalysis, https://maxkersten.nl]
 */
public class MalShareFileDetails {

    private MalShareHashObject hashObject;
    private String ssDeep;
    private String fileType;
    private List<String> sources;
    private boolean empty;

    public MalShareFileDetails(MalShareHashObject hashObject, String ssDeep, String fileType, List<String> sources) {
        this.hashObject = hashObject;
        this.ssDeep = ssDeep;
        this.fileType = fileType;
        this.sources = sources;
        empty = false;
    }

    public MalShareFileDetails() {
        empty = true;
        hashObject = new MalShareHashObject("", "", "");
        ssDeep = "";
        fileType = "";
        sources = new ArrayList<>();
    }

    public MalShareHashObject getHashObject() {
        return hashObject;
    }

    public String getSsDeep() {
        return ssDeep;
    }

    public String getFileType() {
        return fileType;
    }

    public List<String> getSources() {
        return sources;
    }

    public boolean isEmpty() {
        return empty;
    }

}
