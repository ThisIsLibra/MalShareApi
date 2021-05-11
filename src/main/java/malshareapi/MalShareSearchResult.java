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

import java.time.LocalDateTime;
import java.util.List;

/**
 * This class is meant to store a single search result of the search query.
 *
 * @author Max 'Libra' Kersten [@Libranalysis, https://maxkersten.nl]
 */
public class MalShareSearchResult {

    private MalShareHashObject hashObject;
    private String type;
    private LocalDateTime dateTime;
    private String source;
    private String yarahits;
    private List<String> parentFiles;
    private List<String> subFiles;

    public MalShareSearchResult(MalShareHashObject hashObject, String type, LocalDateTime dateTime, String source, String yarahits, List<String> parentFiles, List<String> subFiles) {
        this.hashObject = hashObject;
        this.type = type;
        this.dateTime = dateTime;
        this.source = source;
        this.yarahits = yarahits;
        this.parentFiles = parentFiles;
        this.subFiles = subFiles;
    }

    public MalShareHashObject getHashObject() {
        return hashObject;
    }

    public String getType() {
        return type;
    }

    public LocalDateTime getDateTime() {
        return dateTime;
    }

    public String getSource() {
        return source;
    }

    public String getYarahits() {
        return yarahits;
    }

    public List<String> getParentFiles() {
        return parentFiles;
    }

    public List<String> getSubFiles() {
        return subFiles;
    }

}
