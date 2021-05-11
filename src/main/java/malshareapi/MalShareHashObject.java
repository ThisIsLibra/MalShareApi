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

/**
 * This class is meant to store three hashes, all corresponding to the same
 * sample. The three hash types are MD-5, SHA-1, and SHA-256.
 *
 * @author Max 'Libra' Kersten [@Libranalysis, https://maxkersten.nl]
 */
public class MalShareHashObject {

    /**
     * The MD-5 hash
     */
    private String md5;

    /**
     * The SHA-1 hash
     */
    private String sha1;

    /**
     * The SHA-256 hash
     */
    private String sha256;

    /**
     * This class is meant to store three hashes, all corresponding to the same
     * sample. The three hash types are MD-5, SHA-1, and SHA-256.
     *
     * @param md5 the MD-5 hash of the sample
     * @param sha1 the SHA-1 hash of the sample
     * @param sha256 the SHA-256 hash of the sample
     */
    public MalShareHashObject(String md5, String sha1, String sha256) {
        this.md5 = md5;
        this.sha1 = sha1;
        this.sha256 = sha256;
    }

    /**
     * Gets the MD-5 hash of the given sample
     *
     * @return the MD-5 hash
     */
    public String getMd5() {
        return md5;
    }

    /**
     * Gets the SHA-1 hash of the given sample
     *
     * @return the SHA-1 hash
     */
    public String getSha1() {
        return sha1;
    }

    /**
     * Gets the SHA-256 hash of the given sample
     *
     * @return the SHA-256 hash
     */
    public String getSha256() {
        return sha256;
    }
}
