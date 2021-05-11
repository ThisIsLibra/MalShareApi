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
 * This class is meant to store the API limits, where both the maximum limit is
 * given, as well as the remaining queries for this day.
 *
 * @author Max 'Libra' Kersten [@Libranalysis, https://maxkersten.nl]
 */
public class MalShareApiLimit {

    /**
     * The API limit for the key that was used in the MalShareApi class
     */
    private int limit;

    /**
     * The remaining API requests for this day for the key that was used in the
     * MalShareApi class
     */
    private int remaining;

    /**
     * This class is meant to store the API limits, where both the maximum limit
     * is given, as well as the remaining queries for this day.
     *
     * @param limit the limit of the API key
     * @param remaining the remaining requests for today
     */
    public MalShareApiLimit(int limit, int remaining) {
        this.limit = limit;
        this.remaining = remaining;
    }

    /**
     * The API limit for the key that was used in the MalShareApi class
     *
     * @return the limit
     */
    public int getLimit() {
        return limit;
    }

    /**
     * The remaining API requests for this day for the key that was used in the
     * MalShareApi class
     *
     * @return the amount of remaining requests
     */
    public int getRemaining() {
        return remaining;
    }
}
