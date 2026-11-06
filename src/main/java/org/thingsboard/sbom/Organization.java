// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import java.util.ArrayList;
import java.util.List;

public class Organization {

    private String name;
    private List<String> urls = new ArrayList<>();
    private List<Contact> contacts = new ArrayList<>();

    public Organization() {
    }

    public Organization(String name, List<String> urls, List<Contact> contacts) {
        this.name = name;
        this.urls = urls;
        this.contacts = contacts;
    }

    public String getName() {
        return name;
    }

    public List<String> getUrls() {
        return urls == null ? List.of() : urls;
    }

    public List<Contact> getContacts() {
        return contacts == null ? List.of() : contacts;
    }

}
