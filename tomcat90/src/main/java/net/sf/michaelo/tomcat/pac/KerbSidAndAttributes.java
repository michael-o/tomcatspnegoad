/*
 * Copyright 2024 Michael Osipov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.sf.michaelo.tomcat.pac;

import net.sf.michaelo.tomcat.realm.Sid;

/**
 * A class representing the <a href=
 * "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/311aab27-ebdf-47f7-b939-13dc99b15341">{@code KERB_SID_AND_ATTRIBUTES}</a>
 * structure from MS-PAC.
 */
public class KerbSidAndAttributes {

	private final Sid sid;
	private final long attributes;

	public KerbSidAndAttributes(Sid sid, long attributes) {
		this.sid = sid;
		this.attributes = attributes;
	}

	public Sid getSid() {
		return sid;
	}

	public long getAttributes() {
		return attributes;
	}

	@Override
	public String toString() {
		return String.format("KerbSidAndAttributes[sid=%s, attributes=0x%08X]", sid, attributes);
	}

}
