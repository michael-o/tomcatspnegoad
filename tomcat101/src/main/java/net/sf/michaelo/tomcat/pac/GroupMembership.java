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

/**
 * A class representing the <a href=
 * "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/40526584-1565-4fb1-97b7-eb38fd880595">{@code GROUP_MEMBERSHIP}</a>
 * structure from MS-PAC.
 */
public class GroupMembership {

	private final long relativeId;
	private final long attributes;

	public GroupMembership(long relativeId, long attributes) {
		this.relativeId = relativeId;
		this.attributes = attributes;
	}

	public long getRelativeId() {
		return relativeId;
	}

	public long getAttributes() {
		return attributes;
	}

	@Override
	public String toString() {
		return String.format("GroupMembership[relativeId=%d, attributes=0x%08X]", relativeId, attributes);
	}

}
