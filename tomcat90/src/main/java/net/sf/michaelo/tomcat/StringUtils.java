/*
 * Copyright 2026 Michael Osipov
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
package net.sf.michaelo.tomcat;

import java.util.regex.Pattern;

public class StringUtils {

	public static final String EMPTY = "";

	private static final String[] EMPTY_STRING_ARRRAY = new String[0];

	public static boolean isEmpty(String str) {
		return str == null || str.isEmpty();
	}

	public static boolean isNotEmpty(String str) {
		return !(str == null || str.isEmpty());
	}

	public static boolean startsWithIgnoreCase(String str, String prefix) {
		return str != null && prefix != null && str.regionMatches(true, 0, prefix, 0, prefix.length());
	}

	public static String substring(String str, int start) {
		if (str == null) return null;

		if (start < 0) start = Math.max(str.length() + start, 0);

		if (start > str.length()) return EMPTY;

		return str.substring(start);
	}

	public static String[] split(String str, String separatorChars) {
		if (str == null) return null;

		if (str.isEmpty()) return EMPTY_STRING_ARRRAY;

		return str.split(Pattern.quote(separatorChars));
	}
}
