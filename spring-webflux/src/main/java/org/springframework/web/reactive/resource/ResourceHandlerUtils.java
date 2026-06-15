/*
 * Copyright 2002-2026 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.web.reactive.resource;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogFormatUtils;
import org.springframework.util.ResourceUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriUtils;

/**
 * Resource handling utility methods, back-ported from Spring Framework 6.2.x
 * to support the CVE-2026-41842 / CVE-2026-41843 fixes. Only the input-path
 * validation logic used by {@link VersionResourceResolver} is included.
 *
 * @author Rossen Stoyanchev
 * @since 5.3.49
 */
public abstract class ResourceHandlerUtils {

	private static final Log logger = LogFactory.getLog(ResourceHandlerUtils.class);


	/**
	 * Whether the given input path should be ignored because it is empty, an
	 * invalid path, or an invalid encoded path.
	 */
	public static boolean shouldIgnoreInputPath(String path) {
		return (!StringUtils.hasText(path) || isInvalidPath(path) || isInvalidEncodedPath(path));
	}

	/**
	 * Whether the given path contains invalid escape sequences.
	 */
	public static boolean isInvalidPath(String path) {
		String pathLowerCase = path.toLowerCase(Locale.ROOT);
		if (pathLowerCase.contains("web-inf") || pathLowerCase.contains("meta-inf")) {
			if (logger.isWarnEnabled()) {
				logger.warn(LogFormatUtils.formatValue(
						"Path with \"WEB-INF\" or \"META-INF\": [" + path + "]", -1, true));
			}
			return true;
		}
		if (path.contains(":/")) {
			String relativePath = (path.charAt(0) == '/' ? path.substring(1) : path);
			if (ResourceUtils.isUrl(relativePath) || relativePath.startsWith("url:")) {
				if (logger.isWarnEnabled()) {
					logger.warn(LogFormatUtils.formatValue(
							"Path represents URL or has \"url:\" prefix: [" + path + "]", -1, true));
				}
				return true;
			}
		}
		if (path.contains("../")) {
			if (logger.isWarnEnabled()) {
				logger.warn(LogFormatUtils.formatValue(
						"Path contains \"../\" after call to StringUtils#cleanPath: [" + path + "]", -1, true));
			}
			return true;
		}
		return false;
	}

	private static boolean isInvalidEncodedPath(String path) {
		String decodedPath = decode(path);
		if (decodedPath.contains("%")) {
			decodedPath = decode(decodedPath);
		}
		if (!StringUtils.hasText(decodedPath)) {
			return true;
		}
		if (isInvalidPath(decodedPath)) {
			return true;
		}
		decodedPath = normalizeInputPath(decodedPath);
		return isInvalidPath(decodedPath);
	}

	/**
	 * Normalize the given input path: replace any backslashes with forward
	 * slashes, collapse duplicate slashes, and strip a leading slash.
	 */
	public static String normalizeInputPath(String path) {
		path = StringUtils.replace(path, "\\", "/");
		path = cleanDuplicateSlashes(path);
		return cleanLeadingSlash(path);
	}

	private static String decode(String path) {
		try {
			return UriUtils.decode(path, StandardCharsets.UTF_8);
		}
		catch (Exception ex) {
			return "";
		}
	}

	private static String cleanDuplicateSlashes(String path) {
		StringBuilder sb = null;
		char prev = 0;
		for (int i = 0; i < path.length(); i++) {
			char curr = path.charAt(i);
			try {
				if ((curr == '/') && (prev == '/')) {
					if (sb == null) {
						sb = new StringBuilder(path.substring(0, i));
					}
					continue;
				}
				if (sb != null) {
					sb.append(path.charAt(i));
				}
			}
			finally {
				prev = curr;
			}
		}
		return (sb != null ? sb.toString() : path);
	}

	private static String cleanLeadingSlash(String path) {
		boolean slash = false;
		for (int i = 0; i < path.length(); i++) {
			if (path.charAt(i) == '/') {
				slash = true;
			}
			else if (path.charAt(i) > ' ' && path.charAt(i) != 127) {
				if (i == 0 || (i == 1 && slash)) {
					return path;
				}
				return (slash ? "/" + path.substring(i) : path.substring(i));
			}
		}
		return (slash ? "/" : "");
	}

}
