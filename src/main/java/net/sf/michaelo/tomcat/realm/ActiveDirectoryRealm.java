package net.sf.michaelo.tomcat.realm;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import javax.naming.CompositeName;
import javax.naming.InvalidNameException;
import javax.naming.Name;
import javax.naming.NameParser;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.security.auth.kerberos.KerberosPrincipal;

import net.sf.michaelo.dirctxsrc.DirContextSource;
import net.sf.michaelo.tomcat.realm.mapper.SamAccountNameRfc2247Mapper;
import net.sf.michaelo.tomcat.realm.mapper.UserPrincipalNameSearchMapper;
import net.sf.michaelo.tomcat.realm.mapper.UsernameSearchMapper;
import net.sf.michaelo.tomcat.realm.mapper.UsernameSearchMapper.MappedValues;
import net.sf.michaelo.tomcat.utils.LdapUtils;

import org.apache.catalina.util.HexUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.ietf.jgss.GSSCredential;

/**
 * A Realm which offers access to the Active Directory.
 * <p>
 * <li>{@code strippableRoleNamePrefixes}: Role name prefixes which can be stripped during retrieval
 * (optional). Separate prefixes with comma.</li>
 * <li>{@code useDelegatedCredential}: Use client's/initiator's credential instead of server's to
 * authenticate against Active Directory (optional). Make sure that the user principal is an
 * instance of {@link ActiveDirectoryPrincipal}. Valid values are {@code true}, {@code false}.
 * Default value is {@code false}.</li>
 * </ul>
 * </p>
 * <p>
 * <b>Authentication chaining</b>: If you set both {@code useDelegatedCredential} <i>and</i>
 * {@code loginEntryName}, the realm will try the delegated credential first and if none is supplied
 * the login entry will be used as fallback.
 * </p>
 */
public class ActiveDirectoryRealm extends GssApiAwareRealm<DirContextSource> {

	private static final UsernameSearchMapper[] USERNAME_SEARCH_MAPPERS = {
			new SamAccountNameRfc2247Mapper(), new UserPrincipalNameSearchMapper() };

	private static final Log logger = LogFactory.getLog(ActiveDirectoryRealm.class);

	private String[] strippableRoleNamePrefixes;

	@Override
	public String getInfo() {
		return "net.sf.michaelo.realm.ActiveDirectoryRealm/0.9";
	}

	@Override
	protected String getName() {
		return "ActiveDirectoryRealm";
	}

	public void setDirContextSourceName(String dirContextSourceName) {
		setResourceName(dirContextSourceName);
	}

	public void setLocalDirContextSource(boolean localDirContextSource) {
		setLocalResource(localDirContextSource);
	}

	/**
	 * Retrieves the roles for a specific user from Active Directory. The roles will be stripped by
	 * the CN by default.
	 *
	 * @param user
	 *            the user for role retrievement
	 * @return roles list for the given pricipal
	 */
	protected List<String> getRoles(User user) throws NamingException {

		List<String> roles = new LinkedList<String>();

		if (logger.isTraceEnabled())
			logger.trace(String.format("Retrieving roles for username '%s' with DN '%s'",
					user.getUsername(), user.getDn()));

		for (String role : user.getRoles()) {
			role = StringUtils.substringBetween(role, "CN=", ",");
			if (strippableRoleNamePrefixes != null) {
				for (String prefix : strippableRoleNamePrefixes) {
					if (role.startsWith(prefix))
						roles.add(StringUtils.substringAfter(role, prefix));
					else
						roles.add(role);
				}
			}
		}

		if (logger.isDebugEnabled())
			logger.debug(String.format("Found %s roles for username '%s'", roles.size(),
					user.getUsername()));
		if (logger.isTraceEnabled())
			logger.debug(String.format("Found following roles %s for username '%s'", roles,
					user.getUsername()));

		return roles;
	}

	@Override
	public boolean hasRole(Principal principal, String role) {

		if (principal == null || role == null || !(principal instanceof ActiveDirectoryPrincipal))
			return false;

		ActiveDirectoryPrincipal adp = (ActiveDirectoryPrincipal) principal;
		boolean result = adp.hasRole(role);

		if (logger.isDebugEnabled()) {
			String name = principal.getName();
			if (result)
				logger.debug(String.format("Principal '%s' does not have role '%s'", name, role));
			else
				logger.debug(String.format("Principal '%s' has role '%s'", name, role));
		}

		return result;
	}

	/**
	 * Sets the role name prefixed which can be stripped during retrieval.
	 * 
	 * @param prefixes
	 *            the strippable role name prefixes
	 */
	public void setStrippableRoleNamePrefixes(String prefixes) {
		this.strippableRoleNamePrefixes = StringUtils.split(prefixes, ",");
	}

	/**
	 * 
	 * @param username
	 * @param gssCredential
	 * @return the retrieved principal
	 * @throws RuntimeException
	 *             wraps NamingException
	 */
	@Override
	protected Principal getPrincipal(String username, GSSCredential gssCredential) {

		DirContextSource dirContextSource = null;
		try {
			dirContextSource = (DirContextSource) lookupResource();
		} catch (NamingException e) {
			logger.error(String.format(
					"Could not retrieve the DirContextSource '%s' from JNDI context", resourceName));
			throw new RuntimeException(String.format("Failed to retrieve resource '%s'",
					resourceName), e);
		}

		DirContext context = null;
		try {
			context = dirContextSource.getDirContext();
		} catch (NamingException e) {
			logger.error(String.format("Could not retrieve DirContext from DirContextSource '%s'",
					resourceName), e);
			throw new RuntimeException(e);
		}

		Principal principal = null;
		try {
			principal = getPrincipal(context, username, gssCredential);
		} catch (NamingException e) {
			logger.error(
					String.format("Unable to perform principal search for username '%s'", username), e);
			throw new RuntimeException(e);
		} finally {
			LdapUtils.close(context);
		}

		return principal;
	}

	protected synchronized Principal getPrincipal(DirContext context, String username,
			GSSCredential gssCredential) throws NamingException {

		User user = getUser(context, username);

		List<String> roles = null;
		if (user != null)
			roles = getRoles(user);

		if (user != null) {
			KerberosPrincipal krbPrincipal = new KerberosPrincipal(user.getUsername());
			return new ActiveDirectoryPrincipal(krbPrincipal, user.getDn(), user.getSid(),
					gssCredential, roles);
		}

		return null;
	}

	protected User getUser(DirContext context, String username) throws NamingException {

		SearchControls searchCtls = new SearchControls();
		searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		searchCtls.setReturningAttributes(new String[] { "memberOf", "objectSid;binary" });
		String searchFilterPattern = "(&(objectClass=user)(%s={0})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";

		String searchFilter;
		String searchBase = null;
		String searchAttributeName;
		String searchAttributeValue;

		MappedValues mappedValues;
		NamingEnumeration<SearchResult> results = null;
		for (UsernameSearchMapper mapper : USERNAME_SEARCH_MAPPERS) {
			mappedValues = mapper.map(context, username);

			searchBase = getRelativeName(context, mappedValues.getSearchBase());
			searchAttributeName = mappedValues.getSearchAttributeName();
			searchAttributeValue = mappedValues.getSearchUsername();

			searchFilter = String.format(searchFilterPattern, searchAttributeName);
			results = context.search(searchBase, searchFilter,
					new Object[] { searchAttributeValue }, searchCtls);

			if (results == null || !results.hasMore()) {

				if (logger.isDebugEnabled()) {
					String shortClassName = StringUtils.substringAfterLast(mapper.getClass()
							.getName(), ".");
					logger.debug(String
							.format("Username '%s' in search base '%s' and search attribute '%s' with mapper '%s' not found, trying fallback",
									searchAttributeValue, searchBase, searchAttributeName,
									shortClassName));
				}

				LdapUtils.close(results);
			} else
				break;
		}

		if (results == null || !results.hasMore()) {
			logger.info(String.format("Username '%s' not found", username));
			return null;
		}

		SearchResult result = results.next();

		if (results.hasMore()) {
			logger.warn(String.format("Username '%s' has multiple entries", username));
			return null;
		}

		String dn = getDistinguishedName(context, searchBase, result);

		if (logger.isDebugEnabled())
			logger.debug(String.format("Entry found for username '%s' with DN '%s'", username, dn));

		byte[] sid = (byte[]) result.getAttributes().get("objectSid;binary").get();

		if (logger.isDebugEnabled()) {
			logger.debug(String.format("Found sid '%s' for username '%s'", HexUtils.convert(sid),
					username));
		}

		Attribute memberOfAttr = result.getAttributes().get("memberOf");
		NamingEnumeration<?> memberOfValues = memberOfAttr.getAll();

		List<String> roles = new LinkedList<String>();

		while (memberOfValues.hasMoreElements())
			roles.add((String) memberOfValues.nextElement());

		LdapUtils.close(memberOfValues);

		return new User(username, dn, sid, roles);
	}

	/**
	 * Returns the distinguished name of a search result.
	 * 
	 * @param context
	 *            Our DirContext
	 * @param base
	 *            The base DN
	 * @param result
	 *            The search result
	 * @return String containing the distinguished name
	 */
	protected String getDistinguishedName(DirContext context, String base, SearchResult result)
			throws NamingException {
		// Get the entry's distinguished name. For relative results, this means
		// we need to composite a name with the base name, the context name, and
		// the result name. For non-relative names, use the returned name.
		if (result.isRelative()) {
			if (logger.isTraceEnabled()) {
				logger.trace(String.format("Search returned relative name '%s'", result.getName()));
			}
			NameParser parser = context.getNameParser(StringUtils.EMPTY);
			Name contextName = parser.parse(context.getNameInNamespace());
			Name baseName = parser.parse(base);

			// Bugzilla 32269
			Name entryName = parser.parse(new CompositeName(result.getName()).get(0));

			Name name = contextName.addAll(baseName);
			name = name.addAll(entryName);
			return name.toString();
		} else {
			String absoluteName = result.getName();
			if (logger.isTraceEnabled())
				logger.trace(String.format("Search returned absolute name '%s'", result.getName()));
			try {
				// Normalize the name by running it through the name parser.
				NameParser parser = context.getNameParser(StringUtils.EMPTY);
				URI userNameUri = new URI(absoluteName);
				String pathComponent = userNameUri.getPath();
				// Should not ever have an empty path component, since that is
				// /{DN}
				if (pathComponent.length() < 1) {
					throw new InvalidNameException(String.format(
							"Search returned unparseable absolute name '%s'", absoluteName));
				}
				Name name = parser.parse(pathComponent.substring(1));
				return name.toString();
			} catch (URISyntaxException e) {
				throw new InvalidNameException(String.format(
						"Search returned unparseable absolute name '%s'", absoluteName));
			}
		}
	}

	protected String getRelativeName(DirContext context, String distinguishedName)
			throws NamingException {

		NameParser parser = context.getNameParser(StringUtils.EMPTY);
		Name nameInNamespace = parser.parse(context.getNameInNamespace());
		Name name = parser.parse(distinguishedName);

		String nameRdn;
		String nameInNamespaceRdn;

		while (Math.min(name.size(), nameInNamespace.size()) != 0) {
			nameRdn = name.get(0);
			nameInNamespaceRdn = nameInNamespace.get(0);
			if (nameRdn.equals(nameInNamespaceRdn)) {
				name.remove(0);
				nameInNamespace.remove(0);
			} else
				break;
		}

		int innerPosn;
		while (Math.min(name.size(), nameInNamespace.size()) != 0) {
			innerPosn = nameInNamespace.size() - 1;
			nameRdn = name.get(0);
			nameInNamespaceRdn = nameInNamespace.get(innerPosn);
			if (nameRdn.equals(nameInNamespaceRdn)) {
				name.remove(0);
				nameInNamespace.remove(innerPosn);
			} else
				break;
		}

		return name.toString();

	}

	protected static class User {
		private final String username;
		private final String dn;
		private final byte[] sid;
		private final List<String> roles;

		public User(String username, String dn, byte[] sid, List<String> roles) {
			this.username = username;
			this.dn = dn;
			this.sid = ArrayUtils.clone(sid);

			if (roles == null || roles.isEmpty())
				this.roles = Collections.emptyList();
			else
				this.roles = Collections.unmodifiableList(roles);
		}

		public String getUsername() {
			return username;
		}

		public String getDn() {
			return dn;
		}

		public List<String> getRoles() {
			return roles;
		}

		public byte[] getSid() {
			return ArrayUtils.clone(sid);
		}

	}

}
