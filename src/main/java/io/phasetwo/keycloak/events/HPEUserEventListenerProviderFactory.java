package io.phasetwo.keycloak.events;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import java.util.List;
import java.util.ArrayList;
import java.util.Base64;
import com.google.auto.service.AutoService;

import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.events.EventListenerProviderFactory;
import io.phasetwo.keycloak.model.SCIMUser;

@JBossLog
@AutoService(EventListenerProviderFactory.class)
public class HPEUserEventListenerProviderFactory extends UserEventListenerProviderFactory {

  public static final String PROVIDER_ID = "ext-event-myuseraddremove";
  public static final String SCHEMA_CORE_USER = "urn:ietf:params:scim:schemas:core:2.0:User";
  private static final String SCIM_URL_ENV = "SCIM_URL";
  private static final String SCIM_USERNAME_ENV = "SCIM_USERNAME";
  private static final String SCIM_PASSWORD_ENV = "SCIM_PASSWORD";
 String username;
 String password;

    @Override
  public String getId() {
    return PROVIDER_ID;
  }

  CloseableHttpClient httpclient = HttpClients.custom()
				.setDefaultRequestConfig(RequestConfig.custom()
						.setRedirectsEnabled(false)
						.build()).build();

    public String authtoken(){
        String username = System.getenv(SCIM_USERNAME_ENV);
        String password = System.getenv(SCIM_PASSWORD_ENV);
        String valueToEncode = username + ":" + password;
        return "Basic " + Base64.getEncoder().encodeToString(valueToEncode.getBytes());
    }

	public <T> SimpleHttp.Response clientRequest(String endpoint, String method, T entity) throws Exception {
		SimpleHttp.Response response = null;

		/* Create client */
		CloseableHttpClient httpclient = HttpClients.custom()
				.setDefaultRequestConfig(RequestConfig.custom()
						.setRedirectsEnabled(false)
						.setCookieSpec(CookieSpecs.STANDARD)
						.build()).build();
		this.httpclient = httpclient;
        
        String server = System.getenv(SCIM_URL_ENV);

		/* Build URL */

		String endpointurl;
		endpointurl = String.format("%s/scim/v2/%s", server, endpoint);
		log.infov("Sending {0} request to {1}", method.toString(), endpointurl);
		try {
			switch (method) {
			case "GET":
				response = SimpleHttp.doGet(endpointurl, this.httpclient).header("Authorization", authtoken()).asResponse();
				break;
			case "POST":
				/* Header is needed for domains endpoint only, but use it here anyway */
				response = SimpleHttp.doPost(endpointurl, this.httpclient).header("Authorization", authtoken()).json(entity).asResponse();
				break;
			case "PUT":
				response = SimpleHttp.doPut(endpointurl, this.httpclient).header("Authorization", authtoken()).json(entity).asResponse();
				break;
			default:
				log.warn("Unknown HTTP method, skipping");
				break;
			}
		} catch (Exception e) {
			log.errorv("Error: {0}", e.getMessage());
			throw new Exception();
		}

		/* Caller is responsible for executing .close() */
		return response;
	}

    private SCIMUser getUserByUsername(String username) {
		// call the /scim/v2/Users endpoint and get the list of possible users then filter to a specific user based on the attribute

		String usersSearchUrl = "Users";
		SCIMUser user = null;
		List<SCIMUser.Resource> filteredList;
		SimpleHttp.Response response;
		try {
			response = clientRequest(usersSearchUrl, "GET", null);
			user = response.asJson(SCIMUser.class);
			response.close();
		} catch (Exception e) {
			log.errorv("Error: {0}", e.getMessage());
			throw new RuntimeException(e);
		}
		if (username == "*" || username.isEmpty()) {
			return user;
		}
		// take the userlist and remove any users that don't match the attribute value by iterating over it
		List<SCIMUser.Resource> users = user.getResources();
		filteredList = new ArrayList<SCIMUser.Resource>();
		for (SCIMUser.Resource u : users) {
            if (u.getUserName().equals(username)) {
                filteredList.add(u);
            }

		}
		//replace the existing user
		int length = filteredList.size();
		if (length == 0) {
			log.errorv("No users found for {0}", username);
			return null;
		}
		user.setResources(filteredList);
		user.setTotalResults(length);
		user.setItemsPerPage(length);
		user. setStartIndex(0);
		log.errorv("New User: {0}",user);
		return user;
	}

  private void addUserSCIM(UserModel user) {
    SCIMUser.Resource newUser = null;
    SCIMUser userobj = getUserByUsername(user.getUsername());
    if (userobj == null) {
        newUser = setupUser(user);
    } else {
        newUser = userobj.getResources().get(0);
        newUser.setActive(true);
    }
    SimpleHttp.Response response = null;
    String usersUrl = "Users";
    
    try {
        response = clientRequest(usersUrl, "POST", newUser);
    } catch (Exception e) {
        log.errorv("Error: {0}", e.getMessage());
    }
}

  private void disableUserSCIM(UserModel user) {
    SCIMUser userobj = getUserByUsername(user.getUsername());
    if (userobj == null) {
        log.errorv("User {0} not found", user.getUsername());
        return;
    }
    SCIMUser.Resource scuser = userobj.getResources().get(0);
    scuser.setActive(false);
    String modifyUrl = String.format("Users/%s", scuser.getId());

    SimpleHttp.Response response;
    try {
        response = clientRequest(modifyUrl, "PUT", scuser);
    } catch (Exception e) {
        log.errorv("Error: {0}", e.getMessage());
        throw new RuntimeException(e);
    }
  }
  @Override
  UserChangedHandler getUserChangedHandler() {
    return new UserChangedHandler() {
      @Override
      void onUserAdded(KeycloakSession session, RealmModel realm, UserModel user) {
        log.infof("User %s added to Realm %s", user.getUsername(), realm.getName());
        addUserSCIM(user);
      }

      @Override
      void onUserRemoved(KeycloakSession session, RealmModel realm, UserModel user) {
        log.infof("User %s removed from Realm %s", user.getUsername(), realm.getName());
        disableUserSCIM(user);
	  }
    };
  }

private SCIMUser.Resource setupUser(UserModel keyuser) {
		SCIMUser.Resource user = new SCIMUser.Resource();
		SCIMUser.Resource.Name name = new SCIMUser.Resource.Name();
		SCIMUser.Resource.Email email = new SCIMUser.Resource.Email();
		List<String> schemas = new ArrayList<String>();
		List<SCIMUser.Resource.Email> emails = new ArrayList<SCIMUser.Resource.Email>();
		List<SCIMUser.Resource.Group> groups = new ArrayList<SCIMUser.Resource.Group>();

		schemas.add(SCHEMA_CORE_USER);
		user.setSchemas(schemas);
		user.setUserName(keyuser.getUsername());
		user.setActive(true);
		user.setGroups(groups);


		name.setGivenName(keyuser.getFirstName());
		name.setMiddleName("");
		name.setFamilyName(keyuser.getLastName());
		user.setName(name);

		email.setPrimary(true);
		email.setType("work");
		email.setValue(keyuser.getEmail());
		emails.add(email);
		user.setEmails(emails);

		return user;
	}
























}
