package io.siggi.simplehttpproxy;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

class ForwardingSettings {

    public String key = null;
    public String[] keyList = null;
    public String[] host = null;
    public int[] port = null;
    public String[] path = null;
    public String hostHeader = null;
    public String backend = null;
    public ForwardType forwardType = ForwardType.NORMAL;
    public boolean allowCache = false;
    public boolean hideOtherProxies = false;
    public boolean alwaysCloseConnection = false;
    public BasicAuthCondition basicAuthCondition = BasicAuthCondition.NEVER;
    public String basicAuthFile = null;
    public long hstsTimeout = -1L;
    public boolean hstsIncludeSubdomains = false;
    public boolean hstsPreload = false;
    public List<String> injectHeadersToServer = new ArrayList<>();
    public List<String> injectHeadersToClient = new ArrayList<>();
    ForwardingSettings(String key, int defaultPort) {
        this.key = key;
        this.keyList = key.split(",");
        this.host = new String[this.keyList.length];
        this.port = new int[this.keyList.length];
        this.path = new String[this.keyList.length];
        Arrays.fill(this.port, defaultPort);
        for (int i = 0; i < this.keyList.length; i++) {
            this.keyList[i] = this.keyList[i].trim();
            int slashPos = this.keyList[i].indexOf("/");
            if (slashPos >= 0) {
                host[i] = this.keyList[i].substring(0, slashPos);
                path[i] = this.keyList[i].substring(slashPos);
            } else {
                host[i] = this.keyList[i];
                path[i] = "";
            }
            if (host[i].contains(":")) {
                int colonPos = host[i].lastIndexOf(":");
                port[i] = Integer.parseInt(host[i].substring(colonPos + 1));
                host[i] = host[i].substring(0, colonPos);
            }
        }
    }

    public ForwardingSettingsMatch match(String hostPart, String pathPart, int port) {
        int i = -1;
        for (String key : keyList) {
            i += 1;
            String thisHost = this.host[i];
            int thisPort = this.port[i];
            String thisPath = this.path[i];
            if (thisPort != 0 && thisPort != port) {
                continue;
            }
            if (thisHost.equals("*")) {
                // no check
            } else if (thisHost.startsWith("*.")) {
                if (!hostPart.endsWith(thisHost.substring(1))) {
                    continue;
                }
            } else if (!thisHost.equals(hostPart)) {
                continue;
            }
            if (!pathPart.startsWith(thisPath)) {
                continue;
            }
            return new ForwardingSettingsMatch(this, i);
        }
        return null;
    }

    public BasicAuth getBasicAuth() {
        if (basicAuthFile != null) {
            try {
                return new BasicAuth(new File("basicauth/" + basicAuthFile));
            } catch (Exception e) {
            }
        }
        return null;
    }

    public enum ForwardType {

        NORMAL, REDIRECT_PREFIX, REDIRECT_EXACT
    }

    public enum BasicAuthCondition {

        NEVER, ALL_EXCEPT_SAFE_AND_POST, ALL_EXCEPT_SAFE, ALL
    }
}
