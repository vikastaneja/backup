package identity.util.httplibrary;
import com.google.common.base.Strings;
import org.w3c.dom.css.Counter;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;
import java.util.stream.*;
import java.io.*;
//import java.util.ArrayList;
//import java.util.List;
//
//import org.apache.http.NameValuePair;
//import org.apache.http.client.entity.UrlEncodedFormEntity;
//import org.apache.http.client.methods.CloseableHttpResponse;
//import org.apache.http.client.methods.HttpPost;
//import org.apache.http.impl.client.CloseableHttpClient;
//import org.apache.http.impl.client.HttpClients;
//import org.apache.http.message.BasicNameValuePair;
//
//import com.splunk.*;
//import com.sun.org.apache.xerces.internal.impl.dv.util.*;
//import org.apache.commons.codec.binary.Base64;

/**
 * Class to analyze CSP for email template & content domain records in splunk & do a false positive
 * analysis to write a report to output Spreadsheet file.
 * @author okulkarni
 */
public class LogAnalysis { // extends Service {

    private class Counters {


        private final String method;
        private final String proxy;
        private final String cookie;
        private final String param;
        private final String name;
        private final String loginType;
        private final String referer;
        private final String userAgent;
        private final String orgId;


        private Counters () {
            param = null;
            cookie = null;
            proxy = null;
            method = null;
            name = null;
            loginType = null;
            referer = null;
            userAgent = null;
            orgId = null;
        }

        public Counters(String name, String method, String proxy, String cookie,
                        String param, String loginType, String referer, String userAgent, String orgId) {
            this.name = name;

            this.method = method;

            this.proxy = proxy;

            this.cookie = cookie;

            this.param = param;

            this.loginType = loginType;

            this.referer = referer;

            this.userAgent = userAgent;

            this.orgId = orgId;
        }

        public String getOrgId() { return orgId; }

        public String getLoginType() { return loginType; }

        public String getReferer() {return referer; }

        public String getUserAgent() { return userAgent; }

        public String getParam() {
            return param;
        }

        public String getCookie() {
            return cookie;
        }

        public String getProxy() {
            return proxy;
        }

        public String getMethod() {
            return method;
        }

        public String getName() {
            return name;
        }
    }

    public LogAnalysis(final String folderName) {
        this.folderName = folderName;
//        super(host);
    }

//    public LogAnalysis() {
////        super(host);
//        // TODO Auto-generated constructor stub
//    }

    private final String folderName;
    private static int e_fpCount = 0;
    private static int e_moreInfoCount = 0;
    private static int e_totalCount = 0;
    private static String FALSE_POSITIVE = "FP";
    private static String MORE_INFO = "Investigate";
    private static String EXPECTED = "Expected";
    private static BufferedReader br = null;
    private static FileWriter fr = null;

    private List<Counters> counters = new ArrayList<Counters>();
    private Map<String, Integer> orgsCounter = new HashMap<String, Integer>();
    private Map<String, Integer> userAgentCounters = new HashMap<String, Integer>();
    private Map<String, Integer> typeOfLoginCounters = new HashMap<String, Integer>();


    // Using the format for bit array <method><cookie><param><proxy>

    public void analyzeFiles() throws IOException {
        Files.walk(Paths.get(this.folderName)).forEach(filePath -> {
            if (Files.isRegularFile(filePath) && filePath.getFileName().toString().endsWith(".csv")) {
                try {
                    try(PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter("/Users/vtaneja/ForcedLogin/myfile.txt", true)))) {
                        printLog(out, "\nFile: " + filePath.getFileName().toString());
                    } catch (IOException e) {
                        //exception handling left as an exercise for the reader
                        e.printStackTrace();
                    }

                    final InputStream inputStream = Files.newInputStream(filePath.toAbsolutePath());
                    br = new BufferedReader(new InputStreamReader(inputStream));
                    this.analyzeCSPLogs();
                } catch (IOException e) {
                    e.printStackTrace();
                } finally {
                    if (br != null) {
                        try {
                            br.close();
                            br = null;
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                }
            }
        });
    }

    private void initialize() {
        try {
            br = new BufferedReader(new FileReader("/Users/vtaneja/Downloads/testData.csv"));
//            fr = new FileWriter("/Users/vtaneja/Downloads/FL_Results.csv");
//            fr.append("LogRecord, TimeStamp, BlockedUri, DocumentUri, Policy, Violated Directive, Type, Category\n");
            if (counters.size() != 0)
                counters.clear();
        }
        catch(Exception e) {
            e.printStackTrace();
        }
    }

    public BufferedReader getBr() {
        return this.br;
    }

    public void analyzeCSPLogs() {
        try {
            String sCurrentLine;
            String str = "";

            while ((sCurrentLine = br.readLine()) != null) {
                if(sCurrentLine.contains("sclcm,")) {
                    processLog(sCurrentLine);
                    str = sCurrentLine;
                }
                else
                    str += sCurrentLine;
            }
            processLog(str);
            try(PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter("/Users/vtaneja/ForcedLogin/myfile.txt", true /* append to end */)))) {
                String log = java.text.DateFormat.getDateTimeInstance().format(Calendar.getInstance().getTime());
                printLog(out, log);

                printLog(out, "----> Duration: 8hrs");

                log = "----> total:  " + this.counters.size();

                printLog(out, log);

                log = "----> total for POST: " + this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("POST")).count();
                printLog(out, log);
                log = "----> total for GET: " + this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("GET")).count();
                printLog(out, log);

                log = "----> total for POST with null XiProxy: " + this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("POST") && p.getProxy().equals("null")).count();
                printLog(out, log);

                log = "----> total for POST with non null XiProxy: " + this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("POST") && !p.getProxy().equals("null")).count();
                printLog(out, log);
                log = "----> total for GET with non null XiProxy: " + this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("GET") && !p.getProxy().equals("null")).count();
                printLog(out, log);

                log = "----> total for GET with null XiProxy: " + this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("GET") && p.getProxy().equals("null")).count();
                printLog(out, log);
                log = "----> total for GET with null cookie and null value: " + this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("GET") && p.getCookie().equals("null") && p.getParam().equals("null")).count();

                printLog(out, log);
                log = "----> total for POST with cookie and null param: " + this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("POST") && !p.getCookie().equals("null") && p.getParam().equals("null")).count();
                printLog(out, log);
                log = "----> total for POST with null cookie and null param: " + this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("POST") && p.getCookie().equals("null") && p.getParam().equals("null")).count();
                printLog(out, log);

                log = "----> total for POST with cookie and param: " + this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("POST") && !p.getCookie().equals("null") && !p.getParam().equals("null")).count();
                printLog(out, log);

                log = "----> total with non null user agent: " + this.counters.parallelStream().filter(p -> !"null".equals(p.getUserAgent())).count();
                printLog(out, log);

                log = "----> total with non null referer: " + this.counters.parallelStream().filter(p -> !"null".equals(p.getReferer())).count();
                printLog(out, log);

                log = "----> Total orgs: " + orgsCounter.size();
                printLog(out, log);

                log = "----> Total user agents: " + userAgentCounters.size();
                printLog(out, log);

                log = "----> User agents:\n";
                printLog(out, log);

                Set<String> agents = userAgentCounters.keySet();
                log = "";
                int nonBrowserAttempt = 0;
                StringBuilder nonBrowserAgents = new StringBuilder();
                for (String agent : agents) {
                    log += agent + " ##### ";
                    if (agent.length() <= "Mozilla/".length() || !agent.substring(0, "Mozilla/".length()).equals("Mozilla/")) {
                        nonBrowserAgents.append(agent).append(" ##### ");
                        nonBrowserAttempt++;
                    }
                }


//                printLog(out, log);

                log = "----> Non browser attempts: " + nonBrowserAttempt;

                printLog(out, log);

                printLog(out, nonBrowserAgents.toString());

                log = "----> Total login types: " + typeOfLoginCounters.size();
                printLog(out, log);

                log = "----> Login types: ";
                printLog(out, log);

                Set<String> types = typeOfLoginCounters.keySet();
                log = "";
                int nonUITotal = 0;
                int totalNonUITypes = 0;
                StringBuilder nonUIAttempts = new StringBuilder();
                nonUIAttempts.append("\n*** Non-UI attempt types: \n");
                for (String agent : types) {
                    log += agent + " ##### ";
                    if (!"UI".equals(agent.split(",")[0])) {
                        nonUITotal += typeOfLoginCounters.get(agent);
                        totalNonUITypes++;
                        nonUIAttempts.append(agent).append(" ##### ");
                    }
                }

                printLog(out, log);

                log = "\n*** Total Non UI type logins: " + totalNonUITypes + ", total login attemps for non-ui types: " + nonUITotal;
                printLog(out, log);
                printLog(out, nonUIAttempts.toString());

                log = "----> total with UI login, HTTP POST, mismatch values: "
                        + this.counters.parallelStream().filter(p -> !"UI".equals(p.getLoginType().split(",")[0])
                        && p.getMethod().equals("POST")
                        && !p.getCookie().equals("null") && !p.getParam().equals("null")).count();
                printLog(out, log);

//                log = "\n----> For mismatch values with HTTP POST:";
//                Stream<Counters> mismatchCounters = this.counters.parallelStream().filter(p -> p.getMethod().equals("POST")
//                                && !p.getCookie().equals("null") && !p.getParam().equals("null"));
//
//                List<Counters> mcounters = mismatchCounters.collect(Collectors.<Counters>toList());
//                for (Counters counter : mcounters) {
//                    System.out.print(counter.getReferer() + " ##### ");
//                    log += "\n\nOrg Id *****  " + counter.getOrgId();
//                    log += "\nUser Agent ---- " + counter.getUserAgent();
//                    log += "\nLogin type ==== " + counter.getLoginType();
//                    log += "\nReferer   ##### " + counter.getReferer();
//                }
//
//                printLog(out, log);


//                log = "\n----> For null values with HTTP POST:";
//                Stream<Counters> mismatchCounters = this.counters.parallelStream().filter(p -> p.getMethod().equals("POST")
//                        && p.getCookie().equals("null") && p.getParam().equals("null"));
//
//                List<Counters> mcounters = mismatchCounters.collect(Collectors.<Counters>toList());
//                for (Counters counter : mcounters) {
//                    System.out.print(counter.getReferer() + " ##### ");
//                    log += "\n\nOrg Id *****  " + counter.getOrgId();
//                    log += "\nUser Agent ---- " + counter.getUserAgent();
//                    log += "\nLogin type ==== " + counter.getLoginType();
//                    log += "\nReferer   ##### " + counter.getReferer();
//                }
//
//                printLog(out, log);

                // Questions to ask to filter out the possibilities:
                // 1. We currently have null values for parameters. Can param be null in CSRF attack? If not, we can rule them out from the scenario which we are trying to determine
                // 2. What other scenarios should we be looking for in terms of combinations for cookie and param values?
                // 3. We also need to think about all the HTTP methods when thinking about the combinations.
                log = "\n----> For SessionType as UI (for UI): ";
                printLog(out, log);
                Stream<Counters> mismatchCounters = this.counters.parallelStream().filter(p -> p.getLoginType().split("//")[0].equals("UI")
                        && p.getLoginType().split("//")[1].endsWith("(db=A,api=Application)")
                        && (p.getUserAgent().length() <= "Mozilla/".length() || p.getUserAgent().substring(0, "Mozilla/".length()).equals("Mozilla/"))
                        && (p.getCookie().equals("null") || !p.getParam().equals("null")));

                List<Counters> mcounters = mismatchCounters.collect(Collectors.<Counters>toList());

                if (mcounters.size() == 0) {
                    printLog(out, "no logs");
                } else {
                    printLog(out, "Total number of UI logins to investigate: " + mcounters.size());
                    for (Counters counter : mcounters) {
//                        System.out.print(counter.getReferer() + " ##### ");
                        StringBuilder blog = new StringBuilder();
                        blog.append("\n\nOrg Id:\t" + counter.getOrgId());
                        blog.append("\nUser Agent:\t" + counter.getUserAgent());
                        blog.append("\nLogin type:\t" + counter.getLoginType());
                        blog.append("\nReferer:\t" + counter.getReferer());
                        blog.append("\nCookie/Param:\t" + counter.getCookie() + "/" + counter.getParam());
                        blog.append("\nUser Name:\t" + counter.getName());
                        printLog(out, blog.toString());
                    }
                }


//                System.out.println("----> Login names for cookie and param mismatch for HTTP POST");
//                Stream<Counters> stream = this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("POST") && !p.getCookie().equals("null") && !p.getParam().equals("null"));
//                List<Counters> counterses = stream.collect(Collectors.<Counters>toList());
//                for (Counters counter : counterses) {
//                    System.out.print(counter.getName() + ", ");
//                }
            } catch (IOException e) {
                //exception handling left as an exercise for the reader
                e.printStackTrace();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void printLog(PrintWriter out, String log) {
        if (out != null) {
            out.println(log);
        }

        System.out.println(log);
    }

    private void processLog(String logRecord) {
        try {
            if(!logRecord.isEmpty()) {
//                logRecord = logRecord.replaceAll("," , " ");
                String category = "";
                String[] tokens = logRecord.split("`");

//                logRecordType,method,orgId,name,userName,loginCsrfCookieVal,loginCsrfParamVal,theRest
                String name = tokens[2].trim();
                String method = tokens[5].trim();
                String cookie = tokens[30].trim();
                String param = tokens[10].trim().split("///")[0].split("\"")[0];
                String orgId = tokens[21].trim();
                String loginType = tokens[8].trim().split("//")[0] + "//" + tokens[8].trim().split("//")[1];
                String referer = tokens[7].trim().split("//")[0];
                if (referer != null && !referer.equals("null")) {
                    referer = tokens[7].trim().split("//")[0] + "//" + tokens[7].trim().split("//")[1];
                }
                String userAgent = tokens[4].trim().split("///")[0];
                String xiProxy = tokens[6].trim();
                int i = 0;
//
// method = 5
//                logintype = 8.split(//) 0 + 1
//                cookie = 30
//                value = 10.split(, ") 0
//                referer = 7.split(///) 0
//                user agent = 4.split(///) 0
//                user name = 2
//                xiIdentifier = 6
//                String xiProxy = "";
//                try {
//                    xiProxy = tokens[8].split("`")[3].trim();
//                } catch (Exception ex) {
//                    printLog(null, "ERROR: " + tokens[8]);
//                    xiProxy = tokens[10].split("`")[4].trim();
//                }
//
                if (!Strings.isNullOrEmpty(orgId)) {
                    if (orgsCounter.containsKey(orgId)) {
                        int counter = orgsCounter.get(orgId);
                        orgsCounter.put(orgId, counter + 1);
                    } else {
                        orgsCounter.put(orgId, 1);
                    }
                }

                if (!Strings.isNullOrEmpty(userAgent)) {
                    if (userAgentCounters.containsKey(userAgent)) {
                        int counter = userAgentCounters.get(userAgent);
                        userAgentCounters.put(userAgent, counter + 1);
                    } else {
                        userAgentCounters.put(userAgent, 1);
                    }
                }

                if (!Strings.isNullOrEmpty(loginType)) {
                    if (typeOfLoginCounters.containsKey(loginType)) {
                        int counter = typeOfLoginCounters.get(loginType);
                        typeOfLoginCounters.put(loginType, counter + 1);
                    } else {
                        typeOfLoginCounters.put(loginType, 1);
                    }
                }
//
                counters.add(new Counters(name, method, xiProxy, cookie, param, loginType, referer, userAgent, orgId));

//                category = analyzeCSPEmailTemplateRecord(blockedUri, documentUri, violatedDirective);
//                e_totalCount += 1;

//                fr.append(logRecord + ", ");
//                fr.append(timeStamp + ", ");
//                fr.append(blockedUri + ", ");
//                fr.append(documentUri +", ");
//                fr.append(policy + ", ");
//                fr.append(violatedDirective + ", ");
//                fr.append(type + ", ");
//                fr.append(category + ", ");
//                fr.append("\n");
            }
        }
        catch(Exception e) {
            e.printStackTrace();
        }
    }



    private void analyze(String method, String xiProxy, String cookie, String param) {

    }

    private static String analyzeCSPEmailTemplateRecord(String blockedUri, String documentUri, String violatedDirective) {
        String result = EXPECTED;
        if(violatedDirective.contains("style-src")
                ||violatedDirective.contains("img-src")
                ||violatedDirective.contains("font-src")) {
            result = FALSE_POSITIVE;
            e_fpCount += 1;
        }
        else if(blockedUri.isEmpty() || blockedUri.contains("[\\W]")) {
            result = MORE_INFO;
            e_moreInfoCount += 1;
        }
        else if(violatedDirective.contains("object-src")) {
            result = EXPECTED;
        }
        else {
            String[] policyTokens = violatedDirective.split(" ");
            for(String s : policyTokens) {
                if(blockedUri.contains(s)) {
                    result = FALSE_POSITIVE;
                    e_fpCount += 1;
                }
            }
        }
        return result;
    }

    // Following code is not used. So, I'm commenting out.
	/*
	private static void connectSplunk() {
		try {
			Args args = new Args();
			args.put("username", "");
	        args.put("password", "");
	        HttpService serv = new HttpService("qa-splunk.soma.salesforce.com", 443);
	        ResponseMessage response = serv.post("", args);
	        System.out.println(response.getStatus());
	        System.out.println(response.getContent().toString());
	        String sessionKey = Xml.parse(response.getContent())
	                .getElementsByTagName("sessionKey")
	                .item(0)
	                .getTextContent();
	        System.out.println(sessionKey);

			Service service = new Service("qa-splunk.soma.salesforce.com", 443);
	        String credentials = "username:password";
	        byte[] basicAuthHeaderBytes = Base64.encodeBase64(credentials.getBytes());
	        String basicAuthHeader = new String(basicAuthHeaderBytes);
	        service.setToken("Basic " + basicAuthHeader);

	        // Print the session token
	        System.out.println("Your session token: " + service.getToken());

	        // Print installed apps to the console to verify login
	        for (Application app : service.getApplications().values()) {
	            System.out.println(app.getName());
	        }

		}
		catch(Exception e) {
			e.printStackTrace();
		}
	}*/

    public static void main(String[] args) throws IOException {

        // Currently, the code is dependent on the placement of the fields in the CSV file.
        // Use the following query to get the file.
        // index=* `logRecordType(sclcm)` | fields *
        // index=* `logRecordType(sclcm)` earliest=-2h | fields logRecordType,method,orgId,name,userName,loginCsrfCookieVal,loginCsrfParamVal,theRest
//         index=* `logRecordType(sclcm)` earliest=-1h | fields logRecordType,method,orgId,name,userName,loginCsrfCookieVal,loginCsrfParamVal,theRest
        // index=* `logRecordType(sclcm)` 	earliest=-15m url!="/*" | fields method,postParam,queryString,url,userName,loginCsrfCookieVal,loginCsrfParamVal,theRest
//==>      index=* `logRecordType(sclcm)` 	earliest=-15m url!="/*" | fields logRecordType,theRest

        LogAnalysis fp = new LogAnalysis("/Users/vtaneja/ForcedLogin");

        try {
            fp.analyzeFiles();
//            fp.initialize();
//            fp.analyzeCSPLogs();
//            int e_expectedCount = e_totalCount - (e_fpCount + e_moreInfoCount);
//            String statistics = "Total Records: " + e_totalCount  + ", FP count: " + e_fpCount + ", Investigate: "
//                    + e_moreInfoCount + ", Expected Count: " + e_expectedCount + "\n";
//            fr.append(statistics);
//            br.close();
//            fr.close();
            System.out.println("Logs analyzed successfully!");
            //connectSplunk();
        }
        catch(Exception e) {
            e.printStackTrace();
        } finally {
            if (fp.getBr() != null) {
                fp.getBr().close();
            }
        }
    }
}
