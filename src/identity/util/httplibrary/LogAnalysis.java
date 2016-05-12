package identity.util.httplibrary;
import com.google.common.base.Strings;
import com.google.common.collect.Maps;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;
import org.w3c.dom.css.Counter;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.*;
import java.io.*;
import org.apache.commons.csv.CSVParser;
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

    public static Map<String, CSVRecord> result;
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
        private final String userId;


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
            userId = null;
        }

        public Counters(String name, String method, String proxy, String cookie,
                        String param, String loginType, String referer, String userAgent,
                        String orgId, String userId) {
            this.name = name;

            this.method = method;

            this.proxy = proxy;

            this.cookie = cookie;

            this.param = param;

            this.loginType = loginType;

            this.referer = referer;

            this.userAgent = userAgent;

            this.orgId = orgId;

            this.userId = userId;
        }

        public String getUserId() { return userId; }

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
    private int totalCount = 0;
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

    private Map<String, Integer> userCounter = new HashMap<String, Integer>();
    private Map<String, List<Counters>> userIdToUserName = new HashMap<String, List<Counters>>();
    private Map<String, Map<String, Counters>> orgs = new HashMap<String, Map<String, Counters>>();
    private Map<String, Map<String, Integer>> orgToUser = new HashMap<String, Map<String, Integer>>();


    // Using the format for bit array <method><cookie><param><proxy>

    public void analyzeFiles() throws IOException {
        Files.walk(Paths.get(this.folderName)).forEach(filePath -> {
            if (Files.isRegularFile(filePath) && filePath.getFileName().toString().endsWith(".csv")) {
                try {
                    try(PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter("/Users/vtaneja/ForcedLogin/myfile.txt", true)))) {
                        // printLog(out, "\nFile: " + filePath.getFileName().toString());
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
        this.counters.clear();
        totalCount = 0;
        try {
            String sCurrentLine;
            String str = "";
            int i = 0;
            while ((sCurrentLine = br.readLine()) != null) {
//                System.out.println("Record#: " + ++i);
                if(sCurrentLine.contains("sclcm,")) {
                    totalCount++;
                    processLog(sCurrentLine);
                    str = sCurrentLine;
                }
                else
                    str += sCurrentLine;
            }
            processLog(str);
            try(PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter("/Users/vtaneja/ForcedLogin/myfile.txt", true /* append to end */)))) {
                String log = java.text.DateFormat.getDateTimeInstance().format(Calendar.getInstance().getTime());
                // printLog(out, log);

//                log = "----> total:  " + this.counters.size();

                log = "----> total:  " + totalCount;

                // printLog(out, log);

                String METHOD = "GET";

                HashMap<String, Integer> sortedOrgMap = this.sortByValues(this.orgsCounter);
                printLog(out, "===========>>>>>>>>>>");
//                printLog(out, "OrgId,Count");
                for(Map.Entry<String, Integer> entry : sortedOrgMap.entrySet()) {
                    StringBuilder sb = new StringBuilder();
//                    sb.append("OrgId: ").append(entry.getKey()).append(", Count: ").append(entry.getValue());
                    sb.append(entry.getKey()).append(",").append(entry.getValue());

//                    printLog(out, sb.toString());
                }

                printLog(out, "===========>>>>>>>>>>");
//                printLog(out, "OrgId,UserId,Count");
                for (Map.Entry<String, Map<String, Integer>> entry : orgToUser.entrySet()) {
                    for (Map.Entry<String, Integer> e : entry.getValue().entrySet()) {
                        StringBuilder sb = new StringBuilder();
                        sb.append(entry.getKey()).append(",").append(e.getKey()).append(",").append(e.getValue());

//                        printLog(out, sb.toString());
                    }

                }

                printLog(out, "===========>>>>>>>>>>");
//                printLog(out, "OrgId-UserId,Count");
                for (Map.Entry<String, Map<String, Integer>> entry : orgToUser.entrySet()) {
                    for (Map.Entry<String, Integer> e : entry.getValue().entrySet()) {
                        StringBuilder sb = new StringBuilder();
                        sb.append(entry.getKey()).append("-").append(e.getKey()).append(",").append(e.getValue());

//                        printLog(out, sb.toString());
                    }

                }

                printLog(out, "===========>>>>>>>>>>");
//                StringBuilder sb1 = new StringBuilder();
//                sb1.append("SELECT Account,Active,CreatedDate,Id,Name,OrganizationType,Server,SignupCountryIsoCode,Status FROM AllOrganization WHERE ");
//
//                for(Map.Entry<String, Integer> entry : sortedOrgMap.entrySet()) {
//
////                    sb.append("OrgId: ").append(entry.getKey()).append(", Count: ").append(entry.getValue());
//                    sb1.append("Id='").append(entry.getKey()).append("' OR ");
//
//
//                }

//                printLog(out, sb1.toString());
//                printLog(out, "===========>>>>>>>>>>");
//
//                printLog(out, "OrgId,UserId,OrgCount,UserCount,OrgName,OrgType,Status");
//                for (Map.Entry<String, Map<String, Integer>> entry : orgToUser.entrySet()) {
//                    for (Map.Entry<String, Integer> e : entry.getValue().entrySet()) {
//
//                        StringBuilder sb = new StringBuilder();
//
//                        sb.append(entry.getKey()).append(",").append(e.getKey()).append(",").append(sortedOrgMap.get(entry.getKey())).append(",").append(e.getValue());
//
//                        if (result.containsKey(entry.getKey())) {
//                            CSVRecord r = result.get(entry.getKey());
//
//                            sb.append(",").append(r.get(4).replace(',','-').replace('"',' ').replace(">", "&gt").replace("<", "&lt")).append(",").append(r.get(5)).append(",").append(r.get(8));
//
//                        } else {
//                            sb.append(",").append("EMPTY").append(",").append("EMPTY").append(",").append("EMPTY");
//                        }
//
//                        printLog(out, sb.toString());
//                    }
//
//
//                }
//
//               printLog(out, "===========>>>>>>>>>>");

                printLog(out, "===========>>>>>>>>>>");

                printLog(out, "OrgId,UserIds,UCount,OrgCount,UserCounts,OrgName,OrgType,Status");
                for (Map.Entry<String, Map<String, Integer>> entry : orgToUser.entrySet()) {
                    StringBuilder sb = new StringBuilder();
                    StringBuilder names = new StringBuilder();
                    StringBuilder counts = new StringBuilder();
                    int count = 0;
                    for (Map.Entry<String, Integer> e : entry.getValue().entrySet()) {
                        names.append(e.getKey()).append("-");
                        counts.append(e.getValue()).append("-");
                        count++;
                    }

                    sb.append(entry.getKey()).append(",").append(names.toString()).append(",").append(count).append(",").append(sortedOrgMap.get(entry.getKey())).append(",").append(counts.toString());

                    if (result.containsKey(entry.getKey())) {
                        CSVRecord r = result.get(entry.getKey());

                        sb.append(",").append(r.get(4).replace(',','-').replace('"',' ').replace(">", "&gt").replace("<", "&lt")).append(",").append(r.get(5)).append(",").append(r.get(8));

                    } else {
                        sb.append(",").append("EMPTY").append(",").append("EMPTY").append(",").append("EMPTY");
                    }

                    //printLog(out, sb.toString());


                }

               printLog(out, "===========>>>>>>>>>>");

//                printLog(out, "OrgId,UserIds,UCount,OrgCount,UserCounts,OrgName,OrgType,Status");
                printLog(out, "OrgId,OrgCount,Status");
                for (Map.Entry<String, Map<String, Integer>> entry : orgToUser.entrySet()) {
//                    StringBuilder sb = new StringBuilder();
//                    StringBuilder names = new StringBuilder();
//                    StringBuilder counts = new StringBuilder();
//                    int count = 0;
//                    for (Map.Entry<String, Integer> e : entry.getValue().entrySet()) {
//                        names.append(e.getKey()).append("-");
//                        counts.append(e.getValue()).append("-");
//                        count++;
//                    }
//
//                    sb.append(entry.getKey()).append(",").append(names.toString()).append(",").append(count).append(",").append(sortedOrgMap.get(entry.getKey())).append(",").append(counts.toString());

//                    if (result.containsKey(entry.getKey())) {
//                        CSVRecord r = result.get(entry.getKey());
//
//                        sb.append(",").append(r.get(4).replace(',','-').replace('"',' ').replace(">", "&gt").replace("<", "&lt")).append(",").append(r.get(5)).append(",").append(r.get(8));
//
//                    } else {
//                        sb.append(",").append("EMPTY").append(",").append("EMPTY").append(",").append("EMPTY");
//                    }

                    //printLog(out, sb.toString());
// STATUS: r.get(8): ACTIV ACTIVE EMPTY
// Org ID: entry.getKey()
// Count: sortedOrgMap.get(entry.getKey())


                    StringBuilder sb = new StringBuilder();

                    int count = sortedOrgMap.get(entry.getKey());
                    String status = null;
                    if (result.containsKey(entry.getKey())) {
                        status = result.get(entry.getKey()).get(8);
                    } else {
                        status = "EMPTY";
                    }


                    if (count > 10 && (status.equals("ACTIV") || status.equals("ACTIVE") || status.equals("EMPTY"))) {
//                        sb.append(entry.getKey()).append(",").append(String.valueOf(count)).append(",").append(status);
                        sb.append("insert into upgdata.up198_forcedlogin_optedout_org (organization_id) values ('");
                        sb.append(entry.getKey()).append("');");
                        printLog(out, sb.toString());
                    }
                }

                printLog(out, "===========>>>>>>>>>>");


//                log = "----> total for POST: " + this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("POST")).count();
//                // printLog(out, log);
//                log = "----> total for GET: " + this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("GET")).count();
//                // printLog(out, log);
//
//                log = "----> total for POST with browser: " + this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("POST") && this.isBrowser(p.getUserAgent())).count();
                // printLog(out, log);

//                log = "----> total for GET with browser: " + this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("GET") && this.isBrowser(p.getUserAgent())).count();
                // printLog(out, log);

                // printLog(out, "---> Orgs with number of users:");
//                int counterMoreThanOne = 0;
//                for (Map.Entry<String, Map<String, Counters>> entry : orgs.entrySet()) {
//                    // printLog(out, "Org: " + entry.getKey() + ", Count: " + entry.getValue().size());
//                    if (entry.getValue().size() > 1) counterMoreThanOne++;
//                }

//                long nullRefs = this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals(METHOD) && this.isBrowser(p.getUserAgent()) && p.getReferer().equals("null")).count();
                // printLog(out, "---> Total null referrers: " + nullRefs);

//                long nonNullRefs = this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals(METHOD) && this.isBrowser(p.getUserAgent()) && !p.getReferer().equals("null")).count();
                // printLog(out, "---> Total Non referrers: " + nonNullRefs);


                // printLog(out, "---> %age non-nulls: " + (nonNullRefs * 100)/(nullRefs + nonNullRefs));

//                Stream<Counters> streamOfCounters = this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals(METHOD) && this.isBrowser(p.getUserAgent()) && !p.getReferer().equals("null"));
//                // printLog(out, "===========================");
////                logInfo(out, streamOfCounters);
//                // printLog(out, "===========================");
//
//                // printLog(out, "Number of orgs more than 1 user: " + counterMoreThanOne);
//
//
////                log = "----> total for POST with null XiProxy: " + this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("POST") && p.getProxy().equals("null")).count();
////                // printLog(out, log);
////
////                log = "----> total for POST with non null XiProxy: " + this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("POST") && !p.getProxy().equals("null")).count();
////                // printLog(out, log);
////                log = "----> total for GET with non null XiProxy: " + this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("GET") && !p.getProxy().equals("null")).count();
////                // printLog(out, log);
////
////                log = "----> total for GET with null XiProxy: " + this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("GET") && p.getProxy().equals("null")).count();
////                // printLog(out, log);
////                log = "----> total for GET with null cookie and null value: " + this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("GET") && p.getCookie().equals("null") && p.getParam().equals("null")).count();
////
////                // printLog(out, log);
////                log = "----> total for POST with cookie and null param: " + this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("POST") && !p.getCookie().equals("null") && p.getParam().equals("null")).count();
////                // printLog(out, log);
////                log = "----> total for POST with null cookie and null param: " + this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("POST") && p.getCookie().equals("null") && p.getParam().equals("null")).count();
////                // printLog(out, log);
////
////                log = "----> total for POST with cookie and param: " + this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("POST") && !p.getCookie().equals("null") && !p.getParam().equals("null")).count();
////                // printLog(out, log);
////
////                log = "----> total with non null user agent: " + this.counters.parallelStream().filter(p -> !"null".equals(p.getUserAgent())).count();
////                // printLog(out, log);
////
////                log = "----> total with non null referer: " + this.counters.parallelStream().filter(p -> !"null".equals(p.getReferer())).count();
////                // printLog(out, log);
////
////                log = "----> total with null referer: " + this.counters.parallelStream().filter(p -> "null".equals(p.getReferer())).count();
////                // printLog(out, log);
////
////                log = "----> total POST with non null referer: " + this.counters.parallelStream().filter(
////                        p -> "POST".equals(p.getMethod()) & !"null".equals(p.getReferer())).count();
////                // printLog(out, log);
////
////                log = "----> total POST with null referer: " + this.counters.parallelStream().filter(
////                        p -> "POST".equals(p.getMethod()) &  "null".equals(p.getReferer())).count();
////                // printLog(out, log);
////
////                log = "----> total POST with null referer and null param: " +
////                        this.counters.parallelStream().filter(p -> "null".equals(p.getReferer()) & "null".equals(p.getParam()) & "POST".equals(p.getMethod())).count();
////                // printLog(out, log);
////
////                log = "----> total POST with null referer and null param and null cookie: " +
////                        this.counters.parallelStream().filter(p -> "null".equals(p.getReferer()) & "null".equals(p.getParam())
////                                & "null".equals(p.getCookie()) & "POST".equals(p.getMethod())).count();
////                // printLog(out, log);
//
//                log = "----> Total orgs: " + orgsCounter.size();
//                // printLog(out, log);
//
//                for(Map.Entry<String, Integer> entry : orgsCounter.entrySet()) {
//                    StringBuilder sb = new StringBuilder();
//                    sb.append("OrgId: ").append(entry.getKey()).append(", Count: ").append(entry.getValue());
////                    printLog(out, sb.toString());
//                }
//
//                log = "----> Total user agents: " + userAgentCounters.size();
//                // printLog(out, log);
//
//                log = "----> User agents:\n";
//                // printLog(out, log);
//
//                log = "----> Total users: " + userCounter.size();
//                // printLog(out, log);
//
//                Set<String> agents = userAgentCounters.keySet();
//                log = "";
//                int nonBrowserAttempt = 0;
//                StringBuilder nonBrowserAgents = new StringBuilder();
//                for (String agent : agents) {
//                    log += agent + " ##### ";
//                    if (agent.length() <= "Mozilla/".length() || !agent.substring(0, "Mozilla/".length()).equals("Mozilla/")) {
//                        nonBrowserAgents.append(agent).append(" ##### ");
//                        nonBrowserAttempt++;
//                    }
//                }
//
//
////                // printLog(out, log);
//
//                log = "----> Non browser attempts: " + nonBrowserAttempt;
//
//                // printLog(out, log);
//
//                // printLog(out, nonBrowserAgents.toString());
//
//                log = "----> Total login types: " + typeOfLoginCounters.size();
//                // printLog(out, log);
//
//                log = "----> Login types: ";
//                // printLog(out, log);
//
//                Set<String> types = typeOfLoginCounters.keySet();
//                log = "";
//                int nonUITotal = 0;
//                int totalNonUITypes = 0;
//                StringBuilder nonUIAttempts = new StringBuilder();
////                nonUIAttempts.append("\n*** Non-UI attempt types: \n");
////                for (String agent : types) {
////                    log += agent + " ##### ";
////                    if (!"UI".equals(agent.split(",")[0])) {
////                        nonUITotal += typeOfLoginCounters.get(agent);
////                        totalNonUITypes++;
////                        nonUIAttempts.append(agent).append(" ##### ");
////                    }
////                }
////
////                // printLog(out, log);
//
//
//                log = "\n*** Total Non UI type logins: " + totalNonUITypes + ", total login attemps for non-ui types: " + nonUITotal;
//                // printLog(out, log);
////                // printLog(out, nonUIAttempts.toString());
//
//                log = "----> total with UI login, HTTP POST, mismatch values: "
//                        + this.counters.parallelStream().filter(p -> !"UI".equals(p.getLoginType().split(",")[0])
//                        && p.getMethod().equals(METHOD)
//                        && !p.getCookie().equals(p.getParam())
//
//                ).count();
//                // printLog(out, log);
//
//                // printLog(out, "\nTotal with browser and UI");
//
//
//                Stream<Counters> mismatchCounters = this.counters.parallelStream().filter(
//                        p ->
////                                METHOD.equals(p.getMethod().toUpperCase()) &&
//                                p.getLoginType().split("//")[0].equals("UI") &&
//                                        p.getLoginType().split("//")[1].endsWith("(db=A,api=Application)") &&
////                                        (p.getUserAgent().length() >= "Mozilla/".length() && p.getUserAgent().substring(0, "Mozilla/".length()).equals("Mozilla/")) &&
//                                        this.isBrowser(p.getUserAgent()) &&
////                                        (p.getCookie().equals("null") && p.getParam().equals("null")) &&
//                                        true);
//
////                logInfo(out, mismatchCounters);
//
//
//                StringBuilder sb = new StringBuilder();
//                sb.append(mismatchCounters.count());
//                // printLog(out, sb.toString());
//
//                // printLog(out, "\nlogin.salesforce.com only");
//
//                mismatchCounters = this.counters.parallelStream().filter(
//                        p ->
////                                METHOD.equals(p.getMethod().toUpperCase()) &&
//                                p.getLoginType().split("//")[0].equals("UI") &&
//                                        p.getLoginType().split("//")[1].endsWith("(db=A,api=Application)") &&
////                                        (p.getUserAgent().length() >= "Mozilla/".length() && p.getUserAgent().substring(0, "Mozilla/".length()).equals("Mozilla/")) &&
//                                        this.isBrowser(p.getUserAgent()) &&
////                                        (p.getCookie().equals("null") && p.getParam().equals("null")) &&
//                                        (p.getReferer().equals("https://login.salesforce.com/") || p.getReferer().equals("https://login.salesforce.com//") || p.getReferer().equals("https://login.salesforce.com")) &&
//                true);
//
////                logInfo(out, mismatchCounters);
//                sb = new StringBuilder();
//                sb.append(mismatchCounters.count());
//                // printLog(out, sb.toString());
//
//                // printLog(out, "========>>>>>");
//                mismatchCounters = this.counters.parallelStream().filter(
//                        p ->
////                                METHOD.equals(p.getMethod().toUpperCase()) &&
//                                p.getLoginType().split("//")[0].equals("UI") &&
//                                        p.getLoginType().split("//")[1].endsWith("(db=A,api=Application)") &&
////                                        (p.getUserAgent().length() >= "Mozilla/".length() && p.getUserAgent().substring(0, "Mozilla/".length()).equals("Mozilla/")) &&
//                                        this.isBrowser(p.getUserAgent()) &&
////                                        (p.getCookie().equals("null") && p.getParam().equals("null")) &&
//                                        p.getReferer().contains("saml") &&
//                                        true);
//
////                logInfo(out, mismatchCounters);
////                log = "\n----> For mismatch values with HTTP POST:";
////                Stream<Counters> mismatchCounters = this.counters.parallelStream().filter(p -> p.getMethod().equals(METHOD)
////                                && !p.getCookie().equals("null") && !p.getParam().equals("null"));
////
////                List<Counters> mcounters = mismatchCounters.collect(Collectors.<Counters>toList());
////                for (Counters counter : mcounters) {
////                    System.out.print(counter.getReferer() + " ##### ");
////                    log += "\n\nOrg Id *****  " + counter.getOrgId();
////                    log += "\nUser Agent ---- " + counter.getUserAgent();
////                    log += "\nLogin type ==== " + counter.getLoginType();
////                    log += "\nReferer   ##### " + counter.getReferer();
////                }
////
////                // printLog(out, log);
//
//
////                log = "\n----> For null values with HTTP POST:";
////                Stream<Counters> mismatchCounters = this.counters.parallelStream().filter(p -> p.getMethod().equals(METHOD)
////                        && p.getCookie().equals("null") && p.getParam().equals("null"));
////
////                List<Counters> mcounters = mismatchCounters.collect(Collectors.<Counters>toList());
////                for (Counters counter : mcounters) {
////                    System.out.print(counter.getReferer() + " ##### ");
////                    log += "\n\nOrg Id *****  " + counter.getOrgId();
////                    log += "\nUser Agent ---- " + counter.getUserAgent();
////                    log += "\nLogin type ==== " + counter.getLoginType();
////                    log += "\nReferer   ##### " + counter.getReferer();
////                }
////
////                // printLog(out, log);
//
//                // Questions to ask to filter out the possibilities:
//                // 1. We currently have null values for parameters. Can param be null in CSRF attack? If not, we can rule them out from the scenario which we are trying to determine
//                // 2. What other scenarios should we be looking for in terms of combinations for cookie and param values?
//                // 3. We also need to think about all the HTTP methods when thinking about the combinations.
////                log = "\n----> For SessionType as UI (for UI): ";
//
//                // Since the number of users are considerable lower
//                // printLog(out, "Users with more than one attempt");
//
//                SortedMap<String, List<Counters>> smap = new TreeMap<String, List<Counters>>();
//
//                smap.putAll(userIdToUserName);
//
////                Stream<Map.Entry<String, Integer>> sorted = userCounter.entrySet().stream().sorted(Collections.reverseOrder(Map.Entry.comparingByValue()));
//
////                Map<String, Integer> top50 = sorted.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
//                int post = 0;
//                int get = 0;
//                for (Map.Entry<String, List<Counters>> entry : smap.entrySet()) {
//                    if (entry.getValue().size() > 1) {
//                        Counters ctr = smap.get(entry.getKey()).get(0);
//                        String referer = ctr.getReferer().toLowerCase();
//                        if (referer.contains("https://login.salesforce.com")
//                                && this.isBrowser(ctr.getUserAgent())
////                                || (referer.contains(".salesforce.com") && !referer.contains("my.salesforce.com"))
//                                ) {
//                            // printLog(out, "UID: " + entry.getKey() + ", Count: " + entry.getValue().size());
//
//                            // printLog(out, "Name: " + ctr.getName());
//                            // printLog(out, "Refer: " + ctr.getReferer());
//                            // printLog(out, "Cookie: " + ctr.getCookie());
//                            // printLog(out, "Param: " + ctr.getParam());
//
//                            // printLog(out, "Method: " + ctr.getMethod() + "\n");
//                        }
//                    }
//                }
//
////                for (Map.Entry<String, List<Counters>> entry : userIdToUserName.entrySet()) {
////                    if (entry.getValue().size() >= 1) {
////                        Counters ctr = userIdToUserName.get(entry.getKey()).get(0);
////                        String referer = ctr.getReferer().toLowerCase();
////                        if (referer.contains("https://login.salesforce.com")
////                                && this.isBrowser(ctr.getUserAgent())
//////                                || (referer.contains(".salesforce.com") && !referer.contains("my.salesforce.com"))
////                                ) {
////                            // printLog(out, "UID: " + entry.getKey() + ", Count: " + entry.getValue().size());
////
////                            // printLog(out, "Name: " + ctr.getName());
////                            // printLog(out, "Refer: " + ctr.getReferer());
////                            // printLog(out, "Cookie: " + ctr.getCookie());
////                            // printLog(out, "Param: " + ctr.getParam());
////
////                            // printLog(out, "Method: " + ctr.getMethod() + "\n");
////                        }
////                    }
////                }
//
//                // printLog(out, "POST with browser and UI");
//
//                mismatchCounters = this.counters.parallelStream().filter(
//                        p ->
//                                "GET".equals(p.getMethod().toUpperCase()) &&
//                                p.getLoginType().split("//")[0].equals("UI") &&
//                        p.getLoginType().split("//")[1].endsWith("(db=A,api=Application)") &&
////                                        (p.getUserAgent().length() >= "Mozilla/".length() && p.getUserAgent().substring(0, "Mozilla/".length()).equals("Mozilla/")) &&
//                                        this.isBrowser(p.getUserAgent()) &&
////                                        (p.getCookie().equals("null") && p.getParam().equals("null")) &&
//                                        true);
//
////                logInfo(out, mismatchCounters);
//
//
//                // printLog(out, "POST without browser");
//
//                mismatchCounters = this.counters.parallelStream().filter(
//                        p ->
//                                "GET".equals(p.getMethod().toUpperCase()) &&
////                                p.getLoginType().split("//")[0].equals("UI") &&
////                        p.getLoginType().split("//")[1].endsWith("(db=A,api=Application)") &&
////                                        (p.getUserAgent().length() <= "Mozilla/".length() || !p.getUserAgent().substring(0, "Mozilla/".length()).equals("Mozilla/")) &&
//                                        !this.isBrowser(p.getUserAgent()) &&
////                                        (p.getCookie().equals("null") && p.getParam().equals("null")) &&
//                                        true);
////
////                logInfo(out, mismatchCounters);
//                // printLog(out, "POST with browser");
//
//                mismatchCounters = this.counters.parallelStream().filter(
//                        p ->
//                                "GET".equals(p.getMethod().toUpperCase()) &&
////                                p.getLoginType().split("//")[0].equals("UI") &&
////                        p.getLoginType().split("//")[1].endsWith("(db=A,api=Application)") &&
////                                        (p.getUserAgent().length() >= "Mozilla/".length() && p.getUserAgent().substring(0, "Mozilla/".length()).equals("Mozilla/")) &&
//                                        this.isBrowser(p.getUserAgent()) &&
////                                        (p.getCookie().equals("null") && p.getParam().equals("null")) &&
//                                        true);
//                // printLog(out, String.valueOf(mismatchCounters.count()));
//
//                // printLog(out, "Cookie NULL, Param NULL");
//
//                mismatchCounters = this.counters.parallelStream().filter(
//                        p ->
//                                METHOD.equals(p.getMethod().toUpperCase()) &&
////                                p.getLoginType().split("//")[0].equals("UI") &&
////                        p.getLoginType().split("//")[1].endsWith("(db=A,api=Application)") &&
////                                        (p.getUserAgent().length() >= "Mozilla/".length() && p.getUserAgent().substring(0, "Mozilla/".length()).equals("Mozilla/")) &&
//                                        this.isBrowser(p.getUserAgent()) &&
//                        (p.getCookie().equals("null") && p.getParam().equals("null")) &&
//                                        true);
//
//
////                logInfo(out, mismatchCounters);
//
//                // printLog(out, "Cookie not NULL, Param NULL");
//
//                mismatchCounters = this.counters.parallelStream().filter(
//                        p ->
//                                METHOD.equals(p.getMethod().toUpperCase()) &&
////                                p.getLoginType().split("//")[0].equals("UI") &&
////                        p.getLoginType().split("//")[1].endsWith("(db=A,api=Application)") &&
////                                        (p.getUserAgent().length() >= "Mozilla/".length() && p.getUserAgent().substring(0, "Mozilla/".length()).equals("Mozilla/")) &&
//                                        this.isBrowser(p.getUserAgent()) &&
//                        (!p.getCookie().equals("null") && p.getParam().equals("null")) &&
//                                        true);
//
////                logInfo(out, mismatchCounters);
//
//                // printLog(out, "Cookie NULL, Param not NULL");
//
//                mismatchCounters = this.counters.parallelStream().filter(
//                        p ->
//                                METHOD.equals(p.getMethod().toUpperCase()) &&
////                                p.getLoginType().split("//")[0].equals("UI") &&
////                        p.getLoginType().split("//")[1].endsWith("(db=A,api=Application)") &&
////                                        (p.getUserAgent().length() >= "Mozilla/".length() && p.getUserAgent().substring(0, "Mozilla/".length()).equals("Mozilla/")) &&
//                                        this.isBrowser(p.getUserAgent()) &&
//                                        (p.getCookie().equals("null") && !p.getParam().equals("null")) &&
//                                        true);
//
////                logInfo(out, mismatchCounters);
//
//                // printLog(out, "Cookie not NULL, Param not NULL");
//
//                mismatchCounters = this.counters.parallelStream().filter(
//                        p ->
//                                METHOD.equals(p.getMethod().toUpperCase()) &&
////                                p.getLoginType().split("//")[0].equals("UI") &&
////                        p.getLoginType().split("//")[1].endsWith("(db=A,api=Application)") &&
////                                        (p.getUserAgent().length() >= "Mozilla/".length() && p.getUserAgent().substring(0, "Mozilla/".length()).equals("Mozilla/")) &&
//                                        this.isBrowser(p.getUserAgent()) &&
//                                        (!p.getCookie().equals("null") && !p.getParam().equals("null")) &&
//                                        true);

//                logInfo(out, mismatchCounters);

//                System.out.println("----> Login names for cookie and param mismatch for HTTP POST");
//                Stream<Counters> stream = this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals(METHOD) && !p.getCookie().equals("null") && !p.getParam().equals("null"));
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

    private HashMap<String, Integer> sortByValues(Map<String, Integer> map) {
        List list = new LinkedList(map.entrySet());
        // Defined Custom Comparator here

        Collections.sort(list, new Comparator() {
            public int compare(Object o1, Object o2) {
                return -((Comparable) ((Map.Entry) (o1)).getValue())
                        .compareTo(((Map.Entry) (o2)).getValue());
            }
        });

        // Here I am copying the sorted list in HashMap
        // using LinkedHashMap to preserve the insertion order
        HashMap<String, Integer> sortedHashMap = new LinkedHashMap<String, Integer>();
        for (Iterator it = list.iterator(); it.hasNext();) {
            Map.Entry<String, Integer> entry = (Map.Entry) it.next();
            sortedHashMap.put(entry.getKey(), entry.getValue());
        }
        return sortedHashMap;
    }

    private void logInfo(PrintWriter out, Stream<Counters> mismatchCounters) {
        List<Counters> mcounters = mismatchCounters.collect(Collectors.<Counters>toList());


        if (mcounters == null || mcounters.size() == 0) {
            // printLog(out, "no logs");
        } else {
            int m = 0;
            // printLog(out, "Total number of UI logins: " + mcounters.size());
            for (Counters counter : mcounters) {
//                        System.out.print(counter.getReferer() + " ##### ");
                StringBuilder blog = new StringBuilder();
                blog.append("\n\nCounter:\t" + ++m);
                blog.append("\nOrg Id:\t" + counter.getOrgId());
                blog.append("\nUser Agent:\t" + counter.getUserAgent());
                blog.append("\nLogin type:\t" + counter.getLoginType());
                blog.append("\nReferer:\t" + counter.getReferer());
                blog.append("\nCookie/Param:\t" + counter.getCookie() + "/" + counter.getParam());
                blog.append("\nUser Name:\t" + counter.getName());
                blog.append("\nMethod:\t" + counter.getMethod());
                blog.append("\nUser ID:\t" + counter.getUserId());
                if (m <= 70);
                // printLog(out, blog.toString());
            }
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
                String userId = tokens[22].trim();
                String loginType = tokens[8].trim().split("//")[0] + "//" + tokens[8].trim().split("//")[1];
                String referer = tokens[7].trim().split("//\\{")[0];
//                if (referer != null && !referer.equals("null")) {
//                    referer = tokens[7].trim().split("//")[0] + "//" + tokens[7].trim().split("//")[1];
//                }
                String userAgent = tokens[4].trim().split("///")[0];
                String xiProxy = tokens[6].trim();
if (this.isBrowser(userAgent)) {
    Counters counter1 = new Counters(name, method, xiProxy, cookie, param, loginType, referer, userAgent, orgId, userId);


    if (!Strings.isNullOrEmpty(orgId)) {
        // Add to the org to user mapping
        if (orgToUser.containsKey(orgId)) {
            Map <String, Integer> userList = orgToUser.get(orgId);
            if (userList.containsKey(userId)) {
                int counter = userList.get(userId);
                userList.put(userId, counter + 1);
            } else {
                userList.put(userId, 1);
            }


        } else {
            Map<String, Integer> userList = new HashMap<String, Integer>();
            userList.put(userId, 1);
            orgToUser.put(orgId, userList);
        }


        if (orgsCounter.containsKey(orgId)) {
            int counter = orgsCounter.get(orgId);
            orgsCounter.put(orgId, counter + 1);
        } else {
            orgsCounter.put(orgId, 1);
        }
    }
                if (!Strings.isNullOrEmpty(orgId)) {
                    if (orgs.containsKey(orgId)) {
                        Map<String, Counters> temp = orgs.get(orgId);
                        if (!temp.containsKey(counter1.getUserId())) {
                            temp.put(counter1.getUserId(), counter1);
                        }

                        orgs.remove(orgId);
                        orgs.put(orgId, temp);
                    } else {
                        Map<String, Counters> temp = new HashMap<String, Counters>();
                        temp.put(counter1.getUserId(), counter1);
                        orgs.put(orgId, temp);
                    }
                }

    if (!Strings.isNullOrEmpty(userId)) {
        if (userIdToUserName.containsKey(userId)) {
            List<Counters> list = userIdToUserName.get(userId);
            userIdToUserName.remove(userId);
            list.add(counter1);
            userIdToUserName.put(userId, list);
        } else {
            List<Counters> list = new ArrayList<Counters>();
            list.add(counter1);
            userIdToUserName.put(userId, list);
        }

        if (userCounter.containsKey(userId)) {
            int counter = userCounter.get(userId);
//                        userCounter.remove(userId);
            userCounter.put(userId, counter + 1);
        } else {
            userCounter.put(userId, 1);

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
//                if (counter1.getMethod().equals(METHOD))
    counters.add(counter1);
}
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

    private static final String [] FILE_HEADER_MAPPING = {"Account","Active","CreatedDate","Id","Name","OrganizationType","Server","SignupCountryIsoCode","Status"};

    public static Map<String, CSVRecord> nameMap(List<CSVRecord> records) {

        return Maps.uniqueIndex(records, c -> c.get(3).substring(0, ((c.get(3).length() > 3) ? c.get(3).length() - 3 : c.get(3).length())));
    }

    public static void main(String[] args) throws IOException {

        FileReader fileReader = null;

        CSVParser csvParser = null;

        CSVFormat format = CSVFormat.DEFAULT.withHeader(FILE_HEADER_MAPPING);

        List<Organization> orgs = new ArrayList<Organization>();
        fileReader = new FileReader("/Users/vtaneja/Downloads/WorkBenchQuery.csv");
        csvParser = new CSVParser(fileReader, format);
        List<CSVRecord> records =  csvParser.getRecords();

//        FileInputStream fis = new FileInputStream("/Users/vtaneja/Downloads/WorkBenchQuery.csv");
//        InputStreamReader isr = new InputStreamReader(fis);
//
//        //File csvData = new File("/Users/vtaneja/Downloads/WorkBenchQuery.csv");
//        CSVParser parser = CSVParser.parse(isr, CSVFormat.RFC4180);
//        List<CSVRecord> list = parser.getRecords();


        // Currently, the code is dependent on the placement of the fields in the CSV file.
        // Use the following query to get the file.
        // index=* `logRecordType(sclcm)` | fields *
        // index=* `logRecordType(sclcm)` earliest=-2h | fields logRecordType,method,orgId,name,userName,loginCsrfCookieVal,loginCsrfParamVal,theRest
//         index=* `logRecordType(sclcm)` earliest=-1h | fields logRecordType,method,orgId,name,userName,loginCsrfCookieVal,loginCsrfParamVal,theRest
        // index=* `logRecordType(sclcm)` 	earliest=-15m url!="/*" | fields method,postParam,queryString,url,userName,loginCsrfCookieVal,loginCsrfParamVal,theRest
//==>      index=* `logRecordType(sclcm)` 	earliest=-15m url!="/*" | fields logRecordType,theRest

        result = LogAnalysis.nameMap(records);
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

    private boolean isBrowser(final String userAgent) {
        if (Strings.isNullOrEmpty(userAgent)) return false;

        if (userAgent.toLowerCase().contains("firefox") || userAgent.toLowerCase().contains("chrome")
                || userAgent.toLowerCase().contains("chromium") || userAgent.toLowerCase().contains("safari")
                || userAgent.toLowerCase().contains("opera") || userAgent.toLowerCase().contains("msie")) return true;

        return false;
    }
}
