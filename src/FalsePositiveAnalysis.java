import com.google.common.base.Strings;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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
public class FalsePositiveAnalysis { // extends Service {

    private class Counters {


        private final String method;
        private final String proxy;
        private final String cookie;
        private final String param;
        private final String name;


        private Counters () {
            param = null;
            cookie = null;
            proxy = null;
            method = null;
            name = null;
        }

        public Counters(String name, String method, String proxy, String cookie, String param) {
            this.name = name;

            this.method = method;

            this.proxy = proxy;

            this.cookie = cookie;

            this.param = param;
        }

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

    public FalsePositiveAnalysis(final String folderName) {
        this.folderName = folderName;
//        super(host);
    }

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


    // Using the format for bit array <method><cookie><param><proxy>


    private void analyzeFile(final String fileName) {

    }

    public void analyzeFiles() throws IOException {
        Files.walk(Paths.get(this.folderName)).forEach(filePath -> {
            if (Files.isRegularFile(filePath) && filePath.getFileName().toString().endsWith(".csv")) {
                try {
                    System.out.println("File: " + filePath.getFileName().toString());
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
            br = new BufferedReader(new FileReader("/Users/vtaneja/Downloads/test.csv"));
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
                if(sCurrentLine.contains(",sclcm,")) {
                    processLog(sCurrentLine);
                    str = sCurrentLine;
                }
                else
                    str += sCurrentLine;
            }
            processLog(str);

            System.out.println("----> total:  " + this.counters.size());
            System.out.println("----> total for POST: " + this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("POST")).count());

            System.out.println("----> total for GET: " + this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("GET")).count());

            System.out.println("----> total for POST with null XiProxy: " + this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("POST") && p.getProxy().equals("null")).count());

            System.out.println("----> total for POST with non null XiProxy: " + this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("POST") && !p.getProxy().equals("null")).count());
            System.out.println("----> total for GET with non null XiProxy: " + this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("GET") && !p.getProxy().equals("null")).count());

            System.out.println("----> total for GET with null XiProxy: " + this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("GET") && p.getProxy().equals("null")).count());
            System.out.println("----> total for GET with null cookie and null value: " + this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("GET") && p.getCookie().equals("null") && p.getParam().equals("null")).count());

            System.out.println("----> total for POST with cookie and null param: " + this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("POST") && !p.getCookie().equals("null") && p.getParam().equals("null")).count());
            System.out.println("----> total for POST with null cookie and null param: " + this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("POST") && p.getCookie().equals("null") && p.getParam().equals("null")).count());
            System.out.println("----> total for POST with cookie and param: " + this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("POST") && !p.getCookie().equals("null") && !p.getParam().equals("null")).count());

            System.out.println("----> Login names for cookie and param mismatch for HTTP POST");
            Stream<Counters> stream = this.counters.parallelStream().filter(p -> p.getMethod().toUpperCase().equals("POST") && !p.getCookie().equals("null") && !p.getParam().equals("null"));
            List<Counters> counterses = stream.collect(Collectors.<Counters>toList());
            System.out.println("----> Total orgs: " + orgsCounter.size());
            for (Counters counter : counterses) {
                System.out.print(counter.getName() + ", ");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void processLog(String logRecord) {
        try {
            if(!logRecord.isEmpty()) {
                logRecord = logRecord.replaceAll("," , " ");
                String category = "";
                String[] tokens = logRecord.split("`");

                String name = tokens[2];
                String method = tokens[5];
                String xiProxy = tokens[6];
                String cookie = tokens[9];
                String param = tokens[10].indexOf("\"") >= 0 ? tokens[10].substring(0, tokens[10].indexOf("\"")) : "";
                String orgId = tokens[21].trim();

                if (orgsCounter.containsKey(orgId)) {
                    int counter = orgsCounter.get(orgId);
                    orgsCounter.put(orgId, counter + 1);
                } else {
                    orgsCounter.put(orgId, 1);
                }

                counters.add(new Counters(name, method, xiProxy, cookie, param));

//                category = analyzeCSPEmailTemplateRecord(blockedUri, documentUri, violatedDirective);
                e_totalCount += 1;

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
        // index=* `logRecordType(sclcm)` earliest=-2h | fields method,orgId,loginCsrfCookieVal,loginCsrfParamVal,theRest

        FalsePositiveAnalysis fp = new FalsePositiveAnalysis("/Users/vtaneja/ForcedLogin");

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
