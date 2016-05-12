import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.io.*;

class TestMisc {
  String LongestWord(String sen) {

      // Approach is start parsing the string.
      // Get the word, get its length. If the length is "more than" current max, store the word into max word
      // At the end, return max word.

      int lmax = 0;
      String max = "";
      for (int i = 0; i < sen.length();) {
          String s = getNextWord(sen, i);
          if (s == null) {
              return max;
          }

          if (lmax < s.length()) {
              lmax = s.length();
              max = s;
          }

          i += s.length();
      }
    return max;

  }

    private static String getNextWord(final String s, int current) {
        if (current < 0 || current >= s.length()) {
            return null;
        }

        int curr = current;
        while (curr < s.length() && !String.valueOf(s.charAt(curr)).matches("[a-zA-Z]")) curr++;

        if (curr >= s.length()) {
            return null;
        }

        StringBuilder stb = new StringBuilder();
        while (curr < s.length() && String.valueOf(s.charAt(curr)).matches("[a-zA-Z]")) {
            stb.append(s.charAt(curr));
            curr++;
        }

        return stb.toString();
    }

  public static void main (String[] args) throws Exception {
      String domString = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><env:Envelope xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><env:Header /><env:Body><EchoString xmlns=\"urn:dotnet.callouttest.soap.sforce.com\"><input>Hello</input></EchoString></env:Body></env:Envelope>";
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      DocumentBuilder builder = factory.newDocumentBuilder();
      InputSource is = new InputSource(new StringReader(domString));
      Document doc = builder.parse(is);
      XPathFactory xPathfactory = XPathFactory.newInstance();
      XPath xpath = xPathfactory.newXPath();
      XPathExpression expr = xpath.compile("//input");

      String str = (String)expr.evaluate(doc, XPathConstants.STRING);
      SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

      sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
      String inputString = "2015-12-18 08:35:21";

      Date date = null;
      try {
          date = sdf.parse(inputString);
      } catch (ParseException e) {
          System.out.println(e.getMessage());
      }
      System.out.println("in milliseconds: " + date.getTime());
      Date toDate = Calendar.getInstance().getTime();
      Calendar cal=Calendar.getInstance();
      cal.setTime(date);
      cal.add(Calendar.DATE, 7);
      if(cal.getTime().compareTo(toDate)<0){
          System.out.println("More than 7 days");
      }

      // keep this function call here
    Scanner  s = new Scanner(System.in);

      TestMisc c = new TestMisc();
    System.out.print(c.LongestWord("This@@@@ is true length$."));
  }

}








  