import java.util.Arrays;
import java.util.Scanner;
import java.io.*;

/**
 * Created by vtaneja on 6/28/15.
 */
public class TestMisc2 {
    String LongestWord(String str) {
        if (str == null || str.length() < 5) {
            return "false";
        }

        for (int i = 0; i < str.length() - 4; i++) {
            if ((str.charAt(i) == 'a' && str.charAt(i+4) == 'b')
                    || (str.charAt(i) == 'b' && str.charAt(i+4) == 'a')) return "true";
        }

        return "false";
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

//    public static void main (String[] args) {
//        // keep this function call here
//        Scanner s = new Scanner(System.in);
//        TestMisc2 c = new TestMisc2();
//        System.out.print(c.LongestWord("bdcba"));
//    }


    public static void main (String[] args) throws java.lang.Exception, IOException
    {


//        long startTime = System.currentTimeMillis();

//        generatePrimes();


        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
            String s;
            int totalInputs = 0;
            StringBuilder sb = new StringBuilder();


            // First line
             if ((s = in.readLine()) != null) {
                totalInputs = Integer.parseInt(s);
                if (totalInputs < 1) return;
            }

            // Iterate totalInputs
            while (totalInputs-- > 0) {
                if ((s = in.readLine()) != null) {
                    long startTime = System.currentTimeMillis();

                    String []se = s.split(" ");
                    if (se.length != 2) continue;
                    long start = Long.parseLong(se[0]);
                    long end = Long.parseLong(se[1]);
                    if (end - start > 100000) continue;
                    while (start <= end) {
                        if (isPrime(start))
                            sb.append(start).append("\n");

                        start++;
                    }

                    long endTime = System.currentTimeMillis();

                    System.out.println("That took " + (endTime - startTime) + " milliseconds");

                }

                sb.append("\n");
            }

            long st = System.currentTimeMillis();
            BufferedWriter log = new BufferedWriter(new OutputStreamWriter(System.out));

            log.write(sb.toString());
            log.flush();

            long et = System.currentTimeMillis();
            System.out.println("Printing took " + (et - st) + " milliseconds");

        } catch (NumberFormatException e) {
            return;
        }
    }

    private static boolean isPrime(long n) {
//        if (n <= 1) return false;
//        if (n % 2 == 0) return false;
//        long temp = ((long)java.lang.Math.ceil(java.lang.Math.sqrt((long)n)));
//        for (long i = 2; i <= temp; i++) {
//            if (n % i == 0) return false;
//        }
//
//        return true;

        if (n <= 1)
            return false;
        else if (n <= 3)
            return true;
        else if (n % 2 == 0 || n % 3 == 0)
            return false;

        int i = 5;
        while (i*i <= n) {
            if (n % i == 0 || n %(i + 2) == 0)
                return false;
            i = i + 6;
        }
        return true;
    }

    private static boolean []b = new boolean[1000000000];

    private static void generatePrimes() {
        for (long i = 2; i < 1000000000;) {
            int factor = 2;
            for (long j = i*factor; j < 1000000000; j = i * factor) {
                b[(int)j] = true;
                factor++;
            }

            i++;
            while (i < 1000000000 && b[(int)i] != false) i++;
        }
    }

}
