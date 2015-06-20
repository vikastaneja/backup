/*
 * Copyright, 2004-2015, SALESFORCE.com
 * All Rights Reserved
 * Company Confidential
 */

package identity.util.httplibrary;

import java.io.IOException;
import java.net.*;
import java.util.ArrayList;
import java.util.List;
import identity.util.httplibrary.HttpUtility2.Method;
import com.google.common.base.Strings;

/**
 * This class implements common login operations with different forced login detection cookie and parameters
 *
 * @author vtaneja
 * @since 198
 */
public final class CommonLoginOperations {

    public static void RunAll(final String urlString, final String username, final String password, Method method) throws IOException, URISyntaxException {
        GotoUrl(urlString, username, password);
//         Login(urlString, username, password, method);
//         LoginMismatch(urlString, username, password, method);
//         LoginEmptyCookie(urlString, username, password, method);
//         LoginEmptyParam(urlString, username, password, method);
//         LoginBothEmpty(urlString, username, password, method);
//         LoginMissingCookie(urlString, username, password, method);
//         LoginMissingParam(urlString, username, password, method);
//         LoginMissingBoth(urlString, username, password, method);
    }

    private static void GotoUrl(final String urlString,final String username, final String password) throws IOException, URISyntaxException {
        if (Strings.isNullOrEmpty(urlString)) {
            throw new NullPointerException("Url is null or empty");
        }

        HttpUtility2 utility2 = new HttpUtility2.Builder(urlString, username, password).setAutoRedirection(false).method(Method.Get).build();
        utility2.navigate2();
    }

    private static void Login(final String urlString, final String username, final String password, Method method) throws IOException, URISyntaxException {
        if (Strings.isNullOrEmpty(urlString)) {
            throw new RuntimeException("Url string is either null or empty");
        }

        if (Strings.isNullOrEmpty(username) || Strings.isNullOrEmpty(password)) {
           throw new RuntimeException("Username or password is null or empty");
        }

        // Cookies
        HttpCookie cookie = new HttpCookie("QCQQ", "AAAAAAAA");
        cookie.setDomain(".salesforce.com");
        cookie.setPath("/");

        HttpUtility2 utility2 = new HttpUtility2.Builder(urlString, username, password)
                 .addCookie(cookie)
                 .addParameter("QCQQ", "AAAAAAAA")
                 .method(method)
                 .setAutoRedirection(true)
                 .build();

        try {
            utility2.navigate();
        } catch (IOException ex) {
            System.out.println("HTTP Error: " + ex.getLocalizedMessage());
        }

        List<HttpCookie> cookieList = new ArrayList<>();
        HttpCookie resultCookie = null;
        if (method == Method.Get) {
            resultCookie = new HttpCookie("QCQQR", "SS/" + method.toString() + "/null");
            cookieList.add(resultCookie);
        }


         utility2.validateCookies(cookieList);
    }

    private static void LoginMismatch(final String urlString, final String username, final String password, Method method) throws IOException, URISyntaxException {
        if (Strings.isNullOrEmpty(urlString)) {
            throw new RuntimeException("Url string is either null or empty");
        }

        if (Strings.isNullOrEmpty(username) || Strings.isNullOrEmpty(password)) {
            throw new RuntimeException("Username or password is null or empty");
        }

        HttpCookie cookie = new HttpCookie("QCQQ", "AAAAAAAA");
        cookie.setDomain(".salesforce.com");
        cookie.setPath("/");

        HttpUtility2 utility2 = new HttpUtility2.Builder(urlString, username, password)
                .addCookie(cookie)
                .addParameter("QCQQ", "BBBBBBBB")
                .method(method)
                .setAutoRedirection(true)
                .build();

        try {
            utility2.navigate();
        } catch (IOException ex) {
            System.out.println("HTTP Error: " + ex.getLocalizedMessage());
        }

        List<HttpCookie> cookieList = new ArrayList<>();
        HttpCookie resultCookie = new HttpCookie("QCQQR", "SS/" + method.toString() + "/null");
        cookieList.add(resultCookie);
        utility2.validateCookies(cookieList);
    }

    private static void LoginEmptyCookie(final String urlString, final String username, final String password, Method method) throws IOException, URISyntaxException {
        if (Strings.isNullOrEmpty(urlString)) {
            throw new RuntimeException("Url string is either null or empty");
        }

        if (Strings.isNullOrEmpty(username) || Strings.isNullOrEmpty(password)) {
            throw new RuntimeException("Username or password is null or empty");
        }

        HttpCookie cookie = new HttpCookie("QCQQ", "");
        cookie.setDomain(".salesforce.com");
        cookie.setPath("/");

        HttpUtility2 utility2 = new HttpUtility2.Builder(urlString, username, password)
                .addCookie(cookie)
                .addParameter("QCQQ", "AAAAAAAA")
                .method(method)
                .setAutoRedirection(true)
                .build();

        try {
            utility2.navigate();
        } catch (IOException ex) {
            System.out.println("HTTP Error: " + ex.getLocalizedMessage());
        }

        List<HttpCookie> cookieList = new ArrayList<>();
        HttpCookie resultCookie = new HttpCookie("QCQQR", "ES/" + method.toString() + "/null");
        cookieList.add(resultCookie);
        utility2.validateCookies(cookieList);
    }

    private static void LoginEmptyParam(final String urlString, final String username, final String password, Method method) throws IOException, URISyntaxException {
        if (Strings.isNullOrEmpty(urlString)) {
            throw new RuntimeException("Url string is either null or empty");
        }

        if (Strings.isNullOrEmpty(username) || Strings.isNullOrEmpty(password)) {
            throw new RuntimeException("Username or password is null or empty");
        }

        HttpCookie cookie = new HttpCookie("QCQQ", "AAAAAAAA");
        cookie.setDomain(".salesforce.com");
        cookie.setPath("/");

        HttpUtility2 utility2 = new HttpUtility2.Builder(urlString, username, password)
                .addCookie(cookie)
                .addParameter("QCQQ", "")
                .method(method)
                .setAutoRedirection(true)
                .build();

        try {
            utility2.navigate();
        } catch (IOException ex) {
            System.out.println("HTTP Error: " + ex.getLocalizedMessage());
        }

        List<HttpCookie> cookieList = new ArrayList<>();
        HttpCookie resultCookie = new HttpCookie("QCQQR", "SE/" + method.toString() + "/null");
        cookieList.add(resultCookie);
        utility2.validateCookies(cookieList);
    }

    private static void LoginBothEmpty(final String urlString, final String username, final String password, Method method) throws IOException, URISyntaxException {
        if (Strings.isNullOrEmpty(urlString)) {
            throw new RuntimeException("Url string is either null or empty");
        }

        if (Strings.isNullOrEmpty(username) || Strings.isNullOrEmpty(password)) {
            throw new RuntimeException("Username or password is null or empty");
        }

        HttpCookie cookie = new HttpCookie("QCQQ", "");
        cookie.setDomain(".salesforce.com");
        cookie.setPath("/");

        HttpUtility2 utility2 = new HttpUtility2.Builder(urlString, username, password)
                .addCookie(cookie)
                .addParameter("QCQQ", "")
                .method(method)
                .setAutoRedirection(true)
                .build();

        try {
            utility2.navigate();
        } catch (IOException ex) {
            System.out.println("HTTP Error: " + ex.getLocalizedMessage());
        }

        List<HttpCookie> cookieList = new ArrayList<>();
        HttpCookie resultCookie = new HttpCookie("QCQQR", "EE/" + method.toString() + "/null");
        cookieList.add(resultCookie);
        utility2.validateCookies(cookieList);
    }

    private static void LoginMissingCookie(final String urlString, final String username, final String password, Method method) throws IOException, URISyntaxException {
        if (Strings.isNullOrEmpty(urlString)) {
            throw new RuntimeException("Url string is either null or empty");
        }

        if (Strings.isNullOrEmpty(username) || Strings.isNullOrEmpty(password)) {
            throw new RuntimeException("Username or password is null or empty");
        }

//        HttpCookie cookie = new HttpCookie("QCQQ", "");
//        cookie.setDomain(".salesforce.com");
//        cookie.setPath("/");

        HttpUtility2 utility2 = new HttpUtility2.Builder(urlString, username, password)
//                .addCookie(cookie)
                .addParameter("QCQQ", "")
                .method(method)
                .setAutoRedirection(true)
                .build();

        try {
            utility2.navigate();
        } catch (IOException ex) {
            System.out.println("HTTP Error: " + ex.getLocalizedMessage());
        }

        List<HttpCookie> cookieList = new ArrayList<>();
        HttpCookie resultCookie = new HttpCookie("QCQQR", "ME/" + method.toString() + "/null");
        cookieList.add(resultCookie);
        utility2.validateCookies(cookieList);
    }

    private static void LoginMissingParam(final String urlString, final String username, final String password, Method method) throws IOException, URISyntaxException {
        if (Strings.isNullOrEmpty(urlString)) {
            throw new RuntimeException("Url string is either null or empty");
        }

        if (Strings.isNullOrEmpty(username) || Strings.isNullOrEmpty(password)) {
            throw new RuntimeException("Username or password is null or empty");
        }

        HttpCookie cookie = new HttpCookie("QCQQ", "");
        cookie.setDomain(".salesforce.com");
        cookie.setPath("/");

        HttpUtility2 utility2 = new HttpUtility2.Builder(urlString, username, password)
                .addCookie(cookie)
//                .addParameter("QCQQ", "")
                .method(method)
                .setAutoRedirection(true)
                .build();

        try {
            utility2.navigate();
        } catch (IOException ex) {
            System.out.println("HTTP Error: " + ex.getLocalizedMessage());
        }

        List<HttpCookie> cookieList = new ArrayList<>();
        HttpCookie resultCookie = new HttpCookie("QCQQR", "EM/" + method.toString() + "/null");
        cookieList.add(resultCookie);
        utility2.validateCookies(cookieList);
    }

    private static void LoginMissingBoth(final String urlString, final String username, final String password, Method method) throws IOException, URISyntaxException {
        if (Strings.isNullOrEmpty(urlString)) {
            throw new RuntimeException("Url string is either null or empty");
        }

        if (Strings.isNullOrEmpty(username) || Strings.isNullOrEmpty(password)) {
            throw new RuntimeException("Username or password is null or empty");
        }

//        HttpCookie cookie = new HttpCookie("QCQQ", "");
//        cookie.setDomain(".salesforce.com");
//        cookie.setPath("/");

        HttpUtility2 utility2 = new HttpUtility2.Builder(urlString, username, password)
//                .addCookie(cookie)
//                .addParameter("QCQQ", "")
                .method(method)
                .setAutoRedirection(true)
                .build();

        try {
            utility2.navigate();
        } catch (IOException ex) {
            System.out.println("HTTP Error: " + ex.getLocalizedMessage());
        }

        List<HttpCookie> cookieList = new ArrayList<>();
        HttpCookie resultCookie = new HttpCookie("QCQQR", "MM/" + method.toString() + "/null");
        cookieList.add(resultCookie);
        utility2.validateCookies(cookieList);
    }
}
