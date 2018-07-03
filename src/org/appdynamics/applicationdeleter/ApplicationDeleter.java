/*
   Copyright 2017 AppDynamics LLC

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
package org.appdynamics.applicationdeleter;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.Reader;
import java.net.URI;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;

import org.apache.commons.cli.BasicParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.apache.http.message.BasicHeader;
import org.apache.http.ssl.SSLContextBuilder;
import org.appdynamics.appdrestapi.RESTAccess;
import org.appdynamics.appdrestapi.data.Application;
import org.appdynamics.appdrestapi.data.MetricDatas;
import org.appdynamics.appdrestapi.data.Tier;
import org.appdynamics.appdrestapi.data.Tiers;
import org.appdynamics.appdrestapi.util.TimeRange;
import org.appdynamics.appdrestapi.util.TimeRangeHelper;

/**
 * This program can be run from the command line and it will delete all the apps as long as they have seen no calls 
 * and have no agents reporting within the last N days.
 * 
 * @author john.aronson
 *
 */
public class ApplicationDeleter
{

	private static final int OUTPUT_INDENT = 4;
	private static final int OUTPUT_WIDTH = 80;
	private static final String APPLICATION_LINE = "java -jar ApplicationDeleter.jar";
	private static final String OPTION_QMARK = "?";
	private static final String HELP_HEADER = "This program can be run from the command line and it will delete all "
			+ "the apps that match the regex expression as long as they have seen no calls and have no agents "
			+ "reporting within the last N days.";
	private static final String OPTION_HELP = "help";
	private static final String OPTION_USE_HTTPS = "useHttps";
	private static final String OPTION_S = "s";
	private static final String OPTION_DAYS = "days";
	private static final String OPTION_REGEX = "regex";
	private static final String OPTION_COOKIES = "cookies";
	private static final String OPTION_PASSWD = "passwd";
	private static final String OPTION_ACCT = "acct";
	private static final String OPTION_USER = "user";
	private static final String OPTION_PORT = "port";
	private static final String OPTION_HOST = "host";
	private static final String OPTION_D = "d";
	private static final String OPTION_R = "r";
	private static final String OPTION_C = "c";
	private static final String OPTION_W = "w";
	private static final String OPTION_A = "a";
	private static final String OPTION_U = "u";
	private static final String OPTION_P = "p";
	private static final String OPTION_H = "h";
	private static final String URL_FORMAT_DELETE_APPLICATION = 
			"http%s://%s:%s/controller/restui/allApplications/deleteApplication";
	private static final String OVERALL_APPLICATION_PERFORMANCE_CALLS_PER_MINUTE = 
			"Overall Application Performance|Calls per Minute";
	private static final String user="admin";
	private static final String passwd="Appd-admin";
	private static final String account="customer1";
	
	private static Logger logger = Logger.getLogger(ApplicationDeleter.class.getName());
	
	private CommandLine commandLine;
	private Options options;
	
	/**
	 * @param args
	 */
	public static void main(String[] args)
	{
		ApplicationDeleter deleter = null;
		try 
		{
			deleter = new ApplicationDeleter(args);
			int result = deleter.run();
			if(result != 0) 
				System.err.println("Error detected while running report! See the logs for more info...");
		} catch (ApplicationDeleterException ade)
		{
			System.err.println(ade.getMessage());
			deleter.printUsage(System.err);
			System.exit(1);
		} catch (Exception e) 
		{
			e.printStackTrace(System.err);
			System.exit(1);
		}
	}

	private ApplicationDeleter(String[] args) throws ParseException 
	{
		options = new Options();
		options.addOption(OPTION_A, OPTION_ACCT, true, "license account to authenticate on the controller, default: customer1");
		options.addOption(OPTION_C, OPTION_COOKIES, true, "cookies file that contains a current browser session id. "
				+ "Login to the controller manually using a browser. Then use a browser extension like 'cookies.txt' "
				+ "to download the cookies into a file.");
		options.addOption(OPTION_D, OPTION_DAYS, true, "days back to check history, this program will check the application "
				+ "history and it will not delete applications that show calls or connected agents within the "
				+ "history check period");
		options.addOption(OPTION_H, OPTION_HOST, true, "controller host name");
		options.addOption(OPTION_P, OPTION_PORT, true, "controller port");
		options.addOption(OPTION_R, OPTION_REGEX, true, "regex expression to match against application names, this program "
				+ "will attempt to delete matching application names");
		options.addOption(OPTION_S, OPTION_USE_HTTPS, false, "use https to contact controller, default: false");
		options.addOption(OPTION_U, OPTION_USER, true, "user account to authenticate on the controller");
		options.addOption(OPTION_W, OPTION_PASSWD, true, "user password to authenticate on the controller");
		options.addOption(OPTION_QMARK, OPTION_HELP, false, "this help message");

		CommandLineParser clp = new BasicParser();
		commandLine = clp.parse(options, args, true);		
	}

	private int run() throws Exception 
	{
		if(commandLine.hasOption(OPTION_HELP) ||commandLine.hasOption(OPTION_QMARK))
		{
			printHelp(System.out);
			return 0;
		}
		
		String controllerHost= null;
		if(commandLine.hasOption(OPTION_H))
			controllerHost = commandLine.getOptionValue(OPTION_H);
		if(commandLine.hasOption(OPTION_HOST))
			controllerHost = commandLine.getOptionValue(OPTION_HOST);
		String port= null;
		if(commandLine.hasOption(OPTION_P))
			port = commandLine.getOptionValue(OPTION_P);
		if(commandLine.hasOption(OPTION_PORT))
			port = commandLine.getOptionValue(OPTION_PORT);
		final boolean useSSL = commandLine.hasOption(OPTION_S) || commandLine.hasOption(OPTION_USE_HTTPS);
		String user= null;
		if(commandLine.hasOption(OPTION_U))
			user = commandLine.getOptionValue(OPTION_U);
		if(commandLine.hasOption(OPTION_USER))
			user = commandLine.getOptionValue(OPTION_USER);		
		String account= "customer1";
		if(commandLine.hasOption(OPTION_A))
			account = commandLine.getOptionValue(OPTION_A);
		if(commandLine.hasOption(OPTION_ACCT))
			account = commandLine.getOptionValue(OPTION_ACCT);
		String passwd=null;
		if(commandLine.hasOption(OPTION_W))
			passwd = commandLine.getOptionValue(OPTION_W);
		if(commandLine.hasOption(OPTION_PASSWD))
			passwd = commandLine.getOptionValue(OPTION_PASSWD);
		Pattern regex = null;
		if(commandLine.hasOption(OPTION_R))
			regex = Pattern.compile(commandLine.getOptionValue(OPTION_R));
		if(commandLine.hasOption(OPTION_REGEX))
			regex = Pattern.compile(commandLine.getOptionValue(OPTION_REGEX));
		String cookiesPath = null;
		if(commandLine.hasOption(OPTION_C))
			cookiesPath = commandLine.getOptionValue(OPTION_C);
		if(commandLine.hasOption(OPTION_COOKIES))
			cookiesPath = commandLine.getOptionValue(OPTION_COOKIES);
		
		//in hours
		int checkInterval = 24;
		if(commandLine.hasOption(OPTION_D))
			checkInterval = 24 * Integer.parseInt(commandLine.getOptionValue(OPTION_D));
		if(commandLine.hasOption(OPTION_DAYS))
			checkInterval = 24 * Integer.parseInt(commandLine.getOptionValue(OPTION_DAYS));

		if(controllerHost == null || port == null || user == null || passwd == null || cookiesPath == null)
		{
			throw new ApplicationDeleterException("ERROR: not enough parameters were supplied.");
		}

		/*
		 This will create the instance of the RESTAccess which is able to execute REST calls.
		 If the controller is single tenant the account is 'customer1'.
		 */
		RESTAccess access=new RESTAccess(controllerHost,port,useSSL,user,passwd,account);


		// To get the list of applications all you need to run the following.

		//logger.info(access.getApplications());
		logger.info("fetching applications...");
		
		List<Application> deleteApps = new ArrayList<Application>();

		
		List<Application> applications = access.getApplications().getApplications(); 
		for (int i = 0; i < applications.size(); i++)
		{
			//logger.info(String.format("[%d] %s", app.getId(), name)); 
			Application app = applications.get(i);
			String name = app.getName();
			//check for name matching regex
			if(regex.matcher(name).matches())
			{
				//check for recent traffic
				TimeRange range = TimeRangeHelper.getLastXHours(checkInterval);
				MetricDatas datas = access.getRESTGenericMetricQuery(name, OVERALL_APPLICATION_PERFORMANCE_CALLS_PER_MINUTE, 
					range.getStart(), range.getEnd(), true);
				//logger.info(datas);
				if(!datas.hasNoValues() && datas.getFirstMetricValues().getSingleValue().getSum() > 0)
				{
					logger.info(String.format("skipping %s because it had seen calls within the last %d hours", name, checkInterval));
					continue;
				}
				
				Tiers tiers = access.getTiersForApplication(name);
				////check for agents reporting in tiers
				
				boolean agentsReporting = false;
				for (Iterator<Tier> it = tiers.getTiers().iterator(); it.hasNext();)
				{
					Tier tier = (Tier) it.next();
					datas = access.getRESTGenericMetricQuery(name, 
						String.format("Application Infrastructure Performance|%s|Agent|App|Availability", tier.getName()), 
						range.getStart(), range.getEnd(), true);
					//logger.info(datas);
					if(!datas.hasNoValues() && datas.getFirstMetricValues().getSingleValue().getSum() > 0)
					{
						agentsReporting = true;
						continue;
					}
				}
				if(agentsReporting)
					logger.info(String.format("skipping %s because it had seen had agents report within the last %d hours", name, checkInterval));
				else
					deleteApps.add(app);	
			}
		}
		
		logger.info("Applications to be deleted:");
		for (Application app : deleteApps)
		{
			logger.info(String.format("\t[%d] %s", app.getId(), app.getName()));
		}
		
		System.out.println("\nContinue to the delete phase (y/n)?");
		Reader in = new InputStreamReader(System.in);
		int response = in.read();
		
		if('y' != response)
		{
			System.out.println("Skipping the delete phase.");
			System.exit(0);
		}
		
		String urlString = String.format(URL_FORMAT_DELETE_APPLICATION, 
			(useSSL ? OPTION_S : ""), controllerHost, port );

        for (Iterator<Application> it = deleteApps.iterator(); it.hasNext();)
		{
			Application app = (Application) it.next();			
			try
			{
				deleteApp(urlString, app, cookiesPath);
			} catch (Exception e)
			{
				logger.severe("Error while deleting application: " +e.getMessage());
			}
		}

        return 0;
	}

	private void printUsage(OutputStream str)
	{
		PrintWriter err = new PrintWriter(new OutputStreamWriter(str));
		HelpFormatter helpFormatter = new HelpFormatter();
		helpFormatter.printUsage(err , OUTPUT_WIDTH, APPLICATION_LINE, options);
		err.close();
	}

	private void printHelp(OutputStream str)
	{
		PrintWriter out = new PrintWriter(new OutputStreamWriter(str));
		HelpFormatter helpFormatter = new HelpFormatter();
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		printUsage(baos);
		helpFormatter.printHelp(out, OUTPUT_WIDTH, baos.toString().replaceAll("\n", "").replaceAll("\\s+", " "), 
			HELP_HEADER, options, OUTPUT_INDENT, OUTPUT_INDENT, null);
		out.close();
	}

	private static void deleteApp(String urlString, Application app, String cookiesPath) throws Exception
	{
			URI uri = new URI(urlString);
			CredentialsProvider credsProvider = new BasicCredentialsProvider();
			credsProvider.setCredentials(
				    new AuthScope(uri.getHost(), uri.getPort()), 
				    new UsernamePasswordCredentials(user+"@"+account, passwd));
			
			BasicCookieStore cookieStore = new BasicCookieStore();
			Header csrfHeader = null;
			
			BufferedReader input = new BufferedReader(new FileReader(cookiesPath));
			String line = input.readLine();
			while(line != null)
			{			
				String splitLine[] = line.split("\\t");
				if(splitLine.length > 6 && !line.startsWith("#") && splitLine[0].equals(uri.getHost()))
				{
					BasicClientCookie cookie = new BasicClientCookie(splitLine[5], splitLine[6]);
					cookie.setDomain(splitLine[0]);
					cookie.setPath(splitLine[2]);
					cookieStore.addCookie(cookie);
					if("X-CSRF-TOKEN".equals(splitLine[5]))
					{
						csrfHeader = new BasicHeader(splitLine[5], splitLine[6]);
					}
				}
				line = input.readLine();
			}
			input.close();
			
			BasicClientCookie cookie = new BasicClientCookie("ad-remember-user", user);
			cookie.setDomain(uri.getHost());
			cookie.setPath("/");
			cookieStore.addCookie(cookie);
			
			cookie = new BasicClientCookie("ad-remember-account", account);
			cookie.setDomain(uri.getHost());
			cookie.setPath("/");
			cookieStore.addCookie(cookie);
			
			cookie = new BasicClientCookie("ad-remember-user-account", "true");
			cookie.setDomain(uri.getHost());
			cookie.setPath("/");
			cookieStore.addCookie(cookie);

		    HttpClientBuilder builder = HttpClientBuilder.create();
		    builder.setDefaultCookieStore(cookieStore);
		    builder.setDefaultCredentialsProvider(credsProvider);
		    if("https".equals(uri.getScheme()))
		    {
		    	SSLContext sslContext = SSLContextBuilder
		                .create()
		                .loadTrustMaterial(new TrustSelfSignedStrategy())
		                .build();
		    	HostnameVerifier allowAllHosts = new NoopHostnameVerifier();
		    	SSLConnectionSocketFactory connectionFactory = new SSLConnectionSocketFactory(sslContext, allowAllHosts);
		    	builder.setSSLSocketFactory(connectionFactory);
		    }

			HttpClient client = builder.build();
		    
			HttpPost post = new HttpPost(uri);
			
			post.setEntity(new StringEntity(Integer.toString(app.getId())));
			
			post.setHeader(csrfHeader);
   			post.setHeader(new BasicHeader("Content-type", "application/json"));
			post.setHeader(new BasicHeader("Accept", "application/json, text/plain, */*"));
			
			HttpResponse response = client.execute(post);
			logger.fine("\nSending 'POST' request to URL : " + urlString);
			logger.fine("Post parameters : " + post.getEntity());
			logger.fine("Response Code : " + response.getStatusLine().getStatusCode());
			
			if(response.getStatusLine().getStatusCode() != 204)
			{
				logger.info(String.format("Bad result [%d] while deleting application: [%d]%s", 
						response.getStatusLine().getStatusCode(), app.getId(), app.getName()));				
			}else
				logger.info(String.format("deleted application: [%d] %s", app.getId(), app.getName()));
	}
	
	@SuppressWarnings("serial")
	public class ApplicationDeleterException extends Exception
	{
		public ApplicationDeleterException(String msg)
		{
			super(msg);
		}
	}
}
