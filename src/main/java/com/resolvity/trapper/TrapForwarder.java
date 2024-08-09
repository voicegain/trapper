// Copyright 2010 Resolvity Inc.
package com.resolvity.trapper;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.mail.Message;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import org.apache.log4j.Logger;

import com.resolvity.utility.file.ReadableProperties;
import com.resolvity.utility.file.ResourceLoader;
import com.resolvity.utility.velocity.StringProcessor;

/**
 * <code>TrapForwarder</code> applies a velocity template to a PDU and then emails it
 * somewhere. Note that the <b>first line</b> of the processed template becomes the
 * subject line.
 * @author justin.good
 */
public class TrapForwarder
{
    private final Logger log = Logger.getLogger(getClass().getSimpleName());
    private final List<String> addresses;
    private final List<String> smtpList;
    private final String template;
    private final String domain; // used for sent emails
    private final boolean noSubject;

    /**
     * @param aProps ReadableProperties
     * @param aName our domain within the properties file
     */
    public TrapForwarder(ReadableProperties aProps, String aName)
    {
        smtpList = new ArrayList<String>();
        smtpList.addAll(aProps.getStringList(null, "smtp"));
        if (smtpList.isEmpty())
        {
            smtpList.add("localhost");
        }

        addresses = aProps.getStringList(aName, "address");
        noSubject = aProps.getBoolean(aName, "noSubject", false);
        domain = aProps.getString(aName, "domain", "resolvity.com");
        
        try
        {
            String path = aProps.getString(aName, "template", null);
            template = ResourceLoader.loadTextResource(path).toString();
        }
        catch (IOException ex)
        {
            throw new RuntimeException("unable to load email template", ex);
        }
    }

    /**
     * @param aMap Map of string to string used for Velocity replacements
     * @return merged String, note first line is intended to be the subject
     */
    public String merge(Map<String,String> aMap)
    {
        return StringProcessor.process(template, aMap);
    }

    /**
     * @return empty Message object destined for our SMTP server
     */
    private Message initMessage(String aSmtp)
    {
        Properties props = new Properties();
        props.put("mail.smtp.host", aSmtp);

        Session session = Session.getInstance(props);
        return new MimeMessage(session);
    }

    /**
     * @param aMap Map of string to string used for Velocity replacements
     * @return true if message was sent
     */
    public boolean send(Map<String,String> aMap)
    {
        for (String smtp : smtpList)
        {
            try
            {
                send(smtp, aMap);
                return true; // return after first success
            }
            catch (Exception ex)
            {
                log.error("failed to send to " + addresses + " via " + smtp, ex);
            }
        }
        return false;
    }

    /**
     * @param aSmtp SMTP server address
     * @param aMap Map of string to string used for Velocity replacements
     * @throws Exception
     */
    private void send(String aSmtp, Map<String,String> aMap) throws Exception
    {
        Message msg = initMessage(aSmtp);
        String merged = merge(aMap);

        final String subject, body;
        if (noSubject)
        {
            subject = null;
            body = merged;
        }
        else
        {
            // subject is the first line
            String[] parts = merged.split("[\\r\\n]+", 2);
            subject = parts[0].trim();
            body = parts[1].trim();
        }

        String stack = aMap.get("stack");
        if (stack != null)
        {
            msg.setFrom(new InternetAddress(stack + "@" + domain, stack));
        }
        else
        {
            msg.setFrom(new InternetAddress("trap@" + domain));
        }

        for (String address : addresses)
        {
            InternetAddress to = new InternetAddress(address);
            msg.addRecipient(Message.RecipientType.TO, to);
        }

        if (subject != null)
        {
            msg.setSubject(subject);
        }
        msg.setContent(body, "text/plain");
        Transport.send(msg);
    }

    /**
     * @param aName group name
     * @param aStart start of window we are consolidating
     * @param aCount number of traps during this window
     * @return true if message was sent
     */
    public boolean sendConsolidated(String aName, Date aStart, int aCount)
    {
        for (String smtp : smtpList)
        {
            try
            {
                sendConsolidated(smtp, aName, aStart, aCount);
                return true; // return after first success
            }
            catch (Exception ex)
            {
                log.error("failed to send to " + addresses + " via " + smtp, ex);
            }
        }
        return false;
    }

    /**
     * @param aSmtp SMTP server address
     * @param aName group name
     * @param aStart start of window we are consolidating
     * @param aCount number of traps during this window
     */
    private void sendConsolidated(String aSmtp, String aName, Date aStart, int aCount)
        throws Exception
    {
        Message msg = initMessage(aSmtp);

        msg.setFrom(new InternetAddress("trap@" + domain));

        for (String address : addresses)
        {
            InternetAddress to = new InternetAddress(address);
            msg.addRecipient(Message.RecipientType.TO, to);
        }

        if (!noSubject)
        {
            msg.setSubject(aName + " " + aCount);
        }

        String body = aName + " " + aCount + " since " + aStart;
        msg.setContent(body, "text/plain");
        Transport.send(msg);
    }

    /** {@inheritDoc} */
    @Override
    public String toString()
    {
        return addresses.toString();
    }
}
