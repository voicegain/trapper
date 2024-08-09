// Copyright 2010 Resolvity Inc.
package com.resolvity.trapper;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;

import org.snmp4j.CommandResponderEvent;

/**
 * <code>SecondaryTrapClassifier</code> assumes it's just supposed to listen to traps and
 * do nothing to handle them, unless the master trapper is unavailable.
 * @author justin.good
 */
public class SecondaryTrapClassifier extends TrapClassifier
{
    private final URL primary;
    private boolean usePrimary;
    private Date lastCheck;
    private int checkSeconds;

    /**
     * @param aAccept List of TrapGroups that we explicitly accept
     * @param aIgnore List of TrapGroups that we explicitly ignore
     * @param aPrimary URI of the trapper we should defer to
     */
    public SecondaryTrapClassifier(List<TrapGroup> aAccept,
                                   List<TrapGroup> aIgnore,
                                   URL aPrimary)
    {
        super(aAccept, aIgnore);
        primary = aPrimary;
    }

    /** {@inheritDoc} */
    @Override
    public void processPdu(CommandResponderEvent aEvent)
    {
        if (!usePrimary())
        {
            if (log.isInfoEnabled())
            {
                log.info("secondary: processing " + aEvent.getPDU());
            }
            super.processPdu(aEvent);
        }
        else
        {
            aEvent.setProcessed(true);
        }
    }

    /**
     * @return true if we should defer to primary
     */
    private boolean usePrimary()
    {
        Calendar cal = new GregorianCalendar();
        cal.add(Calendar.SECOND, -checkSeconds); // now - checkSeconds

        if (lastCheck == null || lastCheck.before(cal.getTime()))
        {
            usePrimary = primaryIsAlive();
            lastCheck = new Date(); // now
        }

        return usePrimary;
    }

    private boolean primaryIsAlive()
    {
        try
        {
            HttpURLConnection conn = (HttpURLConnection) primary.openConnection();
            conn.setDoOutput(false);
            
            int code = conn.getResponseCode();
            if (code == 200)
            {
                return true;
            }
            log.warn("primary gave non-200 response: " + code);
        }
        catch (IOException ex)
        {
            log.warn("error contacting primary: " + ex.getMessage());
        }
        return false;
    }
}
