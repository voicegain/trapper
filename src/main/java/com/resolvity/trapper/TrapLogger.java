// Copyright 2010 Resolvity Inc.
package com.resolvity.trapper;

import org.apache.log4j.Logger;
import org.snmp4j.CommandResponder;
import org.snmp4j.CommandResponderEvent;

/**
 * <code>TrapLogger</code> just prints out each PDU it receives.
 * @author justin.good
 */
public class TrapLogger implements CommandResponder
{
    private final Logger log = Logger.getLogger(getClass().getSimpleName());
    
    /** {@inheritDoc} */
    public void processPdu(CommandResponderEvent aEvent)
    {
        if (log.isInfoEnabled())
        {
            log.info(aEvent.getPDU() + " from " + aEvent.getPeerAddress());
        }
    }
}
