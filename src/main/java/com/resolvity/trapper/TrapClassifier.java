// Copyright 2010 Resolvity Inc.
package com.resolvity.trapper;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.snmp4j.CommandResponder;
import org.snmp4j.CommandResponderEvent;
import org.snmp4j.PDU;
import org.snmp4j.smi.IpAddress;

/**
 * <code>TrapClassifier</code> responds to an incoming trap PDU by classifying it based on
 * our TrapGroups. We maintain what is essentially a white list (accept) and black list
 * (ignore) based on TrapGroups. Accepted traps are further processed and forwarded, while
 * ignored traps are... ignored.
 * @author justin.good
 */
public class TrapClassifier implements CommandResponder
{
    protected final Logger log = Logger.getLogger(getClass().getSimpleName());
    private final List<TrapGroup> accept;
    private final List<TrapGroup> ignore;

    // keeps track of all groups being classified
    // the date list stores the times of traps until they are sent
    private final Map<TrapGroup,List<Date>> active;
    // marks the moment a trap group consolidation started
    private final Map<TrapGroup,Date> consolidating;

    /**
     * @param aAccept List of TrapGroups that we explicitly accept
     * @param aIgnore List of TrapGroups that we explicitly ignore
     */
    public TrapClassifier(List<TrapGroup> aAccept, List<TrapGroup> aIgnore)
    {
        accept = Collections.unmodifiableList(aAccept);
        ignore = Collections.unmodifiableList(aIgnore);

        // the following maps must be synchronized on this
        active = new HashMap<TrapGroup,List<Date>>();
        consolidating = new HashMap<TrapGroup,Date>();

        new Consolidator(this).start();
    }

    /** {@inheritDoc} */
    public void processPdu(CommandResponderEvent aEvent)
    {
        InetAddress src = ((IpAddress) aEvent.getPeerAddress()).getInetAddress();
        PDU pdu = aEvent.getPDU();

        for (TrapGroup group : ignore)
        {
            if (group.matches(pdu, src))
            {
                if (log.isInfoEnabled())
                {
                    log.info("ignored, group: " + group.getName() + ", pdu: " + pdu);
                }
                aEvent.setProcessed(true);
                return;
            }
        }

        for (TrapGroup group : accept)
        {
            if (group.matches(pdu, src))
            {
                if (log.isDebugEnabled())
                {
                    log.debug("accepted, group: " + group.getName() + ", pdu: " + pdu);
                }

                if (group.hasSchedule())
                {
                    // keep track of the arrival time of the first pdu in a time frame
                    if (!consolidating.containsKey(group))
                    {
                        consolidating.put(group, new Date());
                    }

                    // Send out a digest as soon as the specified limit has been reached
                    // but no sooner than specified number of minutes after previous send
                    synchronized (group)
                    {
                        group.savePdu(pdu, src);

                        int diffMinutes = -1;
                        final Date lastSentTime = group.getLastSentTime();
                        if(lastSentTime == null)
                        {
                        	log.debug("No traps sent so far for group: "+group.getName());
                        }
                        else
                        {
	                        final Date now = new Date();
	                        diffMinutes = (int)((now.getTime() - lastSentTime.getTime())/60000L);
	                        log.debug("Time since last trap sent in group "+group.getName()+" is "+diffMinutes+" minutes");
                        }

                        if (group.limitReached())
                        {
                        	log.debug("Limit reached ("+group.getNumberOfTraps()+" > "+group.getLimit()+") , for: " + group.getName() + ", pdu: " + pdu);
                            if(lastSentTime == null // never sent before 
                            || diffMinutes >= group.getMinutes())
                            {
	                            group.sendDigest(lastSentTime==null?consolidating.get(group):lastSentTime);
	
	                            if (consolidating.containsKey(group))
	                            {
	                                consolidating.remove(group);
	                            }
                            }
                            else
                            {
                            	log.debug("\t"+diffMinutes+" minutes since last sent, too early to send, will wait till "+group.getMinutes()+"min elapsed: " + group.getName() + ", pdu: " + pdu);
                            }
                        }
                    }
                }
                else // no schedule
                {
                    if (!consolidating(group))
                    {
                        group.forward(pdu, src);
                    }
                }

                aEvent.setProcessed(true);
                return;
            }
        }
    }

    /**
     * Call sendConsolidated for all of our actively consolidating trap groups
     */
    private synchronized void sendAllConsolidated()
    {
        for (TrapGroup group : accept)
        {
            if (group.hasSchedule())
            {
                final Date now = new Date();
                
                // If we get at least one trap and it's time to send out a digest,
                // we'll then send out a digest.
                if (group.onSchedule(now))
                {
                    if (consolidating.containsKey(group))
                    {
                        Date start = consolidating.get(group);
                        group.sendDigest(start);
                        consolidating.remove(group);
                    }
                    group.markScheduleProcessed(now);
                }
            }
            else
            {
                if (consolidating.containsKey(group))
                {
                    sendConsolidated(group);
                }
            }
        }
    }

    /**
     * This method will only send the consolidated email if enough time has passed since
     * this group last sent one
     * @param aGroup TrapGroup which may send the consolidated email
     */
    private synchronized void sendConsolidated(TrapGroup aGroup)
    {
        final Date now = new Date();
        final Date start = consolidating.get(aGroup);
        final Date cutoff = getCutoffStart(now, aGroup);

        if (start != null && start.before(cutoff))
        {
            // we can send
            List<Date> list = active.get(aGroup);

            // end time is based on the window trailing the start time
            final Date end = getCutoffEnd(start, aGroup);

            if (log.isDebugEnabled())
            {
                log.debug("checking consolidation window for " + aGroup.getName() + " "
                        + start + " to " + end);
            }

            final int count = getWindowSize(start, end, list);
            if (count != 0)
            {
                aGroup.sendConsolidated(start, count);

                // now the end is the earliest thing we ever have to examine again
                int removable = getWindowSize(null, end, list);
                if (log.isInfoEnabled())
                {
                    log.info("sending consolidation of " + count + " for "
                            + aGroup.getName() + ", removing " + removable + " before "
                            + end);
                }
                list.subList(0, removable).clear();
            }

            if (count < aGroup.getLimit())
            {
                // stop consolidation
                log.debug("stopping consolidation of " + aGroup.getName());
                consolidating.remove(aGroup);
            }
            else
            {
                // consolidate from end onward next time
                consolidating.put(aGroup, end);
            }
        }
    }

    /**
     * This method considers two criteria:
     * <ol>
     * <li>were we already consolidating this group?
     * <li>based on current window, do we need to consolidate?
     * </ol>
     * @param aGroup
     * @return
     */
    private synchronized boolean consolidating(TrapGroup aGroup)
    {
        // mark group active and get the current trap time
        final Date latest = markActive(aGroup);

        // ensure there's any point in continuing
        final List<Date> list = active.get(aGroup);
        if (aGroup.getLimit() == 0)
        {
            return false; // we are definitely not going to consolidate
        }

        // if we are already consolidating, keep consolidating
        if (consolidating.containsKey(aGroup))
        {
            if (log.isDebugEnabled())
            {
                log.debug("continuing consolidation for " + aGroup.getName()
                        + ", list size " + list.size());
            }
            return true;
        }

        // check current window
        if (consolidateWindow(latest, aGroup))
        {
            // only count the very latest trap towards consolidation,
            // since items prior to this trap were forwarded individually
            consolidating.put(aGroup, latest);
            return true;
        }

        return false;
    }

    /**
     * @param aWindowEnd end time for window, inclusive
     * @param aGroup TrapGroup specifying window size and trap limit
     * @return true if consolidation is required
     */
    private synchronized boolean consolidateWindow(Date aWindowEnd, TrapGroup aGroup)
    {
        final List<Date> list = active.get(aGroup);
        final Date cutoff = getCutoffStart(aWindowEnd, aGroup);
        final int windowSize = getWindowSize(cutoff, aWindowEnd, list);

        // first we examine current window
        if (windowSize > aGroup.getLimit())
        {
            if (log.isDebugEnabled())
            {
                log.debug("consolidating " + aGroup.getName() + ": " + windowSize
                        + " between " + cutoff + " and " + aWindowEnd);
            }
            return true;
        }

        return false;
    }

    /**
     * @param aDate reference Date
     * @param aGroup TrapGroup which specified some number of minutes
     * @return Date before given date (by number of minutes in group)
     */
    private Date getCutoffStart(Date aDate, TrapGroup aGroup)
    {
        Calendar cal = new GregorianCalendar();
        cal.setTime(aDate);
        cal.add(Calendar.MINUTE, -aGroup.getMinutes());
        return cal.getTime();
    }

    /**
     * @param aDate reference Date
     * @param aGroup TrapGroup which specified some number of minutes
     * @return Date after to given date (by number of minutes in group)
     */
    private Date getCutoffEnd(Date aDate, TrapGroup aGroup)
    {
        Calendar cal = new GregorianCalendar();
        cal.setTime(aDate);
        cal.add(Calendar.MINUTE, aGroup.getMinutes());
        return cal.getTime();
    }

    /**
     * @param aStart start time, inclusive, if null then no lower limit
     * @param aEnd end time, inclusive, if null then no upper limit
     * @param aList ordered list of dates
     * @return count of dates in list within given range
     */
    private int getWindowSize(Date aStart, Date aEnd, List<Date> aList)
    {
        int count = 0;
        for (Date date : aList)
        {
            if (aEnd != null && date.after(aEnd))
            {
                break;
            }
            else if (aStart == null || !date.before(aStart))
            {
                ++count;
            }
        }
        return count;
    }

    /**
     * @param aGroup TrapGroup with activity
     */
    private synchronized Date markActive(TrapGroup aGroup)
    {
        if (!active.containsKey(aGroup))
        {
            active.put(aGroup, new ArrayList<Date>());
        }

        Date now = new Date();
        active.get(aGroup).add(now);
        return now;
    }

    private static class Consolidator extends Thread
    {
        private static final int SLEEP_INTERVAL_MS = 30000; // 30 seconds
        private final TrapClassifier parent;

        public Consolidator(TrapClassifier aParent)
        {
            parent = aParent;
            setDaemon(true);
            setName("Consolidator");
        }

        /** {@inheritDoc} */
        @Override
        public void run()
        {
            try
            {
                while (true)
                {
                    sleep(SLEEP_INTERVAL_MS);
                    parent.sendAllConsolidated();
                }
            }
            catch (InterruptedException ex)
            {
                parent.log.warn("Consolidator interrupted...");
            }
        }
    }
}
