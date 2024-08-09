// Copyright 2010 Resolvity Inc.
package com.resolvity.trapper;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;
import org.snmp4j.PDU;
import org.snmp4j.smi.Null;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.Variable;
import org.snmp4j.smi.VariableBinding;

import com.resolvity.utility.file.ReadableProperties;

/**
 * <code>TrapGroup</code> provides criteria for groups traps together. Each group has a
 * "limit" and "minutes", meaning the maximum number (limit) of traps to forward within a
 * given number of minutes (before consolidating).
 * <p>
 * Grouping is based on the incoming PDU or source IP address. The <code>match</code>
 * method returns true if the given PDU and source IP match this group's configuration.
 * Note that is no criteria are specified, everything matches.
 * <p>
 * If minutes or limit are unspecified, the following defaults are used:
 * <ul>
 * <li>minutes: 15</li>
 * <li>limit: 3</li>
 * </ul>
 * <p>
 * schedule is a comma-separated list of time at which a digest of a trap will be sent.
 * For example, 08:00, 12:00, 16:00. Note if both minutes and schedule are specified,
 * schedule will be used and a warning will be logged.
 * @author justin.good
 */
public class TrapGroup
{
    public static final int DEFAULT_MINUTES = 15;
    public static final int DEFAULT_LIMIT = 3;

    private final Logger log = Logger.getLogger(getClass().getSimpleName());
    private final String name;
    private final int minutes;
    private final int limit;
    private final OID varOid;
    private final Pattern varMatch;
    private final Pattern bodyFind;
    private final List<String> senders = new ArrayList<String>();
    private final Map<OID,String> rename = new HashMap<OID,String>();
    private final List<TrapForwarder> forwarders;
    private final List<String> schedules = new ArrayList<String>();
    private final SimpleDateFormat sdf2 = new SimpleDateFormat("MM-dd HH:mm");
    private int indexOfLastProcessedSchedule = -1;
    private DataHolder mostRecentTrap = new DataHolder();
    private AtomicInteger numberOfTraps = new AtomicInteger(0);
    private Date lastSentTime = null; // time when last trap from this group was sent

    /**
     * @param aProps ReadableProperties
     * @param aName our domain within the properties file
     */
    public TrapGroup(ReadableProperties aProps, String aName)
    {
        name = aName;
        minutes = aProps.getInt(aName, "minutes", DEFAULT_MINUTES);
        limit = aProps.getInt(aName, "limit", DEFAULT_LIMIT);

        senders.addAll(aProps.getStringList(aName, "sender"));
        forwarders = loadForwarders(aProps, aName);

        String oidStr = aProps.getString(aName, "var.oid", null);
        varOid = (oidStr != null) ? new OID(oidStr) : null;

        String regex = aProps.getString(aName, "var.regex", null);
        varMatch = (regex != null) ? Pattern.compile(regex) : null;

        String findStr = aProps.getString(aName, "find", null);
        bodyFind = (findStr != null) ? Pattern.compile(findStr) : null;

        String scheduleStr = aProps.getString(aName, "schedule", null);
        populateSchedules(scheduleStr);

        if (schedules.size() == 1)
        {
            log
                .warn(String
                    .format(
                            "[%s] The current implementation doesn't work with only one schedule per day.",
                            name));
        }

        Map<String,String> renameMap = aProps.getStringMap(aName, "rename");
        for (String key : renameMap.keySet())
        {
            OID oid = new OID(key);
            rename.put(oid, renameMap.get(key));
        }

        if (hasSchedule())
        {
            log.warn(String.format("[%s] schedule is used.", name));
        }

        log.info(this);
    }

    /**
     * @param aProps ReadableProperties
     * @param aName our domain within the properties file
     * @return List of TrapForwarders
     */
    private static List<TrapForwarder> loadForwarders(ReadableProperties aProps,
                                                      String aName)
    {
        List<TrapForwarder> list = new ArrayList<TrapForwarder>();

        for (int i = 0; i < 10; ++i)
        {
            String fwdName = aName + ".forward." + i;
            String template = aProps.getString(fwdName, "template", null);
            if (template != null)
            {
                list.add(new TrapForwarder(aProps, fwdName));
            }
        }
        return list;
    }

    /**
     * @return the limit
     */
    public int getLimit()
    {
        return limit;
    }

    /**
     * @return the minutes
     */
    public int getMinutes()
    {
        return minutes;
    }

    /**
     * @return the name
     */
    public String getName()
    {
        return name;
    }

    /**
     * @param aPdu PDU
     * @return each VariableBinding's value on a new line
     */
    public static String getBody(PDU aPdu)
    {
        StringBuilder str = new StringBuilder();
        for (int i = 0; i < aPdu.size(); ++i)
        {
            VariableBinding bind = aPdu.get(i);
            Variable var = bind.getVariable();
            if (!(var instanceof Null))
            {
                str.append(var).append("\n");
            }
        }
        return str.toString();
    }

    /**
     * Returned map will contain duplicate values (but unique keys) if renaming is used
     * @param aPdu PDU
     * @param aSender InetAddress (IP)
     * @return map from string format of OID (or renamed name) to variable value
     */
    public Map<String,String> getVarMap(PDU aPdu, InetAddress aSender)
    {
        StringBuilder body = new StringBuilder();
        StringBuilder remainder = new StringBuilder();

        Map<String,String> map = new HashMap<String,String>();
        for (int i = 0; i < aPdu.size(); ++i)
        {
            VariableBinding bind = aPdu.get(i);
            Variable var = bind.getVariable();
            if (!(var instanceof Null))
            {
                // always add the variable under the OID
                map.put(bind.getOid().toString(), var.toString());

                // optionally add it under a new name too
                String renamed = rename.get(bind.getOid());
                if (renamed != null)
                {
                    map.put(renamed, var.toString());
                }
                else
                {
                    // add non-renamed variables to "remainder" string
                    remainder.append(var).append("\n");
                }

                // but add all variables to body
                body.append(var).append("\n");
            }
        }

        // finally, add the sender and the entire body as their own variables
        map.put("name", name);
        map.put("body", body.toString());
        map.put("remainder", remainder.toString());
        map.put("sender", aSender.getHostName());

        return map;
    }

    /**
     * @param aPdu PDU
     * @param aSender InetAddress (IP)
     * @return name of group if we can classify it, otherwise null
     */
    public boolean matches(PDU aPdu, InetAddress aSender)
    {
        if (!matchesSender(aSender))
        {
            return false;
        }
        else if (!matchesVar(aPdu))
        {
            return false;
        }
        else if (!matchesFind(aPdu))
        {
            return false;
        }

        return true;
    }

    /**
     * Send our trap to all our email destinations
     * @param aPdu PDU
     * @param aSender InetAddress (IP)
     */
    public void forward(PDU aPdu, InetAddress aSender)
    {
        Map<String,String> map = getVarMap(aPdu, aSender);
        boolean sent = false;
        for (TrapForwarder fwd : forwarders)
        {
            if (log.isDebugEnabled())
            {
                log.debug(name + " sending " + aPdu + " to " + fwd);
            }

            fwd.send(map);
            sent = true;
        }
        if(sent)
        {
        	setLastSentTime(new Date());
        }
    }

    /**
     * @param aStart start of window we are consolidating
     * @param aCount count during consolidation window
     */
    public void sendConsolidated(Date aStart, int aCount)
    {
    	boolean sent = false;
        for (TrapForwarder fwd : forwarders)
        {
            if (log.isInfoEnabled())
            {
                log.info(name + " sending consolidation of " + aCount + " since "
                        + aStart + " to " + fwd);
            }

            fwd.sendConsolidated(name, aStart, aCount);
            sent = true;
        }
        if(sent)
        {
        	setLastSentTime(new Date());
        }
    }

    /**
     * @param aSender InetAddress
     * @return true if aSrc matches any of our senders, or we don't use senders
     */
    private boolean matchesSender(InetAddress aSender)
    {
        if (senders.isEmpty())
        {
            return true; // cannot fail
        }

        for (String sender : senders)
        {
            if (matchesAdr(aSender, sender))
            {
                return true;
            }
        }
        return false;
    }

    /**
     * @param aPdu PDU
     * @return true if bodyFind is not set, or bodyFind matches any substring in body
     */
    private boolean matchesFind(PDU aPdu)
    {
        if (bodyFind == null)
        {
            return true; // cannot fail
        }

        String body = getBody(aPdu);
        return bodyFind.matcher(body).find();
    }

    /**
     * @param aPdu
     * @return
     */
    private boolean matchesVar(PDU aPdu)
    {
        if (varOid == null)
        {
            return true; // cannot fail
        }

        for (int i = 0; i < aPdu.size(); ++i)
        {
            VariableBinding bind = aPdu.get(i);
            if (bind.getOid().equals(varOid))
            {
                // we found the OID... does varMatch pattern match entire value?
                if (varMatch != null)
                {
                    String value = bind.getVariable().toString();
                    return varMatch.matcher(value).matches();
                }

                // if no varMatch pattern was used, then the OID presence is enough
                return true;
            }
        }
        return false;
    }

    /**
     * @param aInet InetAddress
     * @param aHost string with host name or IP address, possibly with % wildcard
     * @return true if addresses match
     */
    private boolean matchesAdr(InetAddress aInet, String aHost)
    {
        if (aHost.contains("%"))
        {
            String prefix = aHost.substring(0, aHost.indexOf('%'));
            return aInet.getHostAddress().startsWith(prefix);
        }
        else
        {
            try
            {
                InetAddress host = InetAddress.getByName(aHost);
                return aInet.equals(host);
            }
            catch (UnknownHostException ex)
            {
                log.error("bad sender: " + aHost, ex);
                return false;
            }
        }
    }

    /** {@inheritDoc} */
    @Override
    public int hashCode()
    {
        return name.hashCode();
    }

    /** {@inheritDoc} */
    @Override
    public boolean equals(Object aObj)
    {
        if (aObj instanceof TrapGroup)
        {
            return ((TrapGroup) aObj).name.equals(name);
        }
        return false;
    }

    /** {@inheritDoc} */
    @Override
    public String toString()
    {
        StringBuilder str = new StringBuilder();
        str.append(name + " " + limit + "/" + minutes);

        if (!senders.isEmpty())
        {
            str.append(", sender: " + senders);
        }
        if (bodyFind != null)
        {
            str.append(", find: " + bodyFind);
        }
        if (varOid != null)
        {
            str.append(", var: " + varOid);
            if (varMatch != null)
            {
                str.append("=" + varMatch);
            }
        }

        if (hasSchedule())
        {
            str.append(", schedules:");
            for (String schedule : schedules)
            {
                str.append(" " + schedule);
            }
        }

        return str.toString();
    }

    public boolean hasSchedule()
    {
        return schedules.size() > 0;
    }

    /**
     * DO NOT USE. This is for test only.
     */
    public void setSchedules(List<String> list)
    {
        schedules.clear();
        schedules.addAll(list);
        Collections.sort(schedules);
    }

    /**
     * DO NOT USE. This is for test only.
     */
    public void setIndexOfLastProcessedSchedule(int index)
    {
        indexOfLastProcessedSchedule = index;
    }

    /**
     * Find the index of the closest schedule based on the specified date.
     * @param now Date
     * @return -1 if no schedule is defined. Note that schedules are sorted.
     */
    public int findIndexOfClosestSchedule(final Date now)
    {
        int indexOfClosestSchedule = -1;

        if (!hasSchedule())
        {
            return indexOfClosestSchedule;
        }

        String dateStr = null;
        Date from = null;
        Date to = null;
        final Calendar c = Calendar.getInstance();
        c.set(Calendar.SECOND, 0);
        c.set(Calendar.MILLISECOND, 0);
        for (int index = 0; index < schedules.size(); index++)
        {
            dateStr = schedules.get(index);
            c.set(Calendar.HOUR_OF_DAY, Integer.parseInt(dateStr.substring(0, 2)));
            c.set(Calendar.MINUTE, Integer.parseInt(dateStr.substring(3)));
            from = c.getTime();

            // Return the last schedule for any time before the first schedule of the day
            if (index == 0 && now.before(from))
            {
                indexOfClosestSchedule = schedules.size() - 1;
                break;
            }

            if (index < schedules.size() - 1)
            {
                dateStr = schedules.get(index + 1);
                c.set(Calendar.HOUR_OF_DAY, Integer.parseInt(dateStr.substring(0, 2)));
                c.set(Calendar.MINUTE, Integer.parseInt(dateStr.substring(3)));
                to = c.getTime();
            }
            else
            {
                c.add(Calendar.DAY_OF_YEAR, 1);
                c.set(Calendar.HOUR_OF_DAY, 0);
                c.set(Calendar.MINUTE, 0);
                to = c.getTime();
            }

            // Check if now is between from and to, including from
            if ((now.after(from) && now.before(to)) || now.getTime() == from.getTime())
            {
                indexOfClosestSchedule = index;
                break;
            }
        }

        return indexOfClosestSchedule;
    }

    /**
     * Set the schedule index to the next schedule
     * @return
     */
    public synchronized void markScheduleProcessed(Date now)
    {
        indexOfLastProcessedSchedule = findIndexOfClosestSchedule(now);

        if (log.isInfoEnabled())
        {
            if (schedules != null && indexOfLastProcessedSchedule >= 0
                    && indexOfLastProcessedSchedule < schedules.size())
                log.info(String.format("[%s] mark schedule %s processed. ", name,
                                       schedules.get(indexOfLastProcessedSchedule)));
        }
    }

    /**
     * Check if the specified time is on or past the current schedule.
     * @param Date
     * @return True if the specified time is on or past the current schedule.
     */
    public boolean onSchedule(Date now)
    {
        if (indexOfLastProcessedSchedule == -1)
        {
            return true;
        }

        final int indexOfClosestSchedule = findIndexOfClosestSchedule(now);
        return (indexOfClosestSchedule != indexOfLastProcessedSchedule);
    }

    public synchronized void savePdu(PDU aPdu, InetAddress aSender)
    {
        mostRecentTrap.setAPdu(aPdu);
        mostRecentTrap.setASender(aSender);
        numberOfTraps.incrementAndGet();
    }

    public synchronized void sendDigest(Date aStart)
    {
        if (mostRecentTrap.isEmpty() || aStart == null)
        {
            // nothing to send
            return;
        }

        final int count = numberOfTraps.get();
        final DataHolder dh = mostRecentTrap;
        Map<String,String> map = getVarMap(dh.getPdu(), dh.getSender());
        map.put("count", Integer.toString(count));
        map.put("start_date", sdf2.format(aStart));

        for (TrapForwarder fwd : forwarders)
        {
            if (log.isInfoEnabled())
            {
                log.info(String.format("[%s] sending a digest of %d since %s to %s",
                                       name, count, sdf2.format(aStart), fwd));
            }

            fwd.send(map);
        }

        mostRecentTrap.clear();
        numberOfTraps.set(0);
        setLastSentTime(new Date());
    }

    public boolean limitReached()
    {
        return numberOfTraps.get() >= limit;
    }
    
    /**
	 * @return the numberOfTraps
	 */
	public int getNumberOfTraps() {
		return numberOfTraps.get();
	}

	private void populateSchedules(String scheduleStr)
    {
        if (scheduleStr == null || scheduleStr.trim().length() == 0)
        {
            return;
        }

        final Pattern HHMM_PATTERN = Pattern.compile("^\\s*(\\d{2}\\:\\d{2})\\s*$");
        Matcher m = null;
        String schedule = null;
        final String[] items = scheduleStr.split(",");
        for (String item : items)
        {
            m = HHMM_PATTERN.matcher(item);
            if (m.matches())
            {
                schedule = m.group(1);

                // avoid duplicates
                if (!schedules.contains(schedule))
                {
                    schedules.add(schedule);
                }
                else
                {
                    log.warn(String.format("[%s] Ignore a duplicate schedule (%s).",
                                           name, schedule));
                }
            }
            else
            {
                log.error(String.format("[%s] The format of %s is invalid. HH:MM is expected. This item is ignored.", name, item));
            }
        }

        Collections.sort(schedules);
    }
	
	

    /**
	 * @return the lastSentTime
	 */
	public Date getLastSentTime() {
		return lastSentTime;
	}

	/**
	 * @param lastSentTime the lastSentTime to set
	 */
	public void setLastSentTime(Date lastSentTime) {
		this.lastSentTime = lastSentTime;
	}



	class DataHolder
    {
        private PDU aPdu;
        private InetAddress aSender;

        public DataHolder()
        {
        }

        public PDU getPdu()
        {
            return aPdu;
        }

        public InetAddress getSender()
        {
            return aSender;
        }

        public void setAPdu(PDU pdu)
        {
            aPdu = pdu;
        }

        public void setASender(InetAddress sender)
        {
            aSender = sender;
        }

        public boolean isEmpty()
        {
            return (aPdu == null && aSender == null);
        }

        public void clear()
        {
            aPdu = null;
            aSender = null;
        }
    }
}
