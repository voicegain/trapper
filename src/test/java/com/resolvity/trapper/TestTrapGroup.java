// Copyright 2006 Resolvity Inc.
package com.resolvity.trapper;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import com.resolvity.utility.file.ReadableProperties;

import junit.framework.TestCase;

/**
 * <code>TestTrapGroup</code> TODO
 * @author yungwei
 */
public class TestTrapGroup extends TestCase
{
    public void testFindIndexOfClosestSchedule_OneSchedule()
    {
        int index = 0;
        final List<String> schedules = new ArrayList<String>();
        schedules.add("12:01");

        final ReadableProperties rp = new ReadableProperties(
                "/server/Trapper/trap.properties", ',');
        final TrapGroup group = new TrapGroup(rp, "test");
        group.setSchedules(schedules);

        final Calendar date = Calendar.getInstance();
        for (int i = 0; i <= 11; i++)
        {
            date.set(Calendar.HOUR_OF_DAY, i);
            index = group.findIndexOfClosestSchedule(date.getTime());
            assertEquals(0, index);
        }

        for (int i = 12; i <= 23; i++)
        {
            date.set(Calendar.HOUR_OF_DAY, i);
            index = group.findIndexOfClosestSchedule(date.getTime());
            assertEquals(0, index);
        }
    }

    public void testFindIndexOfClosestSchedule_TwoSchedules()
    {
        final List<String> schedules = new ArrayList<String>();
        schedules.add("06:00");
        schedules.add("12:00");

        final ReadableProperties rp = new ReadableProperties(
                "/server/Trapper/trap.properties", ',');
        final TrapGroup group = new TrapGroup(rp, "test");
        group.setSchedules(schedules);

        final Calendar date = Calendar.getInstance();

        // return 0 for any time before 12:01
        for (int i = 0; i <= 5; i++)
        {
            date.set(Calendar.HOUR_OF_DAY, i);
            int index = group.findIndexOfClosestSchedule(date.getTime());
            assertEquals(schedules.size() - 1, index);
        }

        for (int i = 6; i <= 11; i++)
        {
            date.set(Calendar.HOUR_OF_DAY, i);
            int index = group.findIndexOfClosestSchedule(date.getTime());
            assertEquals(0, index);
        }

        for (int i = 12; i <= 23; i++)
        {
            date.set(Calendar.HOUR_OF_DAY, i);
            int index = group.findIndexOfClosestSchedule(date.getTime());
            assertEquals(1, index);
        }

    }

    public void testFindIndexOfClosestSchedule_MultipleSchedules()
    {
        final List<String> schedules = new ArrayList<String>();
        schedules.add("06:00");
        schedules.add("12:00");
        schedules.add("18:00");

        final ReadableProperties rp = new ReadableProperties(
                "/server/Trapper/trap.properties", ',');
        final TrapGroup group = new TrapGroup(rp, "test");
        group.setSchedules(schedules);

        final Calendar date = Calendar.getInstance();

        for (int i = 0; i <= 5; i++)
        {
            date.set(Calendar.HOUR_OF_DAY, i);
            int index = group.findIndexOfClosestSchedule(date.getTime());
            assertEquals(schedules.size() - 1, index);
        }

        // return 0 for any time between 0600 and 12:00
        for (int i = 6; i <= 11; i++)
        {
            date.set(Calendar.HOUR_OF_DAY, i);
            int index = group.findIndexOfClosestSchedule(date.getTime());
            assertEquals(0, index);
        }

        for (int i = 12; i <= 17; i++)
        {
            date.set(Calendar.HOUR_OF_DAY, i);
            int index = group.findIndexOfClosestSchedule(date.getTime());
            assertEquals(1, index);
        }

        for (int i = 19; i <= 23; i++)
        {
            date.set(Calendar.HOUR_OF_DAY, i);
            int index = group.findIndexOfClosestSchedule(date.getTime());
            assertEquals(2, index);
        }
    }

    public void testFindIndexOfClosestSchedule_OnExactSchedules()
    {
        final List<String> schedules = new ArrayList<String>();
        schedules.add("06:00");
        schedules.add("12:00");
        schedules.add("18:00");

        final ReadableProperties rp = new ReadableProperties(
                "/server/Trapper/trap.properties", ',');
        final TrapGroup group = new TrapGroup(rp, "test");
        group.setSchedules(schedules);

        final Calendar date = Calendar.getInstance();
        date.set(Calendar.MINUTE, 0);
        date.set(Calendar.SECOND, 0);
        date.set(Calendar.MILLISECOND, 0);
        int index = 0;

        // assuming we are done with 06:00 schedule
        group.setIndexOfLastProcessedSchedule(0);
        date.set(Calendar.HOUR_OF_DAY, 12);
        index = group.findIndexOfClosestSchedule(date.getTime());
        assertEquals(1, index);

        // assuming we are done with 12:00 schedule
        group.setIndexOfLastProcessedSchedule(1);
        date.set(Calendar.HOUR_OF_DAY, 18);
        index = group.findIndexOfClosestSchedule(date.getTime());
        assertEquals(2, index);

        // assuming we are done with yesterday's 18:00 schedule
        group.setIndexOfLastProcessedSchedule(2);
        date.set(Calendar.HOUR_OF_DAY, 6);
        index = group.findIndexOfClosestSchedule(date.getTime());
        assertEquals(0, index);
    }

    public void testOnSchedule()
    {
        boolean onSchedule = false;
        final List<String> schedules = new ArrayList<String>();
        schedules.add("06:00");
        schedules.add("12:00");
        schedules.add("18:00");

        final ReadableProperties rp = new ReadableProperties(
                "/server/Trapper/trap.properties", ',');
        final TrapGroup group = new TrapGroup(rp, "test");
        group.setSchedules(schedules);

        final Calendar date = Calendar.getInstance();

        group.setIndexOfLastProcessedSchedule(-1);

        // always return true when indexOfLastProcessedSchedule is set to -1
        for (int i = 0; i <= 23; i++)
        {
            date.set(Calendar.HOUR_OF_DAY, i);
            onSchedule = group.onSchedule(date.getTime());
            assertEquals(true, onSchedule);
        }

        // when indexOfLastProcessedSchedule is set to 0
        // any time between 0000 to 0600 is not on schedule
        group.setIndexOfLastProcessedSchedule(0);
        for (int i = 0; i <= 5; i++)
        {
            date.set(Calendar.HOUR_OF_DAY, i);
            onSchedule = group.onSchedule(date.getTime());
            assertEquals(true, onSchedule);
        }

        // any time between 0600 to 1200 is not on schedule
        for (int i = 6; i <= 11; i++)
        {
            date.set(Calendar.HOUR_OF_DAY, i);
            onSchedule = group.onSchedule(date.getTime());
            assertEquals(false, onSchedule);
        }

        // any time between 1200 and 1800 is on schedule
        for (int i = 12; i <= 17; i++)
        {
            date.set(Calendar.HOUR_OF_DAY, i);
            onSchedule = group.onSchedule(date.getTime());
            assertEquals(true, onSchedule);
        }

        // when indexOfLastProcessedSchedule is set to 1
        group.setIndexOfLastProcessedSchedule(1);

        // any time between 0000 to 0500 is on schedule
        for (int i = 0; i <= 5; i++)
        {
            date.set(Calendar.HOUR_OF_DAY, i);
            onSchedule = group.onSchedule(date.getTime());
            assertEquals(true, onSchedule);
        }

        // any time between 1200 to 1800 is not on schedule
        for (int i = 12; i <= 17; i++)
        {
            date.set(Calendar.HOUR_OF_DAY, i);
            onSchedule = group.onSchedule(date.getTime());
            assertEquals(false, onSchedule);
        }

        // any time between 1800 and 0000 is on schedule
        for (int i = 18; i <= 23; i++)
        {
            date.set(Calendar.HOUR_OF_DAY, i);
            onSchedule = group.onSchedule(date.getTime());
            assertEquals(true, onSchedule);
        }

        // when indexOfLastProcessedSchedule is set to 2
        group.setIndexOfLastProcessedSchedule(2);
        // any time between 1800 and 0000 is not on schedule
        for (int i = 18; i <= 23; i++)
        {
            date.set(Calendar.HOUR_OF_DAY, i);
            onSchedule = group.onSchedule(date.getTime());
            assertEquals(false, onSchedule);
        }

        for (int i = 0; i <= 5; i++)
        {
            date.set(Calendar.HOUR_OF_DAY, i);
            onSchedule = group.onSchedule(date.getTime());
            assertEquals(false, onSchedule);
        }

        for (int i = 6; i <= 11; i++)
        {
            date.set(Calendar.HOUR_OF_DAY, i);
            onSchedule = group.onSchedule(date.getTime());
            assertEquals(true, onSchedule);
        }
    }
}
