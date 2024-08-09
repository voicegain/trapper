// Copyright 2010 Resolvity Inc.
package com.resolvity.trapper;

import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import com.resolvity.utility.file.ReadableProperties;

/**
 * <code>ClassifierFactory</code> TODO
 * @author justin.good
 */
public class ClassifierFactory
{
    /**
     * @param aProps ReadableProperties describing our groups
     * @return TrapClassifier object
     */
    public static TrapClassifier create(ReadableProperties aProps)
    {
        List<TrapGroup> accept = new ArrayList<TrapGroup>();
        for (String name : aProps.getStringList(null, "accept"))
        {
            accept.add(new TrapGroup(aProps, name));
        }

        List<TrapGroup> ignore = new ArrayList<TrapGroup>();
        for (String name : aProps.getStringList(null, "ignore"))
        {
            ignore.add(new TrapGroup(aProps, name));
        }

        URL primary = parsePrimary(aProps);
        if (primary != null)
        {
            return new SecondaryTrapClassifier(accept, ignore, primary);
        }

        return new TrapClassifier(accept, ignore);
    }

    /**
     * @param aProps Properties file which may specify a url under key "primary"
     * @return InetAddress of primary TrapCatcher, or null meaning this is primary
     */
    private static URL parsePrimary(ReadableProperties aProps)
    {
        String adr = aProps.getString(null, "primary", null);
        if (adr != null)
        {
            try
            {
                return new URL(adr);
            }
            catch (IOException ex)
            {
                throw new IllegalArgumentException("bad primary URL: " + adr, ex);
            }
        }
        return null;
    }
}
