// Copyright 2010 Resolvity Inc.
package com.resolvity.trapper;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;

import org.snmp4j.MessageDispatcher;
import org.snmp4j.MessageDispatcherImpl;
import org.snmp4j.Snmp;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.smi.TcpAddress;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.transport.AbstractTransportMapping;
import org.snmp4j.transport.DefaultTcpTransportMapping;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.MultiThreadedMessageDispatcher;
import org.snmp4j.util.ThreadPool;

import com.resolvity.utility.file.ReadableProperties;

/**
 * <code>TrapCatcher</code> listens for traps on a particular address, then groups and
 * processes the traps based on our configuration file.
 * @author justin.good
 */
public class TrapCatcher
{
    private static final String DEFAULT_ADR = "udp://127.0.0.1:162";
    private static final int DEFAULT_UDP_PORT = 162;
    private static final int DEFAULT_ALIVE_PORT = 163;
    private static final int DEFAULT_THREADS = 2;

    private final ReadableProperties props;
    private final TrapperAlive alive;
    private final AbstractTransportMapping transport;
    private final int numThreads;

    /**
     * @param aPath name of our properties file
     * @throws IOException
     */
    public TrapCatcher(String aPath) throws IOException
    {
        props = new ReadableProperties(aPath, ',');
        numThreads = props.getInt(null, "threads", DEFAULT_THREADS);

        transport = parseTransport(props);
        
        int livePort = props.getInt(null, "liveness", DEFAULT_ALIVE_PORT);
        alive = new TrapperAlive(livePort);
    }

    /**
     * Listen for SNMP messages on our address
     * @throws IOException
     */
    public synchronized void listen() throws IOException
    {
        ThreadPool threadPool = ThreadPool.create("DispatcherPool", numThreads);
        MessageDispatcher dispatch = new MultiThreadedMessageDispatcher(threadPool,
            new MessageDispatcherImpl());

        // currently we only expect version 1 and 2 traps
        dispatch.addMessageProcessingModel(new MPv1());
        dispatch.addMessageProcessingModel(new MPv2c());

        Snmp snmp = new Snmp(dispatch, transport);
        snmp.addCommandResponder(new TrapLogger());
        snmp.addCommandResponder(ClassifierFactory.create(props));

        transport.listen();
        System.out.println("Listening on " + transport.getListenAddress());
        
        alive.start();
        System.out.println("Liveness available on " + alive.getPort());

        try
        {
            this.wait();
        }
        catch (InterruptedException ex)
        {
            Thread.currentThread().interrupt();
        }
        System.out.println("Exiting...");
    }

    /**
     * @param aProps Properties file which may have a key "address" with a url
     * @return SNMP4J AbstractTransportMapping based on parsed address
     */
    private static AbstractTransportMapping parseTransport(ReadableProperties aProps)
    {
        String adr = aProps.getString(null, "address", DEFAULT_ADR);

        try
        {
            URI uri = new URI(adr);
            InetAddress inet = InetAddress.getByName(uri.getHost());
            int port = uri.getPort();

            if (uri.getScheme().equalsIgnoreCase("udp"))
            {
                if (port == -1)
                {
                    port = DEFAULT_UDP_PORT;
                }
                UdpAddress udp = new UdpAddress(inet, port);
                return new DefaultUdpTransportMapping(udp);
            }
            else if (uri.getScheme().equalsIgnoreCase("tcp"))
            {
                if (port == -1)
                {
                    throw new IllegalArgumentException("port must be specified for TCP");
                }
                TcpAddress tcp = new TcpAddress(inet, port);
                return new DefaultTcpTransportMapping(tcp);
            }
            else
            {
                throw new IllegalArgumentException("unknown scheme: " + adr);
            }
        }
        catch (URISyntaxException ex)
        {
            throw new IllegalArgumentException("bad URI: " + adr, ex);
        }
        catch (IOException ex)
        {
            throw new IllegalArgumentException(adr, ex);
        }
    }

    public static void main(String[] args) throws IOException
    {
        TrapCatcher t = new TrapCatcher("trap.properties");
        t.listen();
    }

}
