// Copyright 2010 Resolvity Inc.
package com.resolvity.trapper;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;

import org.apache.log4j.Logger;

/**
 * <code>TrapperAlive</code> listens on a given TCP port for simple, http requests
 * checking whether we are alive or not, and just responds with the current time (to
 * ensure non-cached responses).
 * @author justin.good
 */
public class TrapperAlive extends Thread
{
    private final Logger log = Logger.getLogger(getClass().getSimpleName());
    private final ServerSocket server;

    public TrapperAlive(int aPort)
    {
        setName(getClass().getSimpleName());
        try
        {
            server = new ServerSocket(aPort); // this will fail if we don't own the port
        }
        catch (IOException ex)
        {
            log.error("unable to open TrapperAlive on port " + aPort + " - "
                + ex.getMessage());
            throw new RuntimeException(ex);
        }
    }

    /**
     * @return port to which we are listening
     */
    public int getPort()
    {
        return server.getLocalPort();
    }

    /** {@inheritDoc} */
    @Override
    public void run()
    {
        String ok = "HTTP/1.1 200 OK\r\n";
        String cache = "Cache-Control: no-cache\r\n";
        String type = "Content-Type: text/plain\r\n";
        String length = "Content-Length: ";
        String headers = ok + cache + type + length;

        while (!isInterrupted())
        {
            Socket client = null;
            OutputStream out = null;
            InputStream in = null;
            try
            {
                client = server.accept();

                // some clients require us to read the request line
                in = client.getInputStream();
                Scanner scanner = new Scanner(in);
                String req = scanner.nextLine();

                if (log.isDebugEnabled())
                {
                    log.debug(client.getInetAddress() + " " + req);
                }

                String body = String.valueOf(System.currentTimeMillis());
                String message = headers + body.length() + "\r\n\r\n" + body;

                System.out.println(message);

                out = client.getOutputStream();
                out.write(message.getBytes());
            }
            catch (IOException ex)
            {
                log.error("error listening for TrapperAlive messages", ex);
            }
            finally
            {
                close(in, out, client);
            }
        }

        try
        {
            server.close();
        }
        catch (IOException ex)
        {
            log.error("error shutting down TrapperAlive", ex);
        }
    }

    /**
     * @param aIn InputStream, closed first if non-null
     * @param aOut OutputStream, closed second if non-null
     * @param aClient client Socket, closed third if non-null
     */
    private void close(InputStream aIn, OutputStream aOut, Socket aClient)
    {
        try
        {
            if (aIn != null)
            {
                aIn.close();
            }
            if (aOut != null)
            {
                aOut.close();
            }
            if (aClient != null)
            {
                aClient.close();
            }
        }
        catch (IOException ex)
        {
            log.error("error closing resource", ex);
        }
    }
}
