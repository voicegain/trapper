// Copyright 2010 Resolvity Inc.
package com.resolvity.trapper;

import java.io.IOException;

import junit.framework.TestCase;

import org.snmp4j.CommunityTarget;
import org.snmp4j.MessageDispatcher;
import org.snmp4j.MessageDispatcherImpl;
import org.snmp4j.PDU;
import org.snmp4j.PDUv1;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.event.ResponseListener;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModel;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.Counter64;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.Variable;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;

/**
 * <code>TestSendTraps</code> TODO
 * @author justin.good
 */
public class TestSendTraps extends TestCase
{
    private static final long NANOS_TO_MILLIS = 1000000;
    private static OID RESOLVITY = new OID(new int[] {1, 3, 6, 1, 4, 1, 29449});
    private static final int TEST_ROUNDS = 100;

    public static OID makeOID(int aSub)
    {
        OID oid = (OID) RESOLVITY.clone();
        oid.append(aSub);
        return oid;
    }

    public void testV1next() throws IOException
    {
        System.out.println("test v1 getnext");

        Address targetAddress = GenericAddress.parse("udp:127.0.0.1/162");
        TransportMapping transport = new DefaultUdpTransportMapping();
        Snmp snmp = new Snmp(transport);

        // setting up target
        CommunityTarget target = new CommunityTarget();
        target.setCommunity(new OctetString("public"));
        target.setAddress(targetAddress);
        target.setRetries(2);
        target.setTimeout(1500);
        target.setVersion(SnmpConstants.version1);

        // creating PDU
        PDUv1 pdu = new PDUv1();
        pdu.setEnterprise(RESOLVITY);
        pdu.setType(PDU.GETNEXT);

        pdu.add(new VariableBinding(makeOID(1)));
        pdu.add(new VariableBinding(makeOID(2)));

        // sending request
        ResponseListener listener = new ResponseListener()
        {
            public void onResponse(ResponseEvent event)
            {
                // Always cancel async request when response has been received
                // otherwise a memory leak is created! Not canceling a request
                // immediately can be useful when sending a request to a broadcast
                // address.
                ((Snmp) event.getSource()).cancel(event.getRequest(), this);
                System.out.println("Received response PDU is: " + event.getResponse());
            }
        };

        snmp.send(pdu, target, null, listener);

    }

    public void testV1() throws IOException
    {
        //System.out.println("test v1 inform");

        Address targetAddress = GenericAddress.parse("udp:127.0.0.1/162");
        TransportMapping transport = new DefaultUdpTransportMapping();
        Snmp snmp = new Snmp(transport);

        // setting up target
        CommunityTarget target = new CommunityTarget();
        target.setCommunity(new OctetString("public"));
        target.setAddress(targetAddress);
        target.setRetries(2);
        target.setTimeout(1500);
        target.setVersion(SnmpConstants.version1);

        // creating PDU
        PDUv1 pdu = new PDUv1();
        pdu.setEnterprise(RESOLVITY);
        pdu.setType(PDU.V1TRAP);

        Variable stack = new OctetString("junit");
        Variable sid = new OctetString("123456789");
        Variable var1 = new OctetString("another string");
        Variable var2 = new Integer32(123);

        pdu.add(new VariableBinding(RESOLVITY, new OctetString("testV1")));
        pdu.add(new VariableBinding(makeOID(1), stack));
        pdu.add(new VariableBinding(makeOID(2), sid));
        pdu.add(new VariableBinding(makeOID(3), var1));
        pdu.add(new VariableBinding(makeOID(4), var2));

        // sending request
        ResponseListener listener = new ResponseListener()
        {
            public void onResponse(ResponseEvent event)
            {
                // Always cancel async request when response has been received
                // otherwise a memory leak is created! Not canceling a request
                // immediately can be useful when sending a request to a broadcast
                // address.
                ((Snmp) event.getSource()).cancel(event.getRequest(), this);
                System.out.println("Received response PDU is: " + event.getResponse());
            }
        };

        snmp.send(pdu, target, null, listener);
    }

    public void testSimpleSNMP() throws IOException
    {
        //System.out.println("test v1 simple trap");

        TransportMapping transport = new DefaultUdpTransportMapping();
        MessageDispatcher dispatch = new MessageDispatcherImpl();
        dispatch.addMessageProcessingModel(new MPv1());

        Address address = GenericAddress.parse("udp:127.0.0.1/162");
        OctetString community = new OctetString("public");

        PDU pdu = new PDUv1();
        pdu.setType(PDU.V1TRAP);

        Variable stack = new OctetString("junit");
        Variable sid = new OctetString("123456789");
        Variable var1 = new OctetString("another string");
        Variable var2 = new Integer32(123);

        pdu.add(new VariableBinding(RESOLVITY, new OctetString("testSimpleSNMP")));
        pdu.add(new VariableBinding(makeOID(1), stack));
        pdu.add(new VariableBinding(makeOID(2), sid));
        pdu.add(new VariableBinding(makeOID(3), var1));
        pdu.add(new VariableBinding(makeOID(4), var2));

        dispatch.sendPdu(transport, address, SnmpConstants.version1,
            SecurityModel.SECURITY_MODEL_SNMPv1, community.getValue(),
            SecurityLevel.NOAUTH_NOPRIV, pdu, false, null);
    }

    public void testRcTimeout() throws IOException
    {
        //System.out.println("test v1 RapidConnectTimeout");

        TransportMapping transport = new DefaultUdpTransportMapping();
        MessageDispatcher dispatch = new MessageDispatcherImpl();
        dispatch.addMessageProcessingModel(new MPv1());

        Address address = GenericAddress.parse("udp:127.0.0.1/162");
        OctetString community = new OctetString("public");

        PDU pdu = new PDUv1();
        pdu.setType(PDU.V1TRAP);

        Variable stack = new OctetString("junit");
        Variable body = new OctetString(
            "Load ICOMS Account: Get Account Details RapidConnect GetAccountDetails Failed:"
                + " JavaException: com.resolvity.runtime.rconnect.RapidConnectTimeout");

        pdu.add(new VariableBinding(makeOID(1), stack));
        pdu.add(new VariableBinding(RESOLVITY, body));

        dispatch.sendPdu(transport, address, SnmpConstants.version1,
            SecurityModel.SECURITY_MODEL_SNMPv1, community.getValue(),
            SecurityLevel.NOAUTH_NOPRIV, pdu, false, null);
    }

    public void testV2cTrap() throws IOException
    {
        //System.out.println("test v2c");

        Address targetAddress = GenericAddress.parse("udp:127.0.0.1/162");
        TransportMapping transport = new DefaultUdpTransportMapping();
        Snmp snmp = new Snmp(transport);
        transport.listen();

        // setting up target
        CommunityTarget target = new CommunityTarget();
        target.setCommunity(new OctetString("public"));
        target.setAddress(targetAddress);
        //target.setRetries(2);
        target.setRetries(0);
        target.setTimeout(1500);
        target.setVersion(SnmpConstants.version2c);

        // creating PDU
        PDU pdu = new PDU();
        //pdu.setType(PDU.INFORM);
        pdu.setType(PDU.TRAP);

        Variable var1 = new OctetString("testV2c");
        Variable var2 = new OctetString("another string");
        Variable var3 = new Integer32(123);
        Variable var4 = new Counter64(9999999999L);
        pdu.add(new VariableBinding(RESOLVITY));
        pdu.add(new VariableBinding(makeOID(1), var1));
        pdu.add(new VariableBinding(makeOID(2), var2));
        pdu.add(new VariableBinding(makeOID(3), var3));
        pdu.add(new VariableBinding(makeOID(4), var4));

        // sending request
        ResponseListener listener = new ResponseListener()
        {
            public void onResponse(ResponseEvent event)
            {
                // Always cancel async request when response has been received
                // otherwise a memory leak is created! Not canceling a request
                // immediately can be useful when sending a request to a broadcast
                // address.
                ((Snmp) event.getSource()).cancel(event.getRequest(), this);
                System.out.println("Received response PDU is: " + event.getResponse());
            }
        };

        snmp.send(pdu, target, null, listener);
    }

    public void testV2cInform() throws IOException
    {
        //System.out.println("test v2c");

        Address targetAddress = GenericAddress.parse("udp:127.0.0.1/162");
        TransportMapping transport = new DefaultUdpTransportMapping();
        Snmp snmp = new Snmp(transport);
        transport.listen();

        // setting up target
        CommunityTarget target = new CommunityTarget();
        target.setCommunity(new OctetString("public"));
        target.setAddress(targetAddress);
        target.setRetries(2);
        target.setTimeout(1500);
        target.setVersion(SnmpConstants.version2c);

        // creating PDU
        PDU pdu = new PDU();
        pdu.setType(PDU.INFORM);

        Variable var1 = new OctetString("testV2c");
        Variable var2 = new OctetString("another string");
        Variable var3 = new Integer32(123);
        Variable var4 = new Counter64(9999999999L);
        pdu.add(new VariableBinding(RESOLVITY));
        pdu.add(new VariableBinding(makeOID(1), var1));
        pdu.add(new VariableBinding(makeOID(2), var2));
        pdu.add(new VariableBinding(makeOID(3), var3));
        pdu.add(new VariableBinding(makeOID(4), var4));

        // sending request
        ResponseListener listener = new ResponseListener()
        {
            public void onResponse(ResponseEvent event)
            {
                // Always cancel async request when response has been received
                // otherwise a memory leak is created! Not canceling a request
                // immediately can be useful when sending a request to a broadcast
                // address.
                ((Snmp) event.getSource()).cancel(event.getRequest(), this);
                System.out.println("Received response PDU is: " + event.getResponse());
            }
        };

        snmp.send(pdu, target, null, listener);
    }

//    public void testV3() throws IOException
//    {
//        System.out.println("test v3");
//
//        USM usm = new USM(SecurityProtocols.getInstance(), new OctetString(MPv3
//            .createLocalEngineID()), 0);
//        SecurityModels.getInstance().addSecurityModel(usm);
//
//        Address targetAddress = GenericAddress.parse("udp:127.0.0.1/162");
//        TransportMapping transport = new DefaultUdpTransportMapping();
//
//        MessageDispatcher dispatch = new MessageDispatcherImpl();
//        OctetString localEngineID = new OctetString(MPv3.createLocalEngineID());
//        dispatch.addMessageProcessingModel(new MPv3(localEngineID.getValue()));
//        Snmp snmp = new Snmp(dispatch, transport);
//        transport.listen();
//
//        // setting up target
//        CommunityTarget target = new CommunityTarget();
//        target.setCommunity(new OctetString("public"));
//        target.setAddress(targetAddress);
//        target.setRetries(2);
//        target.setTimeout(1500);
//        target.setVersion(SnmpConstants.version3);
//
//
//        // creating PDU
//        PDU pdu = new ScopedPDU();
//        pdu.setType(PDU.TRAP);
//
//        Variable var1 = new OctetString("testV3");
//        Variable var2 = new OctetString("another string");
//        Variable var3 = new Integer32(123);
//        Variable var4 = new Counter64(9999999999L);
//        pdu.add(new VariableBinding(RESOLVITY));
//        pdu.add(new VariableBinding(makeOID(1), var1));
//        pdu.add(new VariableBinding(makeOID(2), var2));
//        pdu.add(new VariableBinding(makeOID(3), var3));
//        pdu.add(new VariableBinding(makeOID(4), var4));
//
//        // sending request
//        ResponseListener listener = new ResponseListener()
//        {
//            public void onResponse(ResponseEvent event)
//            {
//                // Always cancel async request when response has been received
//                // otherwise a memory leak is created! Not canceling a request
//                // immediately can be useful when sending a request to a broadcast
//                // address.
//                ((Snmp) event.getSource()).cancel(event.getRequest(), this);
//                System.out.println("Received response PDU is: " + event.getResponse());
//            }
//        };
//
//        snmp.send(pdu, target, null, listener);
//    }

    public void testForLeaksV1() throws Exception
    {
        testV1();
        System.out.print("gc");
        System.gc();
        System.out.print(".");
        System.gc();
        System.out.println(".");

        Runtime r = Runtime.getRuntime();
        System.out.println("max: " + r.maxMemory() + ", total: " + r.totalMemory()
            + ", free: " + r.freeMemory());

        final long start = System.nanoTime();
        for (int i = 0; i < TEST_ROUNDS; ++i)
        {
            if (i > 0 && i % 1000 == 0)
            {
                System.out.print("testForLeaksV1() " + i);
                System.gc();
                System.out.print(".");
                System.gc();
                System.out.println(".");
                System.out.println("max: " + r.maxMemory() + ", total: "
                    + r.totalMemory() + ", free: " + r.freeMemory());
            }
            testV1();
            Thread.sleep(10);
        }

        final double ellapsed = (System.nanoTime() - start) / NANOS_TO_MILLIS;
        System.out.println("...took " + ellapsed + "ms");

        System.out.print("gc");
        System.gc();
        System.out.print(".");
        System.gc();
        System.out.println(".");
        System.out.println("max: " + r.maxMemory() + ", total: " + r.totalMemory()
            + ", free: " + r.freeMemory());
    }

    public void testForLeaksSimpleSNMP() throws Exception
    {
        testSimpleSNMP();
        System.out.print("gc");
        System.gc();
        System.out.print(".");
        System.gc();
        System.out.println(".");

        Runtime r = Runtime.getRuntime();
        System.out.println("max: " + r.maxMemory() + ", total: " + r.totalMemory()
            + ", free: " + r.freeMemory());

        final long start = System.nanoTime();
        for (int i = 0; i < TEST_ROUNDS; ++i)
        {
            if (i > 0 && i % 1000 == 0)
            {
                System.out.print("testForLeaksSimpleSNMP() " + i);
                System.gc();
                System.out.print(".");
                System.gc();
                System.out.println(".");
                System.out.println("max: " + r.maxMemory() + ", total: "
                    + r.totalMemory() + ", free: " + r.freeMemory());
            }
            testSimpleSNMP();
            Thread.sleep(2000);
        }

        final double ellapsed = (System.nanoTime() - start) / NANOS_TO_MILLIS;
        System.out.println("...took " + ellapsed + "ms");

        System.out.print("gc");
        System.gc();
        System.out.print(".");
        System.gc();
        System.out.println(".");
        System.out.println("max: " + r.maxMemory() + ", total: " + r.totalMemory()
            + ", free: " + r.freeMemory());
    }

    public void testForLeaksV2cTrap() throws Exception
    {
        testV2cTrap();
        System.out.print("gc");
        System.gc();
        System.out.print(".");
        System.gc();
        System.out.println(".");

        Runtime r = Runtime.getRuntime();
        System.out.println("max: " + r.maxMemory() + ", total: " + r.totalMemory()
            + ", free: " + r.freeMemory());

        final long start = System.nanoTime();
        for (int i = 0; i < TEST_ROUNDS; ++i)
        {
            if (i > 0 && i % 100 == 0)
            {
                System.out.print("testForLeaksV2cTrap() " + i);
                System.gc();
                System.out.print(".");
                System.gc();
                System.out.println(".");
                System.out.println("max: " + r.maxMemory() + ", total: "
                    + r.totalMemory() + ", free: " + r.freeMemory());
            }
            testV2cTrap();
            Thread.sleep(10);
        }

        final double ellapsed = (System.nanoTime() - start) / NANOS_TO_MILLIS;
        System.out.println("...took " + ellapsed + "ms");

        System.out.print("gc");
        System.gc();
        System.out.print(".");
        System.gc();
        System.out.println(".");
        System.out.println("max: " + r.maxMemory() + ", total: " + r.totalMemory()
            + ", free: " + r.freeMemory());
    }

    public void testForLeaksV2cInform() throws Exception
    {
        testV2cInform();
        System.out.print("gc");
        System.gc();
        System.out.print(".");
        System.gc();
        System.out.println(".");

        Runtime r = Runtime.getRuntime();
        System.out.println("max: " + r.maxMemory() + ", total: " + r.totalMemory()
            + ", free: " + r.freeMemory());

        final long start = System.nanoTime();
        for (int i = 0; i < TEST_ROUNDS; ++i)
        {
            if (i > 0 && i % 100 == 0)
            {
                System.out.print("testForLeaksV2cInform() " + i);
                System.gc();
                System.out.print(".");
                System.gc();
                System.out.println(".");
                System.out.println("max: " + r.maxMemory() + ", total: "
                    + r.totalMemory() + ", free: " + r.freeMemory());
            }
            testV2cInform();
            Thread.sleep(10);
        }

        final double ellapsed = (System.nanoTime() - start) / NANOS_TO_MILLIS;
        System.out.println("...took " + ellapsed + "ms");

        System.out.print("gc");
        System.gc();
        System.out.print(".");
        System.gc();
        System.out.println(".");
        System.out.println("max: " + r.maxMemory() + ", total: " + r.totalMemory()
            + ", free: " + r.freeMemory());
    }

    public void testConsolidation() throws Exception
    {
        for (int i = 0; i < 150; ++i)
        {
            testRcTimeout();
            Thread.sleep(2000);
        }
    }
}
