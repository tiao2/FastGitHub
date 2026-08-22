package com.tiao2.fastgithub;
import org.xbill.DNS.*;
import java.io.*;
import java.net.*;
public class DnsPacketHandler {
    public static String extractDomain(byte[] packet, int offset) {
        try { Message q = new Message(packet, offset); Record qr = q.getQuestion(); if (qr != null) return qr.getName().toString(); } catch (IOException e) {}
        return null;
    }
    public static byte[] buildAResponse(DatagramPacket qp, int qlen, String ip) {
        try {
            Message q = new Message(qp.getData(), qp.getOffset());
            Record qr = q.getQuestion(); if (qr == null) return null;
            Message resp = new Message(q.getHeader().getID());
            resp.getHeader().setFlag(Flags.QR); resp.getHeader().setFlag(Flags.RA); resp.getHeader().setRcode(Rcode.NOERROR);
            resp.addRecord(qr, Section.QUESTION);
            Record ans = new ARecord(qr.getName(), qr.getDClass(), 300, InetAddress.getByName(ip));
            resp.addRecord(ans, Section.ANSWER);
            return resp.toWire();
        } catch (Exception e) { return null; }
    }
}
