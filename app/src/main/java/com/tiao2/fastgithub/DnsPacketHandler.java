package com.tiao2.fastgithub;
import org.xbill.DNS.*;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
public class DnsPacketHandler {
    public static String extractDomain(byte[] packet, int offset) {
        try {
            Message query = new Message(packet, offset);
            Record question = query.getQuestion();
            if (question != null) {
                return question.getName().toString();
            }
        } catch (IOException e) {}
        return null;
    }
    public static byte[] buildAResponse(DatagramPacket queryPacket, int queryLen, String ip) {
        try {
            Message query = new Message(queryPacket.getData(), queryPacket.getOffset());
            Record question = query.getQuestion();
            if (question == null) return null;
            Name name = question.getName();
            int dnsClass = question.getDClass();
            Message response = new Message(query.getHeader().getID());
            response.getHeader().setFlag(Flags.QR);
            response.getHeader().setFlag(Flags.RA);
            response.getHeader().setRcode(Rcode.NOERROR);
            response.addRecord(question, Section.QUESTION);
            InetAddress addr = InetAddress.getByName(ip);
            Record answer = new ARecord(name, dnsClass, 300, addr);
            response.addRecord(answer, Section.ANSWER);
            return response.toWire();
        } catch (Exception e) {
            return null;
        }
    }
}
