package com.tiao2.fastgithub;

import org.xbill.DNS.*;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;

public class DnsPacketHandler {

    public static String extractDomain(byte[] packet, int offset) {
        try {
            // 从偏移位置截取 DNS 消息
            int len = packet.length - offset;
            byte[] sub = new byte[len];
            System.arraycopy(packet, offset, sub, 0, len);
            Message query = new Message(sub);
            Record question = query.getQuestion();
            if (question != null) {
                return question.getName().toString();
            }
        } catch (IOException e) {
            // ignore
        }
        return null;
    }

    public static byte[] buildAResponse(DatagramPacket queryPacket, int queryLen, String ip) {
        try {
            byte[] data = queryPacket.getData();
            int off = queryPacket.getOffset();
            // 截取完整的 DNS 查询消息
            byte[] sub = new byte[queryLen];
            System.arraycopy(data, off, sub, 0, queryLen);
            Message query = new Message(sub);
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