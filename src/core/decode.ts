/**
 * 链路层/网络层/传输层解码器。
 * 目前覆盖水厂工控最常见的 Ethernet-II + IPv4 + TCP；VLAN(802.1Q) 剥标签。
 * 不支持的字段不报错，只留空，保证单帧异常不影响整包解析。
 */
import { macStr, ipStr, u16be } from './bytes';
import type { RawPacket } from './types';

const ETH_P_IPV4 = 0x0800;
const ETH_P_VLAN = 0x8100;
const IPPROTO_TCP = 6;

export function decodeEthernet(frame: Uint8Array, pkt: RawPacket, linkType: number): void {
  // LINKTYPE_ETHERNET=1；LINKTYPE_RAW=101（裸 IP，少见但顺手支持）
  if (linkType === 101) {
    decodeIp(frame, 0, pkt);
    return;
  }
  if (linkType !== 1) {
    pkt.error = `不支持的 LINKTYPE ${linkType}`;
    return;
  }
  if (frame.length < 14) {
    pkt.error = '以太网帧截断';
    return;
  }
  pkt.l2 = 'ethernet';
  pkt.dstMac = macStr(frame, 0);
  pkt.srcMac = macStr(frame, 6);
  let etherType = u16be(frame, 12);
  let l3Off = 14;

  // 嵌套 VLAN 标签
  while (etherType === ETH_P_VLAN && l3Off + 4 <= frame.length) {
    etherType = u16be(frame, l3Off + 2);
    l3Off += 4;
  }

  if (etherType !== ETH_P_IPV4) {
    pkt.error = `非 IPv4 以太网类型 0x${etherType.toString(16)}`;
    return;
  }
  decodeIp(frame, l3Off, pkt);
}

function decodeIp(frame: Uint8Array, off: number, pkt: RawPacket): void {
  if (frame.length < off + 20) {
    pkt.error = 'IP 头截断';
    return;
  }
  const ver = frame[off] >> 4;
  if (ver !== 4) {
    pkt.ipVer = ver === 6 ? 6 : undefined;
    pkt.error = ver === 6 ? 'IPv6 暂不解析' : `IP 版本异常 ${ver}`;
    return;
  }
  pkt.ipVer = 4;
  const ihl = (frame[off] & 0x0f) * 4;
  if (ihl < 20 || frame.length < off + ihl) {
    pkt.error = 'IPv4 IHL 非法';
    return;
  }
  const totalLen = u16be(frame, off + 2);
  pkt.ipProto = frame[off + 9];
  pkt.srcIp = ipStr(frame, off + 12);
  pkt.dstIp = ipStr(frame, off + 16);

  if (pkt.ipProto !== IPPROTO_TCP) return; // UDP/ICMP 等不进入重组
  decodeTcp(frame, off + ihl, ihl, totalLen, pkt);
}

function decodeTcp(
  frame: Uint8Array,
  off: number,
  ihl: number,
  ipTotalLen: number,
  pkt: RawPacket,
): void {
  if (frame.length < off + 20) {
    pkt.error = 'TCP 头截断';
    return;
  }
  pkt.srcPort = u16be(frame, off);
  pkt.dstPort = u16be(frame, off + 2);
  pkt.seq = u32beWrap(frame, off + 4);
  pkt.ack = u32beWrap(frame, off + 8);
  const dataOff = (frame[off + 12] >> 4) * 4;
  pkt.tcpFlags = frame[off + 13];
  if (dataOff < 20 || frame.length < off + dataOff) {
    pkt.error = 'TCP 数据偏移非法';
    return;
  }
  // 实际 TCP 载荷长度 = IP 总长 - IP 头 - TCP 头（比抓包 caplen 更准，处理尾填充）
  const tcpSegLen = Math.max(0, ipTotalLen - ihl - dataOff);
  const payloadOff = off + dataOff;
  const avail = frame.length - payloadOff;
  const payloadLen = Math.min(tcpSegLen, avail);
  if (payloadLen > 0) {
    pkt.payloadOffset = payloadOff;
    pkt.payloadLength = payloadLen;
  }
}

function u32beWrap(b: Uint8Array, o: number): number {
  return ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
}
