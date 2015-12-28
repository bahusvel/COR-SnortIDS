from cor.api import CORModule, Message
import socket
import os
import struct
import threading

ALERTMSG_LENGTH = 256
MTU = 1500


def eth_addr(a):
	b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (a[0], a[1], a[2], a[3], a[4], a[5])
	return b


class SocketSnort(CORModule):

	def socket_listener(self):
		while True:
			try:
				(datain, addr) = self.s.recvfrom(4096)
				(msg, ts_sec, ts_usec, caplen, pktlen, dlthdr, nethdr, transhdr, data, val, pkt) = struct.unpack(
					self.fmt, datain[:self.fmt_size])
				src = socket.inet_ntoa(pkt[nethdr + 12:nethdr + 16])
				dst = socket.inet_ntoa(pkt[nethdr + 16:nethdr + 20])
				mac = eth_addr(pkt[dlthdr:dlthdr + 6])
				msg = msg.rstrip(b"\0")
				message = Message("SNORT_ALERT", {"srcip": src,
				                                        "dstip": dst,
				                                        "dstmac": mac,
				                                        "message": msg,
				                                        "packet": pkt,
				                                        "timesec": ts_sec,
				                                        "timeusec": ts_sec,
				                                        "data": data,
				                                        "val": val})
				self.messageout(message)
			except struct.error as e:
				print("bad message? (msglen=%d): %s" % (len(datain), e.message))

	def __init__(self, **kwargs):
		super().__init__(**kwargs)
		self.socket_thread = threading.Thread(target=self.socket_listener)
		self.produces.append("SNORT_ALERT")
		# This format does NOT include the 'Event' struct which is the last element
		# of the _AlertPkt struct in src/output-plugins/spo_alert_unixsock.h
		# Thus, we must truncate the messages ('datain[:fmt_size]') before passing
		# them to struct.unpacket()
		self.s = socket.socket(socket.AF_UNIX,
		                       socket.SOCK_DGRAM)
		self.fmt = "%ds9I%ds" % (ALERTMSG_LENGTH, MTU)
		self.fmt_size = struct.calcsize(self.fmt)
		print("Starting socket")
		try:
			os.remove("/var/log/snort_alert")
		except OSError:
			pass
		self.s.bind("/var/log/snort_alert")
		self.socket_thread.start()
