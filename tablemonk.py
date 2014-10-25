#!/usr/bin/env python2.7
# Name: tablemonk.py
# Author: Anoniem4l, irc.freenode.net
# Make sure you run it with sudo. Have fun firewalling.
import sys, os
 
# Global vars.
numbers = "0123456789"
 
 
def main():
  if len(sys.argv) == 1:
    print "## tablemonk v0.01, firewall defense and logging configurator."
    print "[*] Usage:\n   --sshsec [port]                       ;  Secures the specified SSH type of port for bruteforcing and DDOS attacks.\n"
    print "   --secddos [port] [hitcount] [seconds] ;  Secures the specified port for DDOS type of attacks. Hitcount means the number of connections of the individual, seconds is obvious.\n"
    print "   --synproxy [interface] [port]         ;  Applies the well-known SYNPROXY configuration which amplifies defense against SYN flood attacks.\n"
  else:
    for arg in enumerate(sys.argv):
     
      if arg[1] == '--sshsec':
        # Parameter verification.
        for i in sys.argv[arg[0]+1]:
          pas = False
          for number in numbers:
            if int(number) == int(i):
              pas = True
          if pas != True:
            print "Invalid argument after --sshsec."
            return
        # Performing SSH bruteforce defense configuration.
        # ------
        port = sys.argv[arg[0]+1]
        # DDOS/excessive bruteforce.
        os.system("iptables -A INPUT -p tcp -m tcp --dport %s -m state --state NEW -m recent --set --name SSH --rsource" %(port))
        os.system("iptables -A INPUT -p tcp -m tcp --dport %s -m recent --rcheck --seconds 30 --hitcount 4 --rttl --name SSH --rsource -j REJECT --reject-with tcp-reset" %(port))
        # Logging.
        os.system('iptables -A INPUT -p tcp -m tcp --dport %s -m recent --rcheck --seconds 30 --hitcount 3 --rttl --name SSH --rsource -j LOG --log-prefix "SSH brute force "' %(port))
        # --update.
        os.system("iptables -A INPUT -p tcp -m tcp --dport %s -m recent --update --seconds 30 --hitcount 3 --rttl --name SSH --rsource -j REJECT --reject-with tcp-reset" %(port))
        # Slow bruteforce defense.
        os.system("iptables -A INPUT -p tcp -m tcp --dport %s -m recent --rcheck --seconds 3600 --hitcount 20 --rttl --name SSH --rsource -j REJECT --reject-with tcp-reset" %(port))
        # Logging.
        os.system('iptables -A INPUT -p tcp -m tcp --dport %s -m recent --rcheck --seconds 3600 --hitcount 15 --rttl --name SSH --rsource -j LOG --log-prefix "SSH brute force "' %(port))
        # --update.
        os.system("iptables -A INPUT -p tcp -m tcp --dport %s -m recent --update --seconds 3600 --hitcount 15 --rttl --name SSH --rsource -j REJECT --reject-with tcp-reset" %(port))
     
      if arg[1] == '--secddos':
        if arg[0] + 3 >= len(sys.argv):
          print "Insufficient arguments after --secddos."
          return
        party = sys.argv[arg[0]+1] + sys.argv[arg[0]+2] + sys.argv[arg[0]+3]
        # Parameter verification.
        for i in party:
          pas = False
          for number in numbers:
            if int(number) == int(i):
              pas = True
          if pas != True:
            print "Invalid argument after --secddos."
            return
        # Performing anti-DDOS defense configuration.
        # --------
        port = sys.argv[arg[0]+1]
        name = "port_" + sys.argv[arg[0]+1]
        hitcount = sys.argv[arg[0]+2]
        seconds = sys.argv[arg[0]+3]
        os.system("iptables -A INPUT -p tcp -m tcp --dport %s -m state --state NEW -m recent --set --name %s --rsource" %(port, name))
        os.system("iptables -A INPUT -p tcp -m tcp --dport %s -m recent --rcheck --seconds %s --hitcount %s --rttl --name %s --rsource -j REJECT --reject-with tcp-reset" %(port, seconds, hitcount, name))
        # Logging.
        os.system('iptables -A INPUT -p tcp -m tcp --dport %s -m recent --rcheck --seconds %s --hitcount %s --rttl --name %s --rsource -j LOG --log-prefix "[%s] flood attempt: "' %(port, seconds, hitcount, name, name))
       
       
      if arg[1] == '--synproxy':
        if arg[0] + 2 >= len(sys.argv):
          print "Insufficient arguments after --synproxy."
        # DANGEROUS, no parameter verification, be careful with input.
        iface = sys.argv[arg[0]+1]
        port = sys.argv[arg[0]+2]
        # Dropping invalid packets before they reach the LISTEN socket.
        os.system("iptables -m state --state INVALID -j DROP")
        # SYNPROXY: PREROUTING.
        os.system("iptables -t raw -I PREROUTING -i %s -p tcp -m tcp --syn --dport %s -j CT --notrack" %(iface, port))
        # SYNPROXY target.
        os.system("iptables -A INPUT -i %s -p tcp -m tcp --dport %s -m state --state INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460" %(iface, port))
        # Trick to catch SYN-ACK floods, drop rest of state INVALID.
        os.system("iptables -A INPUT -i %s -p tcp -m tcp --dport %s -m state --state INVALID -j DROP" %(iface, port))
        # Strict conntrack hanlding to get unknown ACKs (from 3WHS) to be marked as INVALID state.
        os.system("sysctl -w net/netfilter/nf_conntrack_tcp_loose=0")
        # Enable TCP timestamping (SYN cookies use TCP options field).
        os.system("/sbin/sysctl -w net/ipv4/tcp_timestamps=1")
        # Conntrack entries tuning.
        os.system("/sbin/sysctl -w net/netfilter/nf_conntrack_max=2000000")
        # Adjusting hash bucket size.
        os.system("echo 2000000 > /sys/module/nf_conntrack/parameters/hashsize")
       
    print os.popen("iptables -L").read()
 
   
if __name__ == "__main__":
  main()
