IOANNIS LAMPRINIDIS

Everything seems to be working succesfully according the specifications except the
retrasmission.
Things to point out:
1) For the 7th step it was not understood what exactly was asked so the program 
prints if the packet is TCP or UDP.
2) For the retransmission the program checks the sequence number of the current packet 
with the previous one and if it's lower then it is a retransmission.

question 9: Yes by cheking the sequence number of the TCP packet.
question 10: We cannot tell if a UDP packet is retransmitted, because this action is
not supported by the protocol.

gcc version: gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0

