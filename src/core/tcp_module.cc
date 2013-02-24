#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <ctime>
#include <cstdlib>
#include <iostream>

#include "Minet.h"
#include "tcpstate.h"
#include "tcp.h"

using std::cout;
using std::endl;
using std::cerr;
using std::string;

//Prototype
void createPacket(Packet &packet, ConnectionToStateMapping<TCPState>& constate, int dataLen, int signal, unsigned int seq, unsigned int ack);
void testPacket(Packet &packet);//test use only
unsigned int generateISN(void);
//My signal representation for createPacket();
const int SIG_SYN_ACK = 0;
const int SIG_ACK = 1;
const int SIG_SYN = 2;
const int SIG_FIN = 3;

int main(int argc, char *argv[])
{
  MinetHandle mux, sock;//Multiplexor and Socket

  ConnectionList<TCPState> clist;

  MinetInit(MINET_TCP_MODULE);//initialize tcp module

  //MinetIsModuleConfig(): Check to see if lower module is on the run time configuration
  //if its in configuration, issue MinetConnect() for this module
  mux=MinetIsModuleInConfig(MINET_IP_MUX) ? MinetConnect(MINET_IP_MUX) : MINET_NOHANDLE;
  sock=MinetIsModuleInConfig(MINET_SOCK_MODULE) ? MinetAccept(MINET_SOCK_MODULE) : MINET_NOHANDLE;

  if (MinetIsModuleInConfig(MINET_IP_MUX) && mux==MINET_NOHANDLE) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't connect to mux"));
    return -1;
  }

  if (MinetIsModuleInConfig(MINET_SOCK_MODULE) && sock==MINET_NOHANDLE) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock module"));
    return -1;
  }

  MinetSendToMonitor(MinetMonitoringEvent("tcp_module handling TCP traffic"));

  MinetEvent event;

  cout<<"TCP start working now"<<endl;//test

  while (MinetGetNextEvent(event)==0) {
    // if we received an unexpected type of event, print error
    if (event.eventtype!=MinetEvent::Dataflow 
	|| event.direction!=MinetEvent::IN) {
      MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
    // if we received a valid event from Minet, do processing
    } else {
      if (event.handle==mux) {
	Packet p;
	bool checkSumOK;
	
	unsigned int ackNum;
	unsigned int seqNum;
	unsigned char flags;
	unsigned short windowSize;

	MinetReceive(mux,p);
	//estimate tcp header length
	unsigned tcphlen=TCPHeader::EstimateTCPHeaderLength(p);
	//cerr << "estimated header len="<<tcphlen<<"\n";//TEST
	p.ExtractHeaderFromPayload<TCPHeader>(tcphlen);
	//Find TCP and IP header
	IPHeader iph=p.FindHeader(Headers::IPHeader);
	TCPHeader tcph=p.FindHeader(Headers::TCPHeader);
        checkSumOK=tcph.IsCorrectChecksum(p);
        //cerr << "Checksum is " << (checkSumOK ? "VALID" : "INVALID");//TEST 
        Connection c;
	
	//Flip around, change source to "this machine", source is the machine we receive packet from
	//Handle IP header
	iph.GetDestIP(c.src);
	iph.GetSourceIP(c.dest);
	iph.GetProtocol(c.protocol);
	//Handle TCP header
	tcph.GetDestPort(c.srcport);
	tcph.GetSourcePort(c.destport);
	tcph.GetSeqNum(seqNum);
	tcph.GetAckNum(ackNum);
	tcph.GetFlags(flags);//now we know what we need to do
	tcph.GetWinSize(windowSize);
	//cerr << "TCP Packet: IP Header is "<<iph<<" and "; //TEST
	//cerr << "TCP Header is "<<tcph << " and ";  //TEST
	
	unsigned short len;
	unsigned char iph_len;
	unsigned char tcph_len;
	checkSumOK = tcph.IsCorrectChecksum(p);
        ConnectionList<TCPState>::iterator cs = clist.FindMatching(c); 
	if (cs!=clist.end()) {
          iph.GetTotalLength(len);
          iph.GetHeaderLength(iph_len);
          tcph.GetHeaderLen(tcph_len);
          len  = len - (iph_len + tcph_len);//data length
	  Buffer &data = p.GetPayload().ExtractFront(len);
	  
	  //Now handle connection state
	  ConnectionToStateMapping<TCPState> &connState = *cs;
	  unsigned int currentState = connState.state.GetState();
	  switch (currentState) {
		case CLOSED:
		{
		  cout<< "Receiver wait to be open"<<endl;
		}
		 break;

		case LISTEN:
		{
		  if (IS_SYN(flags)){
		    createPacket(p, connState, 0, 0,seqNum,ackNum+1);//send SYN&ACK
		    //TODO Set a timeout also
		    MinetSend(sock,p);	
		    (*cs).state.SetState(SYN_RCVD); //we just received a SYN, change state
		  }
		  else
		   ;
	        }
		 break;

		case SYN_RCVD:
		{
		  if(IS_ACK(flags)){
		   (*cs).state.SetState(ESTABLISHED);
		  } 
		  else if (IS_FIN(flags)) {
		    //send ACK
		   (*cs).state.SetState(FIN_WAIT1);
		  }
		  
		}
		 break;
		case SYN_SENT:
		{
			;
		}
		case SYN_SENT1:
		{
			break;
		}
		case ESTABLISHED:
		{
			;
		}
		case SEND_DATA:
		{
			;
		}
		case CLOSE_WAIT:
		{
			;
		}
		case FIN_WAIT1:
		{
			;
		}

		case CLOSING:
		{
		  if (IS_FIN(flags))
		   ;
		}
		 break;

		case LAST_ACK:
		{
		  if (IS_ACK(flags))
		  {
		    (*cs).state.SetState(CLOSED);
		    //No need to send anything, just "CLOSE".
		    //since this is the "last" ack	
		  }
		}
		 break;
		case FIN_WAIT2:
		{
			;
		}
		case TIME_WAIT:
		{
			;
		}
	  }
	  SockRequestResponse write(WRITE,
				    (*cs).connection,
				     data,
				     len,
				     EOK);
	  if (!checkSumOK) {
	    MinetSendToMonitor(MinetMonitoringEvent("forwarding packet to sock even though checksum failed"));
	   }
	  MinetSend(sock,write);
	} else {
	  MinetSendToMonitor(MinetMonitoringEvent("Unknown port, sending ICMP error message"));
	  IPAddress source;
	  iph.GetSourceIP(source);
	  ICMPPacket error(source,DESTINATION_UNREACHABLE,PORT_UNREACHABLE,p);
	  MinetSendToMonitor(MinetMonitoringEvent("ICMP error message has been sent to host"));
	  MinetSend(mux, error);
	}
      }

      //  Data from the Sockets layer above  //
      if (event.handle==sock) {
	//A SockRequestResponse
	//contains a request type, a Connection , a Buffer containing data, 
	//a byte count, and an error code.
	SockRequestResponse s;//first handle unserialization
	MinetReceive(sock,s);
	cerr << "Received Socket Request:" << s << endl;
	switch (s.type) {
	case CONNECT: //TODO:active open to remote pp15
	{
	  ;
	}
	 break;
	case ACCEPT:  //TODO:passive open from remote pp15
	 { // ignored, send OK response
	   SockRequestResponse repl;// handle serialization
	   repl.type=STATUS;
	   repl.connection=s.connection;
	// buffer is zero byte
	   repl.bytes=0;
	   repl.error=EOK;
	   MinetSend(sock,repl);
	 }
	 break;
	// case SockRequestResponse::WRITE:
	case WRITE:
	 {
	//TODO: connection refer to previous CONNECT and ACCEPT pp15
	   unsigned bytes;//unsigned bytes = MIN_MACRO(TCP_MAX_DATA, s.data.GetSize()); TODO
	    // create the payload of the packet
	   Packet p(s.data.ExtractFront(bytes));
	    // Make the IP header first since we need it to do the tcp checksum
	   IPHeader ih;
	   ih.SetProtocol(IP_PROTO_TCP);
	   ih.SetSourceIP(s.connection.src);
	   ih.SetDestIP(s.connection.dest);
	   //ih.SetTotalLength(bytes+TCP_HEADER_LENGTH+IP_HEADER_BASE_LENGTH);TODO
	   // push it onto the packet
	   p.PushFrontHeader(ih);
	   // Now build the TCP header
	   // notice that we pass along the packet so that the udpheader can find
	   // the ip header because it will include some of its fields in the checksum
	   TCPHeader th;
	   th.SetSourcePort(s.connection.srcport,p);
	   th.SetDestPort(s.connection.destport,p);
	   //th.SetLength(UDP_HEADER_LENGTH+bytes,p);TODO
	   // Now we want to have the tcp header BEHIND the IP header
	   p.PushBackHeader(th);
	   MinetSend(mux,p);
	   SockRequestResponse repl;
	   //repl.type=SockRequestResponse::STATUS;
	   repl.type=STATUS;
	   repl.connection = s.connection;
	   repl.bytes=bytes;
	   repl.error=EOK;
	   MinetSend(sock,repl);
	//TODO: write generate multiple segments instead of only one (compared with UDP)
	 }
	 break;
	case FORWARD:
	 {
	   //ignore this message, resurn error STATUS
	   SockRequestResponse repl;
	   repl.type = STATUS;
	   repl.error = EWHAT;
	   MinetSend(sock,repl);
         }
	 break;
        case CLOSE:
	 {
	   ;
	   /*TODO:close connection. The connection represents the connection to match on
		and all other fields are ignored. If there is a matching connection, 
		this will close it. Otherwise it is an error. A STATUS with the same connection 
		and an error code will be returned. STATUS: status update.*/
	 }
	 break;
	case STATUS:
	 {
	   ;
	   /*TODO:status update. This should be sent in response to TCP WRITEs. The
		connection should match that in the WRITE. It is important that the byte count
		actually reflects the number of bytes read from the WRITE. The TCP module
		will resend the remaining bytes at some point in the future.*/
	 }
	default: //treat the status as error
	 {
	   SockRequestResponse repl;
	   repl.type = STATUS;
	   repl.error=EWHAT;
	   MinetSend(sock,repl);
	 }		
        }//end of switch
     }//end of "if"
    }//end of "else"
  }//end of "while" loop
  return 0;
}

void createPacket(Packet &packet, ConnectionToStateMapping<TCPState>& constate, int dataLen, int signal, unsigned int seq, unsigned int ack)
{

  unsigned char flags = 0;

  int packetLen = dataLen + TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH;
  IPHeader iph;
  TCPHeader tcph;
  IPAddress src = constate.connection.src;
  IPAddress dest = constate.connection.dest;

  //create the IP packet
  iph.SetSourceIP(src);
  iph.SetDestIP(dest);
  iph.SetTotalLength(packetLen);
  iph.SetProtocol(IP_PROTO_TCP);
  
  packet.PushFrontHeader(iph);
  
  switch (signal){
  case SIG_SYN_ACK:
   {	
     SET_SYN(flags);
     SET_ACK(flags);
   }
   break;
  
  /*case SIG_RST:
    SET_RST(flags);
  break;*/
  
  case SIG_ACK:
    SET_ACK(flags);
  break;
 
  case SIG_SYN:
    SET_SYN(flags);
 
  case SIG_FIN:
    SET_FIN(flags);
  break;
                                                            
  default:
  break;
  }
  //create the TCP header
  tcph.SetSourcePort(constate.connection.srcport,packet);
  tcph.SetDestPort(constate.connection.destport,packet);
  tcph.SetFlags(flags,packet);
  tcph.SetSeqNum(seq,packet);
  tcph.SetAckNum(ack,packet);
  packet.PushBackHeader(tcph);
}

/*
void testPacket(Packet &packet)
{
  unsigned char flags = 0;

  int packetLen = TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH;
  IPHeader iph;
  TCPHeader tcph;
  IPAddress src = constate.connection.src;
  IPAddress dest = constate.connection.dest;

}*/

unsigned int generateISN()
{
  srand((unsigned)time(0));
  unsigned int random;
  unsigned int lowest=100;
  unsigned int highest=1000;
  unsigned int range=(highest-lowest)+1;
  random = lowest+(unsigned int)(range*rand()/(RAND_MAX + 1.0));
  return random;
}
