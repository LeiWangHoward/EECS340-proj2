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


#include <iostream>

#include "Minet.h"
//#include "tcp_in.h"

using std::cout;
using std::endl;
using std::cerr;
using std::string;

int main(int argc, char *argv[])
{
  MinetHandle mux, sock;//Multiplexor and Socket

  //ConnectionList<TCPState> ConnList;

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

  cout<<"TCP start working now"<<endl;

  while (MinetGetNextEvent(event)==0) {
    // if we received an unexpected type of event, print error
    if (event.eventtype!=MinetEvent::Dataflow 
	|| event.direction!=MinetEvent::IN) {
      MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
    // if we received a valid event from Minet, do processing
    } else {
      //  Data from the IP layer below  //
      if (event.handle==mux) {
	Packet p;
	MinetReceive(mux,p);
	unsigned tcphlen=TCPHeader::EstimateTCPHeaderLength(p);
	cerr << "estimated header len="<<tcphlen<<"\n";
	p.ExtractHeaderFromPayload<TCPHeader>(tcphlen);
	IPHeader ipl=p.FindHeader(Headers::IPHeader);
	TCPHeader tcph=p.FindHeader(Headers::TCPHeader);

	cerr << "TCP Packet: IP Header is "<<ipl<<" and ";
	cerr << "TCP Header is "<<tcph << " and ";

	cerr << "Checksum is " << (tcph.IsCorrectChecksum(p) ? "VALID" : "INVALID");
	
      }
      //  Data from the Sockets layer above  //
      if (event.handle==sock) {
	SockRequestResponse s;
	MinetReceive(sock,s);
	cerr << "Received Socket Request:" << s << endl;
	switch (s.type) {
	case CONNECT: //TODO:active open to remote pp15
	case ACCEPT:  //TODO:passive open from remote pp15
	 { // ignored, send OK response
	   SockRequestResponse repl;
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
	   return 0;//ignore this message, resurn 0 STATUS
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
	default:
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
