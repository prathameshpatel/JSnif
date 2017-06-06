import java.util.ArrayList;
import java.util.List;
import java.util.Date;  

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.packet.PcapPacket; 

public class Sniffer {
	private List<PcapIf> alldevs; // Will be filled with NICs  
	private StringBuilder errbuf; // For any error msgs 
	private PcapIf selectedDevice;
	private Pcap pcap;
	private PcapPacketHandler<String> jpacketHandler;
	
	public Sniffer() {
		alldevs = new ArrayList<PcapIf>();
		errbuf = new StringBuilder();
		listDevices();
	    selectedDevice = selectDevice(3);
	    openDevice(selectedDevice);
	    packetHandler();
	    capturePackets();
	}
	
//	Get a list of devices on the system
	public void listDevices(){
	    int r = Pcap.findAllDevs(alldevs, errbuf);  //r: -1 = error; 0 = success
	    if (r == Pcap.NOT_OK || alldevs.isEmpty()) {  
	            System.err.printf("Can't read list of devices, error is %s", errbuf.toString());  
	        return;  
	    }  

	    System.out.println("Devices on the system:");  

//	    Get the description of the network devices on the system
	    int i = 0; //simple counter to keep track of number of devices
	    for (PcapIf device : alldevs) {  
	    	String description;
	    	if(device.getDescription() != null) {
	    		description = device.getDescription();
	    	}
	    	else {
	    		description = "No description available";
	    	}
	        System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);  
	    }  
	}

//	Select a particular device from the list
	private PcapIf selectDevice(int deviceID){
	    PcapIf device = alldevs.get(deviceID); //passing the device we want to sniff on
	    System.out.printf("\nChoosing '%s' on your behalf:\n",  
	            (device.getDescription() != null) ? device.getDescription()  
	                : device.getName());
	    return device;
	}

//	Open up the selected device
	private void openDevice (PcapIf device){
	    int snaplen = 64 * 1024;           // Capture all packets, no trucation  
	    int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
	    int timeout = 10 * 1000;           // 10 seconds in millis  
	    pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);  

	    if (pcap == null) {  
	        System.err.printf("Error while opening device for capture: " + errbuf.toString());  
	        return;  
	    }        
	}

//	Create a packet handler which will receive packets
	private void packetHandler(){
	    jpacketHandler = new PcapPacketHandler<String>() {   
	    	Http http = new Http(); // Preallocate HTTP header
	    	Tcp tcp = new Tcp(); // Preallocate TCP header
	    	Udp udp = new Udp(); // Preallocate UDP header
	    	Ethernet eth = new Ethernet(); // Preallocate our Ethernet header
	    	Arp arp = new Arp(); // Preallocate ARP header
	    	Ip4 ip4 = new Ip4(); // Preallocate IP version 4 header
	    	Ip6 ip6 = new Ip6(); //Preallocate IP version 6 header
	    	
	    	public void nextPacket(PcapPacket packet, String user) {
	    		System.out.println("\nPacket Total size= "+packet.getTotalSize());
	    		
	    		if (packet.hasHeader(eth)) {
	                System.out.printf("Ethernet Type= %X\n", eth.type());
	                System.out.print("Eth source= ");
	                for(byte b : eth.source()){System.out.print(b);}
	                System.out.println("");
	                System.out.print("Eth destination= ");
	                for(byte b : eth.destination()){System.out.print(b);}
	                System.out.println("");
	    		}
	    		if (packet.hasHeader(ip4)) {
	    			System.out.printf("IP Version=%d\n", ip4.version());
	    			System.out.println("IP source="+(long)ip4.sourceToInt());
	    			System.out.println("IP destination="+(long)ip4.destinationToInt());
	    		}
	    		if(packet.hasHeader(tcp)){
//	    			System.out.println(packet.getHeader(tcp).getHeader());
	    			System.out.println("TCP source port= "+tcp.source());
	    			System.out.println("TCP destination port= "+tcp.destination());
	    			if(packet.getHeader(new Tcp()).destination() == 443 || packet.getHeader(new Tcp()).destination() == 80) {
	    				System.out.println("Using HTTP/HTTPS or Instant-Messaging");
	    			}
	    			else
	    				System.out.println("can't know TCP application");
	    		}
	    		if(packet.hasHeader(udp)) {
//	    			System.out.println("packet has UDP");
	    			System.out.println("UDP destination port= "+udp.destination());
	    			System.out.println("UDP destination port= "+udp.source());
	    			if(packet.getHeader(new Udp()).destination() > 16384 || packet.getHeader(new Tcp()).destination() < 32767) {
	    				System.out.println("Using VoIP or video call");
	    			}
	    			else
	    				System.out.println("cant know UDP application");
	    		}
	    		if(packet.hasHeader(http)){
//	                System.out.println("Content Type= "+http.toString());
	                System.out.println("HTTP Host"+http.fieldValue((Http.Request.Host.Host)));
	                System.out.println(http.fieldValue((Http.Request.Host.RequestUrl)));
	                if(http.hasPayload()) {
	                   System.out.println("HTTP payload: (string length is "
	                         +new String(http.getPayload()).length()+")");
//	                   System.out.println(new String(httpheader.getPayload()));
//	                   System.out.println("HTTP truncated? "
//	                         +httpheader.isPayloadTruncated());
	                }
	            }
//	    		System.out.println(packet.toString());
	    	}
	    }; 
	}

//	Capture packets
	private void capturePackets(){
	    pcap.loop(3 , jpacketHandler, "Received Packet"); //Enter the loop and tell it capture some packets
	    pcap.close(); //Close the pcap handle
	}
}
