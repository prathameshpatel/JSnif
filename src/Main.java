import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.XmlFormatter;

public class Main {

	public static void main(String[] args) {
		
		List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs  
		StringBuilder errbuf = new StringBuilder();     // For any error msgs  
		                  
//		Get a list of devices on the system
		int r = Pcap.findAllDevs(alldevs, errbuf);  // r: -1 = error; 0 = success
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {  
		  System.err.printf("Can't read list of devices, error is %s", errbuf.toString());  
		  return;  
		}

//		Select a particular device from the list
		int i=0; //simple counter to keep track of number of devices
		for (PcapIf device : alldevs) {  
            String description =  
                (device.getDescription() != null) ? device.getDescription() : "No description available";  
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);  
        }
		PcapIf device = alldevs.get(3); 
		System.out.printf("\nChoosing '%s' on your behalf:\n",  
            (device.getDescription() != null) ? device.getDescription() : device.getName()); 
		
//		Open up the selected device
		int snaplen = 64 * 1024;           // Capture all packets, no truncation  
		int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
		int timeout = 10 * 1000;           // 10 seconds in millis  
		Pcap pcap =  Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf); 
		if (pcap == null) {  
            System.err.printf("Error while opening device for capture: "+ errbuf.toString());  
            return;  
        }
		
//		Create a packet handler which will receive packets
		PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {  
			  
	        public void nextPacket(PcapPacket packet, String user) {

	            /*System.out.printf("Received packet at %s caplen=%-4d len=%-4d %s\n",  
	                new Date(packet.getCaptureHeader().timestampInMillis()),   
	                packet.getCaptureHeader().caplen(),  // Length actually captured  
	                packet.getCaptureHeader().wirelen(), // Original length
	                user
	                );*/
	        	/*XmlFormatter out = new XmlFormatter(System.out);  
	        	try {
					out.format(packet);
				} catch (IOException e) {
					e.printStackTrace();
				}*/
	        	
	        	System.out.println(packet.toString());
	        	
	        }  
	    };
	    
//	    Enter the loop and tell it capture some packets
	    pcap.loop(3, jpacketHandler, "jNetPcap rocks!"); //arguments = number of packets, packet handler, user string
	    
//	    Close the pcap handle
	    pcap.close();
	}
	
	

}
