package net.floodlightcontroller.mactracker;
 
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Collection;
import java.util.Map;
 
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.TransportPort;
import org.projectfloodlight.openflow.types.VlanVid;
 
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.IFloodlightProviderService;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;

import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//second release

public class MACTracker implements IOFMessageListener, IFloodlightModule {

	protected IFloodlightProviderService floodlightProvider;
	protected Set<Long> macAddresses;
	protected static Logger logger;
	protected int count = 0;
	boolean allow = true;
	protected Timer timer;
	protected IOFSwitch sw1;
	
	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return MACTracker.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		// TODO Auto-generated method stub
		Collection<Class<? extends IFloodlightService>> l =
				new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
	    macAddresses = new ConcurrentSkipListSet<Long>();
	    logger = LoggerFactory.getLogger(MACTracker.class);
	    //logger.info("Initialized");
	    count = 0;
	    // And From your main() method or any other method
	    timer = new Timer();
	    timer.schedule(new outputnumber(), 0, 1000);
	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}

	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		count++;
		sw1 = sw;
		//logger.info("Message type: " + msg.getType());
		switch (msg.getType()) {
	    case PACKET_IN:
	        /* Retrieve the deserialized packet in message */
	        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
	 
	        /* Various getters and setters are exposed in Ethernet */
	        MacAddress srcMac = eth.getSourceMACAddress();
	        VlanVid vlanId = VlanVid.ofVlan(eth.getVlanID());
	 
	        /* 
	         * Check the ethertype of the Ethernet frame and retrieve the appropriate payload.
	         * Note the shallow equality check. EthType caches and reuses instances for valid types.
	         */
	        if (eth.getEtherType() == EthType.IPv4) {
	        	
	            /* We got an IPv4 packet; get the payload from Ethernet */
	            IPv4 ipv4 = (IPv4) eth.getPayload();
	            //logger.info("IPv4 length: " + ipv4.getTotalLength()); 
	            /* Various getters and setters are exposed in IPv4 */
	            byte[] ipOptions = ipv4.getOptions();
	            IPv4Address dstIp = ipv4.getDestinationAddress();
	             
	            /* 
	             * Check the IP protocol version of the IPv4 packet's payload.
	             * Note the deep equality check. Unlike EthType, IpProtocol does
	             * not cache valid/common types; thus, all instances are unique.
	             */
	            if (ipv4.getProtocol().equals(IpProtocol.TCP)) {
	            	//logger.info("TCP length: " + ipv4.getTotalLength());
	                /* We got a TCP packet; get the payload from IPv4 */
	                TCP tcp = (TCP) ipv4.getPayload();
	  
	                /* Various getters and setters are exposed in TCP */
	                TransportPort srcPort = tcp.getSourcePort();
	                TransportPort dstPort = tcp.getDestinationPort();
	                short flags = tcp.getFlags();
	                 
	                /* Your logic here! */
	            } else if (ipv4.getProtocol().equals(IpProtocol.UDP)) {
	            	//logger.info("UDP length: " + ipv4.getTotalLength());
	                /* We got a UDP packet; get the payload from IPv4 */
	                UDP udp = (UDP) ipv4.getPayload();
	  
	                /* Various getters and setters are exposed in UDP */
	                TransportPort srcPort = udp.getSourcePort();
	                //logger.info("Source port: " + srcPort);
	                TransportPort dstPort = udp.getDestinationPort();
	                 
	                /* Your logic here! */
	            }
	 
	        } else if (eth.getEtherType() == EthType.ARP) {
	        	//logger.info("ARP");
	            /* We got an ARP packet; get the payload from Ethernet */
	            ARP arp = (ARP) eth.getPayload();
	 
	            /* Various getters and setters are exposed in ARP */
	            boolean gratuitous = arp.isGratuitous();
	 
	        } else {
	            /* Unhandled ethertype */
	        }
	        break;
	    default:
	    	//logger.info("In default");
	        break;
	    }
	    return Command.CONTINUE;
	}
		/*
		Ethernet eth =
                IFloodlightProviderService.bcStore.get(cntx,
                                            IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
 
        Long sourceMACHash = eth.getSourceMACAddress().getLong();
        logger.info("This is running");
        if (!macAddresses.contains(sourceMACHash)) {
            macAddresses.add(sourceMACHash);
            logger.info("MAC Address: {} seen on switch: {}",
                    eth.getSourceMACAddress().toString(),
                    sw.getId().toString());
        }
        return Command.CONTINUE;
	}
        */
	/*
	public void blockSwitchFlow() {
		
		OFFactory myFactory = sw1.getOFFactory();
		ArrayList<OFAction> actions = new ArrayList<OFAction>();
		actions.add(myFactory.actions().buildOutput(). // builder pattern used throughout
	    .setPort(OFPort.of(1)) // raw types replaced with objects for type-checking and readability
	    .build()); // list of immutable OFAction objects
		actions.add(myFa)
	    OFFlowAdd flow = myFactory.buildFlowAdd()
	    .setMatch(myFactory.buildMatch()
	    .setExact(MatchField.IN_PORT, OFPort.of(1)) // type-checked matching
	    .setExact(MatchField.ETH_TYPE, EthType.IPv4)
	    .build()) // immutable Match object
	    .setActions(actions)
	    .setOutPort(OFPort.of(2))
	    .setBufferId(OFBufferId.NO_BUFFER)
	    .build(); // immutable OFFlowMod; no lengths to set; no wildcards to set
	    sw1.write(flow);
	}
	*/
	private class outputnumber extends TimerTask{
		public void run(){
			logger.info("packet in 1 sec: " + count);
			if (count > 100) {
				try {
					Process p = Runtime.getRuntime().exec(new String[]{"bash","-c","echo floodlight | sudo -S ovs-vsctl --if-exists del-br s1"});
					
					BufferedReader stdInput = new BufferedReader(new 
			                 InputStreamReader(p.getInputStream()));

			            BufferedReader stdError = new BufferedReader(new 
			                 InputStreamReader(p.getErrorStream()));

			            // read the output from the command
			            System.out.println("Here is the standard output of the command:\n");
			            String s;
						while ((s = stdInput.readLine()) != null) {
			                System.out.println(s);
			            }
			            
			            // read any errors from the attempted command
			            System.out.println("Here is the standard error of the command (if any):\n");
			            while ((s = stdError.readLine()) != null) {
			                System.out.println(s);
			            }
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			count = 0;
		}
	}
}
