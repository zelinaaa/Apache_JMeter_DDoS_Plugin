package eu.gity.jmeter.ddos.dnsqueryflood;

import eu.gity.jmeter.ddos.common.DDoSUtils;
import eu.gity.jmeter.ddos.common.Trafgen;
import eu.gity.jmeter.ddos.common.TrafgenControl;
import eu.gity.jmeter.ddos.common.TrafgenControl.TrafgenThread;
import org.apache.jmeter.samplers.AbstractSampler;
import org.apache.jmeter.samplers.Entry;
import org.apache.jmeter.samplers.SampleResult;
import org.apache.jmeter.testelement.TestElement;
import org.apache.jmeter.testelement.TestStateListener;
import org.apache.jmeter.testelement.property.PropertyIterator;
import org.apache.jmeter.util.JMeterUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.TimeUnit;

import static eu.gity.jmeter.ddos.common.DDoSUtils.EXPOSE_INTERFACE_AND_IP_RANGE;
import static eu.gity.jmeter.ddos.common.DDoSUtils.EXPOSE_TARGET_FOR_NET_ANALYZER;
import static eu.gity.jmeter.ddos.common.DDoSUtils.POSITION_IN_TEST_PLAN_LIST;

/**
 * This Test Element class stores properties of DNS Query Flood DoS attack and starts trafgen generator using instance of TrafgenControl class
 *
 * @author Gity a.s.
 */

public class DnsQueryFloodSampler extends AbstractSampler implements TestStateListener, Trafgen{
	//------!!Do not change values of the string constants below because the string values are used by TrafgenControl directly
    public static final String DMAC = "DnsQueryFloodSampler.dmac";
    public static final String SMACSINGLE = "DnsQueryFloodSampler.smacSingle";
    public static final String SMACMIN = "DnsQueryFloodSampler.smacmin";
    public static final String SMACMAX = "DnsQueryFloodSampler.smacmax";
    public static final String RANDOMMAC = "DnsQueryFloodSampler.randomsmac";
    public static final String SMACTG = "DnsQueryFloodSampler.smacTG";
    
    public static final String TARGETIP = "DnsQueryFloodSampler.targetIP";
    public static final String SOURCEIPSINGLE = "DnsQueryFloodSampler.sourceIPsingle";
    public static final String RANDOMIP = "DnsQueryFloodSampler.randomIP";
    public static final String SOURCEIPMIN = "DnsQueryFloodSampler.sourceIPmin";
    public static final String SOURCEIPMAX = "DnsQueryFloodSampler.sourceIPmax";
    public static final String SOURCEIPTG = "DnsQueryFloodSampler.sourceIPTG";
    
    public static final String IPV6ENABLED = "DnsQueryFloodSampler.ipv6enabled";
    public static final String TARGETIPV6 = "DnsQueryFloodSampler.targetIPv6";
    public static final String SOURCEIPV6 = "DnsQueryFloodSampler.sourceIPv6";
    
    public static final String RANDOMIPV6 = "DnsQueryFloodSampler.randomIPv6";
    public static final String SOURCEIPV6MIN = "DnsQueryFloodSampler.sourceIPv6Min";
    public static final String SOURCEIPV6MAX = "DnsQueryFloodSampler.sourceIPv6Max";
    public static final String NUMBEROFIPV6ADDRESSES = "DnsQueryFloodSampler.numberOfIPv6Addresses";
    
    public static final String SOURCEPORTSINGLE = "DnsQueryFloodSampler.sourcePort";
    public static final String RANDOMPORT = "DnsQueryFloodSampler.randomPort";
    public static final String SOURCEPORTMIN = "DnsQueryFloodSampler.sourcePortmin";
    public static final String SOURCEPORTMAX = "DnsQueryFloodSampler.sourcePortmax";
    public static final String DPORT = "DnsQueryFloodSampler.dPort";
    public static final String SOURCEPORTTG = "DnsQueryFloodSampler.sourcePortTG";
    
    public static final String QUERYTG = "DnsQueryFloodSampler.queryTG";
    public static final String QUERY = "DnsQueryFloodSampler.query";
    public static final String RANDOMQUERY = "DnsQueryFloodSampler.randomQuery";
    
    public static final String NUMBER = "DnsQueryFloodSampler.number";
    public static final String RATE = "DnsQueryFloodSampler.rate";      
    public static final String INTERF = "DnsQueryFloodSampler.interface";    
    
    
    //This property is set from DDoSThreadGroup and is just forwarded to TrafgenControl
    public static final String DYNAMICRATE = "DnsQueryFloodSampler.dynamicRate";
    public static final String configFileSuffix = "DnsQueryFlood.cfg";
    public static final String configFileSuffixIpv6 = "DnsQueryFloodIpv6.cfg";
    private static final long serialVersionUID = 240L;
    private static final Logger log = LoggerFactory.getLogger(DnsQueryFloodSampler.class);
    private transient TrafgenControl trafgenControl;
    private boolean isOrderNumberInTespPlanTreeSet;
    
    /**
     * Constructs trafgenControl object if not done yet
     */
    void checkInit() {
    	if (trafgenControl == null) {
    		trafgenControl = new TrafgenControl(configFileSuffix, this);
    	}
    }
    
    /**
     * Syncing of the information to GUI do disable/enable specific options
     * 
     * @return true if dynamicRate will be used
     */
    boolean isDynamicRate() {
    	return trafgenControl.isDynamicRate();
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    public void setDynamicRate(boolean dynamic) {
        this.setProperty(DYNAMICRATE, dynamic);
        trafgenControl.setDynamicRate(dynamic);
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    public SampleResult sample(Entry e) {
    	if (this.getPropertyAsString(INTERF).isEmpty()) {
            return null; //This error is already reported to log in DDoSUtils class
        }

        if (!isOrderNumberInTespPlanTreeSet) {
            isOrderNumberInTespPlanTreeSet = true;
            DDoSUtils.setPropertyForNetworkAnalyzer(this);
        }

        if(getPropertyAsBoolean(IPV6ENABLED)){
            JMeterUtils.setProperty(EXPOSE_TARGET_FOR_NET_ANALYZER, this.getPropertyAsString(TARGETIPV6));
            if (this.getPropertyAsBoolean(RANDOMIPV6)) {
                JMeterUtils.setProperty(EXPOSE_INTERFACE_AND_IP_RANGE, DDoSUtils.buildStringWithDelimiter(
                        this.getPropertyAsString(SOURCEIPV6MIN), this.getPropertyAsString(SOURCEIPV6MAX), this.getPropertyAsString(INTERF)
                ));
            } else {
                JMeterUtils.setProperty(EXPOSE_INTERFACE_AND_IP_RANGE, DDoSUtils.buildStringWithDelimiter(
                        this.getPropertyAsString(SOURCEIPV6), this.getPropertyAsString(SOURCEIPV6), this.getPropertyAsString(INTERF)
                ));
            }
        } else {
            JMeterUtils.setProperty(EXPOSE_TARGET_FOR_NET_ANALYZER, this.getPropertyAsString(TARGETIP));
            if (this.getPropertyAsBoolean(RANDOMIP)) {
                JMeterUtils.setProperty(EXPOSE_INTERFACE_AND_IP_RANGE, DDoSUtils.buildStringWithDelimiter(
                        this.getPropertyAsString(SOURCEIPMIN), this.getPropertyAsString(SOURCEIPMAX), this.getPropertyAsString(INTERF)
                ));
            } else {
                JMeterUtils.setProperty(EXPOSE_INTERFACE_AND_IP_RANGE, DDoSUtils.buildStringWithDelimiter(
                    this.getPropertyAsString(SOURCEIPTG), this.getPropertyAsString(SOURCEIPTG), this.getPropertyAsString(INTERF)
            ));
            }
        }

        SampleResult res = new SampleResult();
        res.setSampleLabel(getName());
        res.sampleStart();
        res.setDataType(SampleResult.TEXT);
        int result = trafgenControl.runTrafgen();
        switch (result) {
            case -3 -> {    //Trafgen has finished (static rate)
                log.debug("Trafgen has finished generating predefined amount of packets. Stopping JMeter thread.");
                res.setResponseOK();
                this.getThreadContext().getThread().stop();
            }
            case -2 ->    //Rate is constant;
                    res.setResponseOK();
            case -1 -> {
                log.error("There was problem with Trafgen configuration file - see details above.");
                res.setResponseMessage("There was problem with Trafgen configuration file - see log for details.");
            }
            case 0 -> {
                log.debug("Rate set to 0 - terminating generator");
                res.setResponseOK();
            }
            default -> {
                log.debug("Packet generation rate changed to " + result);
                res.setResponseOK();
            }
        }
        res.sampleEnd();

        try {
            //Prevents generation of excessive amounts of samples
            TimeUnit.MILLISECONDS.sleep(50);
        } catch (InterruptedException e1) {
            //Never mind
        }
        return res;
    }
    
    /**
     * If property string `IPV6ENABLED` of JCheckbox is checked, the abstract config file is changed to ipv6 config file
     */
    public void changeTrafgenElementToIPV6OrIpv4() {
        if(this.getPropertyAsBoolean(IPV6ENABLED)) {
            trafgenControl.setConfigFileSuffix(configFileSuffixIpv6);
        } else {
            trafgenControl.setConfigFileSuffix(configFileSuffix);
        }
    }

    
    /**
     * {@inheritDoc}
     */
    @Override
    public void stopTrafgen() {
        trafgenControl.terminateTrafgen(false);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void checkPacketCount(String tgName, long duration) {
        trafgenControl.verifyPacketCount(tgName, duration, this.getPropertyAsLong(RATE), this.getPropertyAsLong(NUMBER));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void changeRate(int rateChange) {
        trafgenControl.changeRate(rateChange);
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    public void testStarted() {
    	 checkInit();
         changeTrafgenElementToIPV6OrIpv4();
         if (this.getPropertyAsBoolean(RANDOMIPV6) && this.getPropertyAsBoolean(IPV6ENABLED)) {
             trafgenControl.verifyIPv6Range(this.getPropertyAsString(SOURCEIPV6MIN), this.getPropertyAsString(SOURCEIPV6MAX),
                     this.getPropertyAsInt(NUMBEROFIPV6ADDRESSES));
             trafgenControl.generateConfigForRandomIpv6();
         } else {
             trafgenControl.generateConfig();
         }
         isOrderNumberInTespPlanTreeSet = false;
         JMeterUtils.setProperty(POSITION_IN_TEST_PLAN_LIST, "");
         JMeterUtils.setProperty(EXPOSE_TARGET_FOR_NET_ANALYZER, "");
         JMeterUtils.setProperty(EXPOSE_INTERFACE_AND_IP_RANGE, "");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void testStarted(String host) {
        testStarted();
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    public void testEnded() {
        TrafgenThread tt = trafgenControl.getTrafgenThread();
        if (tt == null) {
            return;
        }
        try {
            tt.join();
        } catch (InterruptedException e) {
            log.error("The sampler was interrupted while waiting for trafgen thread to finish:\n" + e.getStackTrace().toString());
        }

        if (!tt.getResult()) {
            log.error("A problem occured while generating traffic");
        }
        isOrderNumberInTespPlanTreeSet = false;
        JMeterUtils.setProperty(POSITION_IN_TEST_PLAN_LIST, "");
        JMeterUtils.setProperty(EXPOSE_TARGET_FOR_NET_ANALYZER, "");
        JMeterUtils.setProperty(EXPOSE_INTERFACE_AND_IP_RANGE, "");
        trafgenControl.reset();
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    public void testEnded(String host) {
        testEnded();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Object clone() {
        try {
            TestElement clonedElement = this.getClass().newInstance();
            PropertyIterator iter = propertyIterator();
            while (iter.hasNext()) {
                clonedElement.setProperty(iter.next().clone());
            }
            clonedElement.setRunningVersion(isRunningVersion());
            //trafgenControl is a reference to object so changes in trafgenControl are reflected back to original instance
            ((DnsQueryFloodSampler) clonedElement).trafgenControl = this.trafgenControl;

            return clonedElement;
        } catch (InstantiationException | IllegalAccessException e) {
            throw new AssertionError(e); // clone should never return null
        }
    }
}











