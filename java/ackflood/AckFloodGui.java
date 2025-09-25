package eu.gity.jmeter.ddos.ackflood;

import eu.gity.jmeter.ddos.common.DDoSInputVerifier;
import eu.gity.jmeter.ddos.common.DDoSUtils;

import org.apache.jmeter.engine.StandardJMeterEngine;
import org.apache.jmeter.gui.util.HorizontalPanel;
import org.apache.jmeter.gui.util.MenuFactory;
import org.apache.jmeter.gui.util.VerticalPanel;
import org.apache.jmeter.samplers.gui.AbstractSamplerGui;
import org.apache.jmeter.testelement.TestElement;
import org.apache.jmeter.testelement.TestStateListener;
import org.apache.jmeter.util.JMeterUtils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.Serial;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static eu.gity.jmeter.ddos.properties.strings.DdosPropertiesStrings.*;


/**
 * This GUI class provides user interface to setup ACK flood DoS attack
 *
 * @author Gity a.s.
 */

public class AckFloodGui extends AbstractSamplerGui{
	@Serial
    private static final long serialVersionUID = 240L;

    private JTextField targetIP;
    private JTextField targetIPv6;
    private JTextField sourceIPsingle;
    private JTextField sourceIPMIN;
    private JTextField sourceIPMAX;
    private JTextField sourceIPv6;
    private JTextField sourceIPv6Min;
    private JTextField sourceIPv6Max;
    private JTextField numberOfIPv6Addresses;

    private JCheckBox randomIP;
    private JCheckBox randomIPv6;
    private JCheckBox ipv6Enabled;
    private JTextField sourcePortSingle;
    private JTextField sourcePortMIN;
    private JTextField sourcePortMAX;
    private JCheckBox randomPort;
    private JTextField destPort;
    private JTextField number;
    private JTextField rate;
    private JTextField sMACsingle;
    private JTextField sMACmin;
    private JTextField sMACmax;
    private JCheckBox incrementalMAC;
    private JTextField dMAC;
    private JTextField ttl;
    private JTextField windowSize;
    private JTextField payLoad;
    private boolean dynamicRate;

    private final JComboBox<String> selectInt = new JComboBox<>();
    private final DDoSInputVerifier verifier = new DDoSInputVerifier();

    /**
     * Ctor which starts GUI initialization
     */
    public AckFloodGui() {
    	init();
        registerTestStateListener();
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    public String getLabelResource() {
        return DDOS_ACK_FLOOD_TITLE; // $NON-NLS-1$
    }

    /**
     * @return The name of component used in title, tree and name of the test
     */
    @Override
    public String getStaticLabel() {
        return JMeterUtils.getLocaleString(DDOS_ACK_FLOOD_TITLE);
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    public TestElement createTestElement() {
        AckFloodSampler sampler = new AckFloodSampler();
        modifyTestElement(sampler);
        return sampler;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void modifyTestElement(TestElement te) {
        te.clear();
        configureTestElement(te);
        Object selectedDev = selectInt.getSelectedItem();
        if (selectedDev != null) { //Maybe no network devices were found       
            te.setProperty(AckFloodSampler.INTERF, selectedDev.toString());
        }

        te.setProperty(AckFloodSampler.DMAC, dMAC.getText());
        te.setProperty(AckFloodSampler.SMACSINGLE, sMACsingle.getText());
        te.setProperty(AckFloodSampler.SMACMIN, sMACmin.getText());
        te.setProperty(AckFloodSampler.SMACMAX, sMACmax.getText());
        te.setProperty(AckFloodSampler.RANDOMMAC, incrementalMAC.isSelected());
        te.setProperty(AckFloodSampler.TARGETIP, targetIP.getText());
        te.setProperty(AckFloodSampler.TARGETIPV6, targetIPv6.getText());
        te.setProperty(AckFloodSampler.SOURCEIPSINGLE, sourceIPsingle.getText());
        te.setProperty(AckFloodSampler.SOURCEIPV6, sourceIPv6.getText());
        te.setProperty(AckFloodSampler.RANDOMIP, randomIP.isSelected());
        te.setProperty(AckFloodSampler.RANDOMIPV6, randomIPv6.isSelected());
        te.setProperty(AckFloodSampler.IPV6ENABLED, ipv6Enabled.isSelected());
        te.setProperty(AckFloodSampler.NUMBEROFIPV6ADDRESSES, numberOfIPv6Addresses.getText());
        te.setProperty(AckFloodSampler.SOURCEIPMIN, sourceIPMIN.getText());
        te.setProperty(AckFloodSampler.SOURCEIPMAX, sourceIPMAX.getText());
        te.setProperty(AckFloodSampler.SOURCEIPV6MIN, sourceIPv6Min.getText());
        te.setProperty(AckFloodSampler.SOURCEIPV6MAX, sourceIPv6Max.getText());
        te.setProperty(AckFloodSampler.TTL, ttl.getText());
        te.setProperty(AckFloodSampler.SOURCEPORTSINGLE, sourcePortSingle.getText());
        te.setProperty(AckFloodSampler.RANDOMPORT, randomPort.isSelected());
        te.setProperty(AckFloodSampler.SOURCEPORTMIN, sourcePortMIN.getText());
        te.setProperty(AckFloodSampler.SOURCEPORTMAX, sourcePortMAX.getText());
        te.setProperty(AckFloodSampler.DPORT, destPort.getText());
        te.setProperty(AckFloodSampler.WINSIZE, windowSize.getText());
        te.setProperty(AckFloodSampler.PAYLOAD, payLoad.getText());
        te.setProperty(AckFloodSampler.NUMBER, number.getText());
        te.setProperty(AckFloodSampler.RATE, rate.getText());

        //Following blocks assigns final values for trafgen config to separate properties 
        if (incrementalMAC.isSelected()) {
            te.setProperty(AckFloodSampler.SMACTG, DDoSUtils.getInstance().macIncremental(sMACmin.getText(), sMACmax.getText()));
        } else {
            te.setProperty(AckFloodSampler.SMACTG, sMACsingle.getText());
        }
        if (randomIP.isSelected()) {
            te.setProperty(AckFloodSampler.SOURCEIPTG, DDoSUtils.getInstance().ipRandom(sourceIPMIN.getText(), sourceIPMAX.getText()));
        } else {
            te.setProperty(AckFloodSampler.SOURCEIPTG, sourceIPsingle.getText());
        }
        if (randomPort.isSelected()) {
            te.setProperty(AckFloodSampler.SOURCEPORTTG, "drnd(" + sourcePortMIN.getText() + "," + sourcePortMAX.getText() + ")");
        } else {
            te.setProperty(AckFloodSampler.SOURCEPORTTG, sourcePortSingle.getText());
        }
        ((AckFloodSampler) te).checkInit();
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    public void configure(TestElement element) {
        super.configure(element);

        List<String> devs = DDoSUtils.getInstance().getValidDevNames();
        if (devs.size() > selectInt.getItemCount()) {
            selectInt.setModel(new DefaultComboBoxModel<String>(devs.toArray(new String[devs.size()])));
        }
        selectInt.setSelectedItem(element.getPropertyAsString(AckFloodSampler.INTERF));

        dMAC.setText(element.getPropertyAsString(AckFloodSampler.DMAC));
        sMACsingle.setText(element.getPropertyAsString(AckFloodSampler.SMACSINGLE));
        incrementalMAC.setSelected(element.getPropertyAsBoolean(AckFloodSampler.RANDOMMAC, false));
        sMACmin.setText(element.getPropertyAsString(AckFloodSampler.SMACMIN));
        sMACmax.setText(element.getPropertyAsString(AckFloodSampler.SMACMAX));
        targetIP.setText(element.getPropertyAsString(AckFloodSampler.TARGETIP));
        targetIPv6.setText(element.getPropertyAsString(AckFloodSampler.TARGETIPV6));
        sourceIPsingle.setText(element.getPropertyAsString(AckFloodSampler.SOURCEIPSINGLE));
        sourceIPv6.setText(element.getPropertyAsString(AckFloodSampler.SOURCEIPV6));
        randomIP.setSelected(element.getPropertyAsBoolean(AckFloodSampler.RANDOMIP, false));
        randomIPv6.setSelected(element.getPropertyAsBoolean(AckFloodSampler.RANDOMIPV6));
        ipv6Enabled.setSelected(element.getPropertyAsBoolean(AckFloodSampler.IPV6ENABLED));
        numberOfIPv6Addresses.setText(element.getPropertyAsString(AckFloodSampler.NUMBEROFIPV6ADDRESSES));
        sourceIPMIN.setText(element.getPropertyAsString(AckFloodSampler.SOURCEIPMIN));
        sourceIPMAX.setText(element.getPropertyAsString(AckFloodSampler.SOURCEIPMAX));
        sourceIPv6Min.setText(element.getPropertyAsString(AckFloodSampler.SOURCEIPV6MIN));
        sourceIPv6Max.setText(element.getPropertyAsString(AckFloodSampler.SOURCEIPV6MAX));

        ttl.setText(element.getPropertyAsString(AckFloodSampler.TTL));
        destPort.setText(element.getPropertyAsString(AckFloodSampler.DPORT));
        sourcePortSingle.setText(element.getPropertyAsString(AckFloodSampler.SOURCEPORTSINGLE));
        randomPort.setSelected(element.getPropertyAsBoolean(AckFloodSampler.RANDOMPORT, false));
        sourcePortMIN.setText(element.getPropertyAsString(AckFloodSampler.SOURCEPORTMIN));
        sourcePortMAX.setText(element.getPropertyAsString(AckFloodSampler.SOURCEPORTMAX));
        windowSize.setText(element.getPropertyAsString(AckFloodSampler.WINSIZE));
        payLoad.setText(element.getPropertyAsString(AckFloodSampler.PAYLOAD));

        ((AckFloodSampler) element).checkInit();
        if (((AckFloodSampler) element).isDynamicRate()) {
            dynamicRate = true;
            element.setProperty(AckFloodSampler.DYNAMICRATE, true); //Must be here to prevent DYNAMICRATE property from being deleted by JMeter
            number.setEnabled(false);
            rate.setEnabled(false);
        } else {
            dynamicRate = false;
            element.setProperty(AckFloodSampler.DYNAMICRATE, false); //Must be here to prevent DYNAMICRATE property from being deleted by JMeter
            number.setText(element.getPropertyAsString(AckFloodSampler.NUMBER));
            rate.setText(element.getPropertyAsString(AckFloodSampler.RATE));
            if (selectInt.isEnabled()) { //Means the test is not running
                number.setEnabled(true);
                rate.setEnabled(true);
            }
        }
    }
    
    /**
     * Creates a panel for target IP setting
     *
     * @return panel containing GUI components for setting target IP
     */
    private JPanel createServerPanel() {
        JLabel label = new JLabel(JMeterUtils.getLocaleString(DDOS_TARGET_IP)); //$NON-NLS-1
        JLabel labelIpv6 = new JLabel(JMeterUtils.getLocaleString(DDOS_TARGET_IPV6)); //$NON-NLS-1$

        targetIP = new JTextField("192.168.0.10");
        label.setLabelFor(targetIP);
        targetIP.setName("ip");
        targetIP.setInputVerifier(verifier);

        targetIPv6 = new JTextField("2001:db8:85a3::188");
        labelIpv6.setLabelFor(targetIPv6);
        targetIPv6.setName("ipv6");
        targetIPv6.setInputVerifier(verifier);
        targetIPv6.setEnabled(false);

        ipv6Enabled = new JCheckBox(JMeterUtils.getLocaleString(DDOS_IPV6_ENABLED));

        ipv6Enabled.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(final ItemEvent e) {
                enableIpv6(e.getStateChange() == ItemEvent.SELECTED);
            }

            private void enableIpv6(boolean b) {
                targetIPv6.setEnabled(b);
                targetIP.setEnabled(!b);
                randomIPv6.setEnabled(b);
                randomIP.setEnabled(!b);
                if (randomIPv6.isSelected()) {
                    numberOfIPv6Addresses.setEnabled(b);
                    sourceIPv6Min.setEnabled(b);
                    sourceIPv6Max.setEnabled(b);
                } else {
                    sourceIPv6.setEnabled(b);
                }
                if(randomIP.isSelected()) {
                    sourceIPMIN.setEnabled(!b);
                    sourceIPMAX.setEnabled(!b);
                } else {
                    sourceIPsingle.setEnabled(!b);
                }
            }
        });

        JPanel serverPanel = new JPanel(new BorderLayout(5, 0));
        serverPanel.add(label, BorderLayout.WEST);
        serverPanel.add(targetIP, BorderLayout.CENTER);

        final JPanel ipv6Panel = new JPanel(new BorderLayout(5, 0));
        ipv6Panel.add(labelIpv6, BorderLayout.WEST);
        ipv6Panel.add(targetIPv6, BorderLayout.CENTER);
        ipv6Panel.add(ipv6Enabled, BorderLayout.EAST);

        JPanel targetIpPanel = new VerticalPanel();
        targetIpPanel.add(serverPanel);
        targetIpPanel.add(ipv6Panel);

        return targetIpPanel;
    }

    /**
     * Creates a panel for source IP setting
     *
     * @return panel containing GUI components for setting source IP
     */
    private JPanel sourceIPPanel() {
        final JPanel sourcePanel = new VerticalPanel();
        sourcePanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), JMeterUtils.getLocaleString(DDOS_SOURCE_IP)));

        sourcePanel.add(sourceIPv4Panel());
        sourcePanel.add(sourceIpv6Panel());

        return sourcePanel;
    }

    /**
     * Create panel for IPv4 source
     *
     * @return panel containing GUI components for setting source IPv4
     */
    private JPanel sourceIPv4Panel() {
        sourceIPsingle = new JTextField("192.168.0.1");
        sourceIPsingle.setName("ip");
        sourceIPsingle.setInputVerifier(verifier);
        //$NON-NLS-1$
        sourceIPMIN = new JTextField("192.168.0.1");
        sourceIPMIN.setName("ip");
        sourceIPMIN.setInputVerifier(verifier);
        sourceIPMIN.setEnabled(false);

        sourceIPMAX = new JTextField("192.168.0.10");
        sourceIPMAX.setName("ip");
        sourceIPMAX.setInputVerifier(verifier);
        sourceIPMAX.setEnabled(false);

        randomIP = new JCheckBox(JMeterUtils.getLocaleString(DDOS_RANDOM)); // $NON-NLS-1$
        // add a listener to activate or not randomIP selection
        randomIP.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(final ItemEvent e) {
                enableRandom(e.getStateChange() == ItemEvent.SELECTED);
            }

            private void enableRandom(boolean b) {
                if(!ipv6Enabled.isSelected()) {
                    sourceIPMIN.setEnabled(b);
                    sourceIPMAX.setEnabled(b);
                    sourceIPsingle.setEnabled(!b);
                }

            }
        });

        final JPanel sourceIpv4Panel = new HorizontalPanel();

        JLabel labelMin = new JLabel(DDOS_MIN);
        labelMin.setLabelFor(sourceIPMIN);
        JLabel labelMax = new JLabel(DDOS_MAX);
        labelMax.setLabelFor(sourceIPMAX);

        JLabel labelS = new JLabel(JMeterUtils.getLocaleString(DDOS_SINGLE_VALUE));
        labelS.setLabelFor(sourceIPsingle);

        sourceIpv4Panel.add(labelS);
        sourceIpv4Panel.add(sourceIPsingle);
        sourceIpv4Panel.add(randomIP);
        sourceIpv4Panel.add(labelMin);
        sourceIpv4Panel.add(sourceIPMIN);
        sourceIpv4Panel.add(labelMax);
        sourceIpv4Panel.add(sourceIPMAX);

        return sourceIpv4Panel;

    }

    /**
     * Create panel for IPv6 source
     *
     * @return panel containing GUI components for setting source IPv6
     */
    private JPanel sourceIpv6Panel() {
        sourceIPv6 = new JTextField("2001:db8:85a3::150");
        sourceIPv6.setName("ipv6");
        sourceIPv6.setInputVerifier(verifier);
        sourceIPv6.setEnabled(false);

        numberOfIPv6Addresses = new JTextField("10");
        numberOfIPv6Addresses.setName("natural");
        numberOfIPv6Addresses.setInputVerifier(verifier);
        numberOfIPv6Addresses.setEnabled(false);

        sourceIPv6Min = new JTextField("2001:db8:85a3::150");
        sourceIPv6Min.setName("ipv6");
        sourceIPv6Min.setInputVerifier(verifier);
        sourceIPv6Min.setEnabled(false);

        sourceIPv6Max = new JTextField("2001:db8:85a3::164");
        sourceIPv6Max.setName("ipv6");
        sourceIPv6Max.setInputVerifier(verifier);
        sourceIPv6Max.setEnabled(false);

        randomIPv6 = new JCheckBox(JMeterUtils.getLocaleString(DDOS_RANDOM)); // $NON-NLS-1$
        randomIPv6.setEnabled(false);
        // add a listener to activate or not randomIP selection
        randomIPv6.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(final ItemEvent e) {
                enableRandom(e.getStateChange() == ItemEvent.SELECTED);
            }

            private void enableRandom(boolean b) {
                if(ipv6Enabled.isSelected()) {
                    numberOfIPv6Addresses.setEnabled(b);
                    sourceIPv6Min.setEnabled(b);
                    sourceIPv6Max.setEnabled(b);
                    sourceIPv6.setEnabled(!b);
                }
            }
        });

        JLabel labelMin = new JLabel(JMeterUtils.getLocaleString(DDOS_MIN));
        labelMin.setLabelFor(sourceIPv6Min);
        JLabel labelMax = new JLabel(JMeterUtils.getLocaleString(DDOS_MAX));
        labelMax.setLabelFor(sourceIPv6Max);

        final JPanel sourceIpv6Panel = new VerticalPanel();

        final JPanel sourceIpv6SinglePanel = new HorizontalPanel();

        JLabel labelSipv6 = new JLabel(JMeterUtils.getLocaleString(DDOS_SINGLE_VALUE));
        labelSipv6.setLabelFor(sourceIPv6);
        JLabel labelNumberOfIPv6Addresses = new JLabel(JMeterUtils.getLocaleString(DDOS_NUMBER_OF_IVP6_TO_USE));
        labelNumberOfIPv6Addresses.setLabelFor(numberOfIPv6Addresses);

        sourceIpv6SinglePanel.add(labelSipv6);
        sourceIpv6SinglePanel.add(sourceIPv6);
        sourceIpv6SinglePanel.add(labelNumberOfIPv6Addresses);
        sourceIpv6SinglePanel.add(numberOfIPv6Addresses);

        final JPanel sourceIpv6MultiplePanel = new HorizontalPanel();

        sourceIpv6MultiplePanel.add(randomIPv6);
        sourceIpv6MultiplePanel.add(labelMin);
        sourceIpv6MultiplePanel.add(sourceIPv6Min);
        sourceIpv6MultiplePanel.add(labelMax);
        sourceIpv6MultiplePanel.add(sourceIPv6Max);

        sourceIpv6Panel.add(sourceIpv6SinglePanel);
        sourceIpv6Panel.add(sourceIpv6MultiplePanel);

        return sourceIpv6Panel;
    }
    
    /**
     * Creates a panel for source MAC setting
     *
     * @return panel containing GUI components for setting source MAC
     */
	private JPanel sMACPanel() {
	    JLabel label = new JLabel(JMeterUtils.getLocaleString(DDOS_SINGLE_VALUE)); //$NON-NLS-1$
	
	    sMACsingle = new JTextField("aa:bb:cc:dd:ee:ff");
	    label.setLabelFor(sMACsingle);
	    sMACsingle.setName("mac");
	    sMACsingle.setInputVerifier(verifier);
	
	    sMACmin = new JTextField("aa:bb:cc:dd:ee:ff");
	    sMACmin.setName("mac");
	    sMACmin.setInputVerifier(verifier);
	    sMACmin.setEnabled(false);
	
	    sMACmax = new JTextField("aa:bb:cc:dd:ef:ff");
	    sMACmax.setName("mac");
	    sMACmax.setInputVerifier(verifier);
	    sMACmax.setEnabled(false);
	
	    incrementalMAC = new JCheckBox(JMeterUtils.getLocaleString(DDOS_INCREMENT)); // $NON-NLS-1$
	    incrementalMAC.addItemListener(new ItemListener() {
	        @Override
	        public void itemStateChanged(final ItemEvent e) {
	            enableRandom(e.getStateChange() == ItemEvent.SELECTED);
	        }
	
	        private void enableRandom(boolean b) {
	            sMACmin.setEnabled(b);
	            sMACmax.setEnabled(b);
	            sMACsingle.setEnabled(!b);
	        }
	    });
	
	    JLabel labelMin = new JLabel("Min: ");
	    labelMin.setLabelFor(sMACmin);
	    JLabel labelMax = new JLabel("Max: ");
	    labelMax.setLabelFor(sMACmax);
	
	    JPanel sMACPanel = new HorizontalPanel();
	    sMACPanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), JMeterUtils.getLocaleString(DDOS_SOURCE_MAC)));
	
	    sMACPanel.add(label);
	    sMACPanel.add(sMACsingle);
	    sMACPanel.add(incrementalMAC);
	    sMACPanel.add(labelMin);
	    sMACPanel.add(sMACmin);
	    sMACPanel.add(labelMax);
	    sMACPanel.add(sMACmax);
	
	    return sMACPanel;
	}
	
	/**
	 * Creates a panel for destination MAC setting
	 *
	 * @return panel containing GUI components for setting destination MAC
	 */
	private JPanel dMACPanel() {
	    JLabel label = new JLabel(JMeterUtils.getLocaleString(DDOS_DEST_MAC)); //$NON-NLS-1$
	
	    dMAC = new JTextField("ff:ff:ff:ff:ff:ff");
	    label.setLabelFor(dMAC);
	    dMAC.setName("mac");
	    dMAC.setInputVerifier(verifier);
	
	    JPanel dMACPanel = new JPanel(new BorderLayout(5, 0));
	
	    dMACPanel.add(label, BorderLayout.WEST);
	    dMACPanel.add(dMAC, BorderLayout.CENTER);
	
	    return dMACPanel;
	}
	
	/**
	 * Creates a panel for source IP setting
	 *
	 * @return panel containing GUI components for setting source IP
	 */
	private JPanel sourcePortPanel() {
	    sourcePortMIN = new JTextField("1025");
	    sourcePortMIN.setName("port");
	    sourcePortMIN.setInputVerifier(verifier);
	    sourcePortMIN.setEnabled(false);
	
	    sourcePortMAX = new JTextField("1035");
	    sourcePortMAX.setName("port");
	    sourcePortMAX.setInputVerifier(verifier);
	    sourcePortMAX.setEnabled(false);
	
	    sourcePortSingle = new JTextField("1025");
	    sourcePortSingle.setName("port");
	    sourcePortSingle.setInputVerifier(verifier);
	
	    randomPort = new JCheckBox(JMeterUtils.getLocaleString(DDOS_RANDOM)); // $NON-NLS-1$
	    // add a listener to activate or not random selection
	    randomPort.addItemListener(new ItemListener() {
	        @Override
	        public void itemStateChanged(final ItemEvent e) {
	            enableRandom(e.getStateChange() == ItemEvent.SELECTED);
	        }
	
	        private void enableRandom(boolean b) {
	            sourcePortMIN.setEnabled(b);
	            sourcePortMAX.setEnabled(b);
	            sourcePortSingle.setEnabled(!b);
	        }
	    });
	
	    final JPanel sourcePortPanel = new HorizontalPanel();
	    sourcePortPanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), JMeterUtils.getLocaleString(DDOS_SOURCE_TCP_PORT)));
	
	    JLabel labelMin = new JLabel("Min: ");
	    labelMin.setLabelFor(sourcePortMIN);
	    JLabel labelMax = new JLabel("Max: ");
	    labelMax.setLabelFor(sourcePortMAX);
	
	    JLabel labelS = new JLabel(JMeterUtils.getLocaleString(DDOS_SINGLE_VALUE));
	    labelS.setLabelFor(sourcePortSingle);
	
	    sourcePortPanel.add(labelS);
	    sourcePortPanel.add(sourcePortSingle);
	    sourcePortPanel.add(randomPort);
	    sourcePortPanel.add(labelMin);
	    sourcePortPanel.add(sourcePortMIN);
	    sourcePortPanel.add(labelMax);
	    sourcePortPanel.add(sourcePortMAX);
	
	    return sourcePortPanel;
	}


	/**
	 * Creates a panel for destination port setting
	 *
	 * @return panel containing GUI components for setting destination port
	 */
	private JPanel destPortPanel() {
	    JLabel label = new JLabel(JMeterUtils.getLocaleString(DDOS_DEST_TCP_PORT)); //$NON-NLS-1$
	    destPort = new JTextField("53");
	    destPort.setName("port");
	    destPort.setInputVerifier(verifier);
	    label.setLabelFor(destPort);
	    JPanel destPortPanel = new JPanel(new BorderLayout(5, 0));
	    destPortPanel.add(label, BorderLayout.WEST);
	    destPortPanel.add(destPort, BorderLayout.CENTER);
	    return destPortPanel;
	}
	
	
	/**
	 * Creates a panel for TTL setting
	 *
	 * @return panel containing GUI components for setting TTL
	 */
	private JPanel ttlPanel() {
	    JLabel label = new JLabel("TTL:"); //$NON-NLS-1$
	
	    ttl = new JTextField("64");
	    label.setLabelFor(ttl);
	    ttl.setName("natural");
	    ttl.setInputVerifier(verifier);
	
	    JPanel ttlPanel = new JPanel(new BorderLayout(5, 0));
	
	    ttlPanel.add(label, BorderLayout.WEST);
	    ttlPanel.add(ttl, BorderLayout.CENTER);
	
	    return ttlPanel;
	}
	
	/**
	 * Creates a panel for TCP window size setting
	 *
	 * @return panel containing GUI components for setting TCP window size
	 */
	private JPanel windowSizePanel() {
	    JLabel label = new JLabel(JMeterUtils.getLocaleString(DDOS_WINDOW_SIZE)); //$NON-NLS-1$
	
	    windowSize = new JTextField("16");
	    windowSize.setName("natural");
	    windowSize.setInputVerifier(verifier);
	    label.setLabelFor(windowSize);
	
	    JPanel windowSizePanel = new JPanel(new BorderLayout(5, 0));
	
	    windowSizePanel.add(label, BorderLayout.WEST);
	    windowSizePanel.add(windowSize, BorderLayout.CENTER);
	
	    return windowSizePanel;
	}
	
	/**
     * Creates a panel for payload size setting
     *
     * @return panel containing GUI components for setting payload size
     */
    private JPanel payloadPanel() {
        JLabel label = new JLabel(JMeterUtils.getLocaleString(DDOS_PADDING_SIZE)); //$NON-NLS-1$

        payLoad = new JTextField("12");
        payLoad.setName("natural");
        payLoad.setInputVerifier(verifier);
        label.setLabelFor(payLoad);

        JPanel payloadPanel = new JPanel(new BorderLayout(5, 0));

        payloadPanel.add(label, BorderLayout.WEST);
        payloadPanel.add(payLoad, BorderLayout.CENTER);

        return payloadPanel;
    }


    /**
     * Creates a panel for setting a number of packets to be generated
     *
     * @return panel containing GUI components for setting number of packets
     */
    private JPanel numberPanel() {
        JLabel label = new JLabel(JMeterUtils.getLocaleString(DDOS_PACKET_COUNT)); //$NON-NLS-1$
        number = new JTextField("5");
        number.setName("naturalOrNothing");
        number.setInputVerifier(verifier);
        label.setLabelFor(number);
        JPanel numberPanel = new JPanel(new BorderLayout(5, 0));
        numberPanel.add(label, BorderLayout.WEST);
        numberPanel.add(number, BorderLayout.CENTER);
        return numberPanel;
    }


    /**
     * Creates a panel for setting generation rate
     *
     * @return panel containing GUI components for setting generation rate
     */
    private JPanel ratePanel() {
        JLabel label = new JLabel(JMeterUtils.getLocaleString(DDOS_PACKET_RATE)); //$NON-NLS-1$
        rate = new JTextField("100");
        rate.setName("naturalOrNothing");
        rate.setInputVerifier(verifier);
        label.setLabelFor(rate);
        JPanel ratePanel = new JPanel(new BorderLayout(5, 0));
        ratePanel.add(label, BorderLayout.WEST);
        ratePanel.add(rate, BorderLayout.CENTER);
        return ratePanel;
    }


    /**
     * Creates a panel for choosing output interface
     *
     * @return panel containing GUI components for choosing output interface
     */
    private JPanel interfPanel() {
        JLabel label = new JLabel(JMeterUtils.getLocaleString(DDOS_NET_INTERFACE)); //$NON-NLS-1$
        label.setLabelFor(selectInt);
        JPanel interfPanel = new JPanel(new BorderLayout(5, 0));
        interfPanel.add(label, BorderLayout.WEST);
        interfPanel.add(selectInt, BorderLayout.CENTER);
        return interfPanel;
    }


    /**
     * Performs GUI initialization
     */
    private void init() {
        setLayout(new BorderLayout(5, 5));
        setBorder(makeBorder());
        add(makeTitlePanel(), BorderLayout.NORTH);

        VerticalPanel mainPanel = new VerticalPanel();

        JPanel linkLayer = new VerticalPanel();
        linkLayer.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(Color.LIGHT_GRAY, Color.BLACK), JMeterUtils.getLocaleString(DDOS_LINK_LAYER))); // ohraniceni

        JPanel ipLayer = new VerticalPanel();
        ipLayer.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(Color.LIGHT_GRAY, Color.BLACK), JMeterUtils.getLocaleString(DDOS_IP_LAYER)));

        JPanel tcpLayer = new VerticalPanel();
        tcpLayer.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(Color.LIGHT_GRAY, Color.BLACK), JMeterUtils.getLocaleString(DDOS_TRANSPORT_LAYER)));

        JPanel payload = new VerticalPanel();
        payload.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(Color.LIGHT_GRAY, Color.BLACK), JMeterUtils.getLocaleString(DDOS_PAYLOAD)));

        JPanel attack = new VerticalPanel();
        attack.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(Color.LIGHT_GRAY, Color.BLACK), JMeterUtils.getLocaleString(DDOS_ATTACK_STRENGTH)));

        linkLayer.add(sMACPanel());
        linkLayer.add(dMACPanel());

        ipLayer.add(createServerPanel());
        ipLayer.add(sourceIPPanel());
        ipLayer.add(ttlPanel());

        tcpLayer.add(sourcePortPanel());
        tcpLayer.add(destPortPanel());
        tcpLayer.add(windowSizePanel());

        payload.add(payloadPanel());

        attack.add(numberPanel());
        attack.add(ratePanel());

        mainPanel.add(interfPanel());
        mainPanel.add(linkLayer);
        mainPanel.add(ipLayer);
        mainPanel.add(tcpLayer);
        mainPanel.add(payload);
        mainPanel.add(attack);

        add(mainPanel, BorderLayout.CENTER);
    }
    
    /**
     * Enables/disables GUI components (used when test starts/ends)
     *
     * @param en true if the components should be enabled, false if disabled
     */
    private void enableGUIComponents(boolean en) {
        if(ipv6Enabled.isSelected()) {
            targetIPv6.setEnabled(en);
            randomIPv6.setEnabled(en);
            numberOfIPv6Addresses.setEnabled(en);
            if (randomIPv6.isSelected()) {
                sourceIPv6Min.setEnabled(en);
                sourceIPv6Max.setEnabled(en);
            } else {
                sourceIPv6.setEnabled(en);
            }
        } else {
            targetIP.setEnabled(en);
            randomIP.setEnabled(en);
            if (randomIP.isSelected()) {
                sourceIPMIN.setEnabled(en);
                sourceIPMAX.setEnabled(en);
            } else {
                sourceIPsingle.setEnabled(en);
            }
        }
        ipv6Enabled.setEnabled(en);
        randomPort.setEnabled(en);
        if (randomPort.isSelected()) {
            sourcePortMIN.setEnabled(en);
            sourcePortMAX.setEnabled(en);
        } else {
            sourcePortSingle.setEnabled(en);
        }
        destPort.setEnabled(en);
        if (!dynamicRate) {
            number.setEnabled(en);
            rate.setEnabled(en);
        }
        incrementalMAC.setEnabled(en);
        if (incrementalMAC.isSelected()) {
            sMACmin.setEnabled(en);
            sMACmax.setEnabled(en);
        } else {
            sMACsingle.setEnabled(en);
        }
        dMAC.setEnabled(en);
        ttl.setEnabled(en);
        windowSize.setEnabled(en);
        payLoad.setEnabled(en);
        selectInt.setEnabled(en);
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void clearGui() {
        super.clearGui();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Collection<String> getMenuCategories() {
        return new ArrayList<String>();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JPopupMenu createPopupMenu() {
        JPopupMenu pop = new JPopupMenu();
        MenuFactory.addEditMenu(pop, true);
        MenuFactory.addFileMenu(pop);
        return pop;
    }

    /**
     * Registers a listener which reacts to start/end of the test events
     */
    private void registerTestStateListener() {
        TestStateListener testStateListener = new TestStateListener() {

            @Override
            public void testStarted() {
                enableGUIComponents(false);
            }

            @Override
            public void testStarted(String host) {
                testStarted();
            }

            @Override
            public void testEnded() {
                //Register again for a next run
                registerTestStateListener();
                enableGUIComponents(true);
            }

            @Override
            public void testEnded(String host) {
                testEnded();
            }
        };
        StandardJMeterEngine.register(testStateListener);
    }
}
