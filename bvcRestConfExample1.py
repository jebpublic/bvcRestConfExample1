#!/usr/bin/env python
"""
bvcRestConfExample1.py is an example Python application that demonstrates
    how to use the BVC RESTconf api.

    The main goal is as an example of coding to BVC 
    RESTconf api.

    bvcRestConfExample1.py uses the BVC RESTconf api to provide packet
    forwarding between hosts on a single switch even when
    the BVC Host Tracker's arphandler is configured to be in
    passive mode.

    bvcRestConfExample1.py is not the best way to provide forwarding.  
    bvcRestConfExample1.py is not the best Python code.
    bvcRestConfExample1.py has been tested in only one environment:
       BVC 1.1.1 with HostTracker configured to use
       passive mode, Mininet in its default topology of 
       one (1) switch and two (2) hosts.
    

    PRE-REQUISITES:
       1.  Install python-requests:
             a.  sudo easy_install requests OR sudo pip install requests
       2.  Install websocket-client:
             a.  sudo easy_install websocket-client  OR  sudo pip install websocket-client

    SETUP:
       1.  Configure BVC 1.1.1 HostTracker to use passive mode
       2.  Start BVC 1.1.1
       3.  Start Mininet and set its controller to BVC
             sudo mn --controller=remote,ip=<ip of BVC>

    RUN:
       1.  At the command line:
             bvcRestConfExample1 -c <bvc_ip>

           WHERE:
               <bvc_ip> is the ip address of BVC (you should be able to ping it from 
                    where you are running bvcRestConfExample1)

    TRY IT:
       1.  Start bvcRestConfExample1 -c <bvc_ip>
       2.  On mininet do a pingall
              - the hosts should be able to ping each other (something that normally
                fails when HostTracker is in passive mode)

    USAGE:
       bvcRestConfExample1.py [options]

       Options:
         -c --controller <ip address>  the IP address of the BVC 1.1.1 (you should be able to ping it). Example:  192.168.56.101
         -h                            this help

 
Mail bug reports and suggestion to : jeb@elbrys.com
Although it is better if you post a comment below wherever you retrieved this app
since then the whole community will benefit.  I am watching everywhere that I have
posted this.
"""
 
import getopt, sys   
import requests
from requests.auth import HTTPBasicAuth
from websocket import create_connection
 

def RConfCreateStream(rConfBaseUrl):
    # This calls RESTConf api to create a stream to nodes in operational data store
    # RETURNS: stream's url or None if fail
    url = rConfBaseUrl + '/operations/sal-remote:create-data-change-event-subscription'
    headers = {'content-type': 'application/xml',
                'accept': 'application/json'}

    payload = '<input xmlns="urn:opendaylight:params:xml:ns:yang:controller:md:sal:remote"> \
                    <path xmlns:a="urn:TBD:params:xml:ns:yang:network-topology">/a:network-topology</path> \
                    <datastore xmlns="urn:sal:restconf:event:subscription">OPERATIONAL</datastore> \
                    <scope xmlns="urn:sal:restconf:event:subscription">SUBTREE</scope> \
                </input>'
    r = requests.post(url, data=payload, headers=headers, auth=HTTPBasicAuth('admin','admin'))
    streamName = r.text
    #print streamName

    if ('error' in streamName):
        print "Error: " + streamName
        return None
    else:
        streamName = r.json()
        streamName = streamName['output']
        streamName = streamName['stream-name']
        return streamName

def RConfSubscribeStream(rConfBaseUrl, streamName):
    # This calls the RESTConf api to suscribed to the stream at streamName
    # RETURNS: stream's url at which to listen with web socket
    url = rConfBaseUrl + '/streams/stream/' + streamName
    #print url
    headers = {'content-type': 'application/json',
                'accept': 'application/json'}
    r = requests.get(url, headers=headers, auth=HTTPBasicAuth('admin','admin'))
    streamListenUrl = r.headers['location']
    return streamListenUrl


def RConfGetTopology(rConfBaseUrl):
    # This calls the RESTConf api to get the topology
    # RETURNS topology
    url = rConfBaseUrl + '/operational/network-topology:network-topology/'
    #print url
    headers = {'content-type': 'application/json',
                'accept': 'application/json'}
    r = requests.get(url, headers=headers, auth=HTTPBasicAuth('admin','admin'))
    topo = r.json()
    return topo

def AddFlows(rConfBaseUrl,switchId,flowId,hostMac):
    #Adds two (2) flows with flowId and flowId+1 to switch switchId that has priority of 100
    # that will flood all ARP packets from host with hostMac
    print "Adding flows, switchId " + switchId + ", flowId: " + str(flowId) + ", hostMac: " + hostMac
    url = rConfBaseUrl + '/config/opendaylight-inventory:nodes/node/'+switchId+'/table/0/flow/'+ str(flowId)

    headers = {'content-type': 'application/json',
                'accept': 'application/json'}

    payload = '{"flow": \
    {"id":"'+str(flowId)+'",\
     "instructions": {"instruction": [\
          {"order": 0,"apply-actions": {"action": [\
                                        {"order": 0,"output-action": {"max-length": 65535,\
                                        "output-node-connector": "FLOOD"\
                                        }}]}}]},\
      "match": {"ethernet-match": {"ethernet-source": {"address": "'+hostMac+'"}}},\
      "priority": 100,"table_id": 0,"hard-timeout": 0,"idle-timeout": 0} }'

    r = requests.put(url, data=payload, headers=headers, auth=HTTPBasicAuth('admin','admin')) 
    print r.text  

    flowId=flowId+1
    url = rConfBaseUrl + '/config/opendaylight-inventory:nodes/node/'+switchId+'/table/0/flow/'+ str(flowId)
    payload = '{"flow": \
    {"id":"'+str(flowId)+'",\
     "instructions": {"instruction": [\
          {"order": 0,"apply-actions": {"action": [\
                                        {"order": 0,"output-action": {"max-length": 65535,\
                                        "output-node-connector": "FLOOD"\
                                        }}]}}]},\
      "match": {"ethernet-match": {"ethernet-destination": {"address": "'+hostMac+'"}}},\
      "priority": 100,"table_id": 0,"hard-timeout": 0,"idle-timeout": 0} }'

    r = requests.put(url, data=payload, headers=headers, auth=HTTPBasicAuth('admin','admin')) 
    print r.text  

def UpdateForwardingRules(rConfBaseUrl,topology):
    #Looks at topology and outputs flows to foward packets
    # between all known hosts
    #Returns nothing

    print "Updating forwarding rules..."

    hosts = []
    switches = []

    if ('network-topology' not in topology):
        print "....no topology."
        return
    else:
        net = topology['network-topology']
        net = net['topology']

        for topo in net:
            topo_id = topo['topology-id']
            if 'node' in topo:
                nodes = topo['node']
                for node in nodes:
                    node_id = node['node-id']
                    if 'host:' in node_id:
                        host = node_id.replace("host:","",1)
                        print "new host: " + host
                        hosts.append(host)
                    else:
                        switch = node_id
                        print "new switch: " + switch
                        switches.append(switch)
    flowId=10
    for host in hosts:
        for switch in switches:
            AddFlows(rConfBaseUrl,switch,flowId,host)
        flowId=flowId+5


def PrintTopology(topology):
    #Prints out provided topology.  It is indented 12 spaces.
    #print topology

    print "            ======================================================"
    print "            Topology"
    print "            ======================================================"

    if ('network-topology' not in topology):
        print "            No toplogy."
    else:
        net = topology['network-topology']
        net = net['topology']

        for topo in net:
            topo_id = topo['topology-id']
            print "            Network: " + topo_id
            if 'node' in topo:
                nodes = topo['node']
                for node in nodes:
                    node_id = node['node-id']
                    print "                Node: " + node_id
                    if 'termination-point' in node:
                        ports = node['termination-point']
                        for port in ports:
                            port_id = port['tp-id']
                            print "                    Port: " + port_id

    print "            ======================================================"

 
def main(): 

    # The url to redirect unauthenticated endpoints to
    bvcIp = None
    hosts = None

    # The version of the application
    version="1.0"

    print "EXAMPLE application that uses RESTConf of Brocade Vyatta Controller 1.1.1"
    print "Version: " + version

    # --------------------------------
    #    Parse Command Line Parameters
    try:
        cmdlineOptions, args= getopt.getopt(sys.argv[1:],'he:',["help","controller="])
    except getopt.GetoptError, e:
        print "Error in a command-line option:\n\t" + str(e)
 
    for (optName,optValue) in cmdlineOptions:
        if  optName in ("-h","--help"):
            print __doc__
            sys.exit()
        elif optName in ("-c","--controller"):
            bvcIp = optValue
        else:
            errorHandler('Option %s not recognized' % optName)
 
    # --------------------------------
    #    Main logic
    if not(bvcIp):

        print __doc__
        print "ERROR:  You must provide IP address for the RESTConf Controller (BVC), for example: "
        print "         bvcRestConfExample1 --controller 192.168.56.101 "
        sys.exit()
    else:
        rConfBaseUrl = "http://"+bvcIp+":8181/restconf"
        print "Base URL for RESTConf is: " + rConfBaseUrl
        topology = RConfGetTopology(rConfBaseUrl)
        UpdateForwardingRules(rConfBaseUrl,topology)
        print "    Starting Topology: "
        PrintTopology(topology)

        streamName = RConfCreateStream(rConfBaseUrl)
        if (streamName is None): sys.exit()
        print "    Stream created, name: " + streamName
        streamUrl = RConfSubscribeStream(rConfBaseUrl, streamName)
        if (streamUrl is None): sys.exit()
        print "    Subscription to stream complete, url: " + streamUrl

        streamUrl = streamUrl.replace("http:","ws:",1)
        ws = create_connection(streamUrl)

        while True:
            print "        Listening on stream for topology change... (ctrl-c to exit)"
            result =  ws.recv()
            #print "        Received '%s'" % result
            print "         Change detected, new topology: "
            topology = RConfGetTopology(rConfBaseUrl)
            UpdateForwardingRules(rConfBaseUrl,topology)
            PrintTopology(topology)

        ws.close()

 
if __name__ == "__main__": 
  main()
