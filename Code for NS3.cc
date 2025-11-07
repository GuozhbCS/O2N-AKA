#include <stdlib.h>     /* srand, rand */
#include <math.h>
#include "ns3/core-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/csma-module.h"
#include "ns3/network-module.h"
#include "ns3/applications-module.h"
#include "ns3/olsr-helper.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/internet-module.h"
#include "ns3/netanim-module.h"
#include "ns3/basic-energy-source.h"
#include "ns3/flow-monitor-helper.h"


using namespace ns3;

static bool verbose = 0;

uint32_t M1=64, M2=64, M3=64, M4=64;;

char * stringbuilder( char* prefix,  char* sufix){
  char* buf = (char*)malloc(50); 
  snprintf(buf, 50, "%s%s", prefix, sufix);
  return  buf;
}


ApplicationContainer sendMessage(ApplicationContainer apps, double time, Ptr<Node>source,Ptr<Node>sink, uint32_t packetSize){
    Ipv4Address  remoteAddress = sink->GetObject<Ipv4> ()->GetAddress (1, 0).GetLocal ();
 	  
  uint16_t port = 9;  // well-known echo port number
  uint32_t maxPacketCount = 100;
  Time interPacketInterval = Seconds (5.);
  UdpClientHelper client (remoteAddress, port);
  client.SetAttribute ("MaxPackets", UintegerValue (maxPacketCount));
  client.SetAttribute ("Interval", TimeValue (interPacketInterval));
  client.SetAttribute ("PacketSize", UintegerValue (packetSize));
  client.SetAttribute ("StartTime", TimeValue (Seconds (time)));
  apps.Add(client.Install (source));
  return apps;
 }

ApplicationContainer authenticate(ApplicationContainer appContainer, double time, Ptr<Node> user, Ptr<Node> gateway , Ptr<Node> device ){	

  if (verbose){
    std::cout<<"user : "<< user->GetObject<Ipv4> ()->GetAddress (1, 0).GetLocal ();
    std::cout<<"gateway : "<< gateway->GetObject<Ipv4> ()->GetAddress (1, 0).GetLocal ();
    std::cout<<"device : "<< device->GetObject<Ipv4> ()->GetAddress (1, 0).GetLocal ()<<std::endl;
  }
	
	appContainer = sendMessage(appContainer, time, user, gateway, M1);
	appContainer = sendMessage(appContainer, time, gateway, device,  M2); 
	appContainer = sendMessage(appContainer, time, device, gateway, M3); 
        appContainer = sendMessage(appContainer, time, gateway, user, M4);
        //appContainer = sendMessage(appContainer, time, gateway, device,  M5);
        //appContainer = sendMessage(appContainer, time, user, device,  M6);
        //appContainer = sendMessage(appContainer, time, device, gateway,  M7);
        //appContainer = sendMessage(appContainer, time, gateway, user,  M8);
  return appContainer;
}


int main (int argc, char *argv[])
{
  
  uint32_t mobileUserNodes = 5;
  uint32_t smartDeviceNodes = 2;
  uint32_t stopTime = 1600;
  bool verbose = 0;
  bool enablePcap = 0;
  bool enableAnim = 0;
  bool verifyResults = 0; //used for regression
  char saveFilePrefix[50];
  

  CommandLine cmd;
  //cmd.AddValue ("backboneNodes", "number of backbone nodes", backboneNodes);
  cmd.AddValue ("MU", "number of User nodes", mobileUserNodes);
  cmd.AddValue ("SD", "number of smart device nodes", smartDeviceNodes);
  cmd.AddValue ("t", "simulation stop time (seconds)", stopTime);  
  cmd.AddValue ("p", "Enable/disable pcap file generation", enablePcap);
  cmd.AddValue ("a", "Enable/disable xml gneration for netanim-module", enableAnim);
  cmd.AddValue ("o", "Show output end of the simulation", verifyResults);
  cmd.AddValue ("v", "Verbose mode.", verbose);
  cmd.AddValue ("s", "Define the prefix for .pcap anf .xml files. Default: IOT ", saveFilePrefix);
  cmd.AddValue ("M1", "Size of message 1 ", M1);
  cmd.AddValue ("M2", "Size of message 2 ", M2);
  cmd.AddValue ("M3", "Size of message 3 ", M3);
  cmd.AddValue ("M4", "Size of message 4 ", M4);

  cmd.Parse (argc, argv);

  if (verbose)
  {
    LogComponentEnable("Simulator", LOG_LEVEL_INFO);
  }
  
  // Config::SetDefault ("ns3::LogDistancePropagationLossModel::ReferenceLoss", DoubleValue (40.046));
  //创建节点
  //动态 用户节点
  NodeContainer wifiUserNodes;
  wifiUserNodes.Create (mobileUserNodes);
  //动态 传感器节点
  NodeContainer wifiDeviceNodes;
  wifiDeviceNodes.Create (smartDeviceNodes);
  //1个网关节点
  NodeContainer wifiGateway ;
  wifiGateway.Create (1);
 
  std::string phyMode ("OfdmRate6Mbps");

    WifiHelper wifi;
    wifi.SetStandard (WIFI_PHY_STANDARD_80211a);
    YansWifiPhyHelper phy = YansWifiPhyHelper::Default ();
    phy.SetPcapDataLinkType (YansWifiPhyHelper::DLT_IEEE802_11_RADIO);
    YansWifiChannelHelper wifiChannel;
   // phy.set('EnergyDetectionThreshold',DoubleValue(-71.9842))
    wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
    wifiChannel.AddPropagationLoss ("ns3::LogDistancePropagationLossModel",
                "Exponent", DoubleValue (0.1));
    Config::SetDefault ("ns3::LogDistancePropagationLossModel::ReferenceLoss", DoubleValue (40.046)); 
    phy.SetChannel (wifiChannel.Create ());
    NqosWifiMacHelper wifiMac = NqosWifiMacHelper::Default ();
    wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                    "DataMode",StringValue (phyMode),
                    "ControlMode",StringValue (phyMode),
                    "RtsCtsThreshold", UintegerValue(0));
    
    wifiMac.SetType ("ns3::AdhocWifiMac");
    NetDeviceContainer apDevices = wifi.Install (phy, wifiMac, wifiGateway);

    wifiMac.SetType ("ns3::AdhocWifiMac");
    NetDeviceContainer UserDevices = wifi.Install (phy, wifiMac, wifiUserNodes);

    wifiMac.SetType ("ns3::AdhocWifiMac");
    NetDeviceContainer SmartDevices = wifi.Install (phy, wifiMac, wifiDeviceNodes);    


   /* 添加移动模型，使sta节点处于移动状态，使ap节点处于静止状态 */
  // 设置范围和移动方式
  MobilityHelper mobility;
  // 设置位置分配器，用于分配MobilityModel :: Install中初始化的每个节点的初始位置
  mobility.SetPositionAllocator ("ns3::GridPositionAllocator",
                                 "MinX", DoubleValue (-10.0),
                                 "MinY", DoubleValue (-10.0),
                                 "DeltaX", DoubleValue (5.0),
                                 "DeltaY", DoubleValue (5.0),
                                 "GridWidth", UintegerValue (5),
                                 "LayoutType", StringValue ("RowFirst"));

  mobility.SetMobilityModel ("ns3::RandomDirection2dMobilityModel",
                                 "Bounds", RectangleValue (Rectangle (-150, 150, -150, 150)),
                                 "Speed", StringValue ("ns3::ConstantRandomVariable[Constant=3]"),
                                 "Pause", StringValue ("ns3::ConstantRandomVariable[Constant=0.4]"));
  mobility.Install (wifiUserNodes);//// 把该移动模型安装到user节点上

 
  Ptr<ListPositionAllocator> subnetAlloc =   CreateObject<ListPositionAllocator> ();
  subnetAlloc->Add (Vector (0.0, 0.0, 0.0));   //for gateway
  for (uint32_t j = 0; j < wifiDeviceNodes.GetN (); ++j){
    double  theta = (j)*360/wifiDeviceNodes.GetN();
    uint32_t  r =((double)rand() / (RAND_MAX))*80 +20;
    subnetAlloc->Add (Vector (sin(theta)*r, cos(theta)*r, 0.0));
  }

  mobility.SetPositionAllocator (subnetAlloc);
  mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");// 固定位置的模型
  mobility.Install (wifiGateway);
  mobility.Install (wifiDeviceNodes);


  /* 安装协议栈 */
  InternetStackHelper stack;
 // OlsrHelper olsr;
 // stack.SetRoutingHelper (olsr);
  stack.Install (wifiUserNodes);
  stack.Install (wifiDeviceNodes);
  stack.Install (wifiGateway);

  /* 给设备接口分配IP地址 */
  Ipv4AddressHelper address;

  address.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer apInterface; // apInterfaces用于获取ap节点的ip地址
  apInterface = address.Assign (apDevices);
  Ipv4InterfaceContainer staInterfaces; // staInterfaces用于获取sta节点的ip地址
  staInterfaces = address.Assign (UserDevices);
  staInterfaces = address.Assign (SmartDevices);

  /* 创建clien和server应用 */
  /* 创建clien和server应用 */
  ApplicationContainer serverAppContainer, clientAppContainer;
  uint16_t port = 9; // 创建一个端口号为9的server
  Ptr<Node> gateway = wifiGateway.Get (0);
  UdpServerHelper server(port);
  //UdpEchoServerHelper echoServer (port);
  serverAppContainer.Add(server.Install (gateway)); // 把该server安装到ap节点上
  //serverAppContainer = echoServer.Install (gateway);


  double time = 1;
  for (uint32_t i = 0; i < wifiUserNodes.GetN (); ++i)
  {
	  Ptr<Node> user = wifiUserNodes.Get (i);
    serverAppContainer.Add(server.Install (user));
    //serverAppContainer = echoServer.Install (user);
    
	  for (uint32_t j = 0; j < wifiDeviceNodes.GetN (); ++j)
    {
		  Ptr<Node> device = wifiDeviceNodes.Get (j);
        if(i==0)
       {
      serverAppContainer.Add(server.Install (device));
       }
      clientAppContainer = authenticate(clientAppContainer,time,user,gateway,device ); 
	  }
    
  }


  serverAppContainer.Start (Seconds (1.0));
  serverAppContainer.Stop (Seconds (stopTime+1));
  //clientAppContainer.Start (Seconds (2.0));   //started induvugualy
  clientAppContainer.Stop (Seconds (stopTime+1));

  snprintf(saveFilePrefix, 50, "IOT_%dx%d_", mobileUserNodes, smartDeviceNodes);

 if (enablePcap)
 {
  phy.EnablePcap (stringbuilder(saveFilePrefix,(char*)"_users"), UserDevices, 0);
  phy.EnablePcap (stringbuilder(saveFilePrefix,(char*)"_devices"), SmartDevices, 0);
  phy.EnablePcap (stringbuilder(saveFilePrefix,(char*)"_gateway"), apDevices, 0);
 }

  /* 启用互联网络路由 */
  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();
  Ptr<FlowMonitor> flowMonitor;
  FlowMonitorHelper flowHelper;
  flowMonitor = flowHelper.InstallAll();
  // setting up simulator
  Simulator::Stop (Seconds (stopTime+1));
  Simulator::Run ();
  Simulator::Destroy ();
  flowMonitor->SerializeToXmlFile(stringbuilder(saveFilePrefix,(char*)"_flowMonitor.xml"), false, false);

  return 0;
}
