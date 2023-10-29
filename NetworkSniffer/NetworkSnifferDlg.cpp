
// NetworkSnifferDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "NetworkSniffer.h"
#include "NetworkSnifferDlg.h"
#include "afxdialogex.h"
#include "CNICDlg.h"
#include "CfilterDlg.h"
#include "packethead.h"
#include<iostream>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CNetworkSnifferDlg 对话框



CNetworkSnifferDlg::CNetworkSnifferDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_NETWORKSNIFFER_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CNetworkSnifferDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, LControl);
	DDX_Control(pDX, IDC_TREE1, mytree);
	DDX_Control(pDX, IDC_EDIT1, myedit);
	
}

BEGIN_MESSAGE_MAP(CNetworkSnifferDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST1, &CNetworkSnifferDlg::OnLvnItemchangedList1)
	ON_COMMAND(ID_NIC, &CNetworkSnifferDlg::OnNic)
	ON_COMMAND(ID_filter, &CNetworkSnifferDlg::Onfilter)
	ON_BN_CLICKED(IDC_BUTTON1, &CNetworkSnifferDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CNetworkSnifferDlg::OnBnClickedButton2)
	ON_BN_CLICKED(IDC_BUTTON4, &CNetworkSnifferDlg::OnBnClickedButton4)
END_MESSAGE_MAP()


// CNetworkSnifferDlg 消息处理程序

BOOL CNetworkSnifferDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	//数据包概览界面（ListControl）初始化
	LControl.SetExtendedStyle(LControl.GetExtendedStyle() | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);// 为列表视图控件添加全行选中和栅格风格
	LControl.InsertColumn(0, _T("序号"), LVCFMT_CENTER, 50);
	LControl.InsertColumn(1, _T("时间"), LVCFMT_CENTER, 200);
	LControl.InsertColumn(2, _T("源地址"), LVCFMT_CENTER, 160);
	LControl.InsertColumn(3, _T("目的地址"), LVCFMT_CENTER, 160);
	LControl.InsertColumn(4, _T("协议"), LVCFMT_CENTER, 80);
	LControl.InsertColumn(5, _T("长度"), LVCFMT_CENTER, 80);
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CNetworkSnifferDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CNetworkSnifferDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CNetworkSnifferDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



//从网卡的子对话框获取选择的网卡
void CNetworkSnifferDlg::OnNic()
{
	// TODO: 在此添加命令处理程序代码
	CNICDlg nicdlg;
	if (nicdlg.DoModal() == IDOK)
	{
		myNIC = nicdlg.cNIC;
	}
}

//从过滤的子对话框获取选择的过滤规则
void CNetworkSnifferDlg::Onfilter()
{
	// TODO: 在此添加命令处理程序代码
	CfilterDlg filterdlg;
	filterdlg.DoModal();
	int iSize;
	//将宽字符转换为多字节字符
	iSize = WideCharToMultiByte(CP_ACP, 0, filterdlg.filters, -1, NULL, 0, NULL, NULL);
	myfilter = (char*)malloc(iSize * sizeof(char));
	WideCharToMultiByte(CP_ACP, 0, filterdlg.filters, -1, myfilter, iSize, NULL, NULL);
}
//捕获数据包的子线程
UINT CNetworkSnifferDlg::CaptureThread(void* lpParam)
{
	CNetworkSnifferDlg* cDlg = (CNetworkSnifferDlg*)lpParam;//子线程为静态对象，需要由参数传进主对话框来获取数据
	pcap_t  *pcap_session;
	struct bpf_program fp;
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	char errbuf[PCAP_ERRBUF_SIZE];//错误信息
	int captureflag;//标志位，用来判断获取数据包时的状态
	bpf_u_int32 net;//子网掩码
	//创建嗅探会话
	if (cDlg->myNIC == NULL)
	{
		AfxMessageBox(_T("网卡未绑定"));
		return -1;
	}
	if ((pcap_session = pcap_open_live(cDlg->myNIC->name, 65536, 1, 1000, errbuf))==NULL)
	{
		AfxMessageBox(_T("会话获取失败"));
		return -1;
	}
	//获取掩码
	if (cDlg->myNIC->addresses != NULL)
	{
		net = ((struct sockaddr_in*)(cDlg->myNIC->addresses->netmask))->sin_addr.S_un.S_addr;
	}
	else
	{
		net = 0xffffff;
	}
	//设置过滤规则
	if (pcap_compile(pcap_session, &fp, cDlg->myfilter, 1, net) == -1)
	{
		AfxMessageBox(_T("过滤规则出错"));
		return -1;
	}
	pcap_setfilter(pcap_session, &fp);
	//捕获数据包
	while ((captureflag = pcap_next_ex(pcap_session, &pkt_header, &pkt_data)) >= 0)
	{
		if (captureflag == 0)//读取超时没有获取到数据包
		{
			if (cDlg->OnOff == 0)
				break;
			continue;
		}
		if (cDlg->OnOff == 0)//OnOff标志位由开始捕获和停止捕获按钮确定，用来控制捕获线程的开启暂停
			break;
		CNetworkSnifferDlg* cDlg = (CNetworkSnifferDlg*)AfxGetApp()->GetMainWnd();
		cDlg->ShowList(pkt_header, pkt_data);
		cDlg = NULL;
	}
	//关闭会话
	pcap_close(pcap_session);
	cDlg = NULL;
	return 1;

}
//开始捕获按钮，开启捕获线程
void CNetworkSnifferDlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
	OnOff = 1;
	AfxBeginThread(CaptureThread, this);
}
//停止捕获按钮，停止捕获线程
void CNetworkSnifferDlg::OnBnClickedButton2()
{
	// TODO: 在此添加控件通知处理程序代码
	OnOff = 0;
}
//显示捕获数据包的概要信息在ListControl控件中
int CNetworkSnifferDlg::ShowList(struct pcap_pkthdr* pkt_header, const u_char* pkt_data)
{
	//存储捕获到的数据包到数组中
	struct pcap_pkthdr* pkt_header_copy = (struct pcap_pkthdr*)malloc(sizeof(struct pcap_pkthdr));
	memcpy(pkt_header_copy, pkt_header, sizeof(struct pcap_pkthdr));
	pktHeaders.Add(pkt_header_copy);
	u_char* pkt_data_copy = (u_char*)malloc(pkt_header->caplen);
	memcpy(pkt_data_copy, pkt_data, pkt_header->caplen);
	pktDatas.Add(pkt_data_copy);
	struct ethheader* eth = (struct ethheader*)pkt_data;
	
	// 显示序号
	CString str;
	str.Format(_T("%d"), nCount);
	LControl.InsertItem(nCount, str);

	// 并显示捕获时间
	struct tm ltime;
	char timestr[16];
	time_t local_tv_sec;
	local_tv_sec = pkt_header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);
	wchar_t w_timestr[16];
	MultiByteToWideChar(CP_ACP, 0, timestr, -1, w_timestr, sizeof(w_timestr) / sizeof(w_timestr[0]));
	str.Format(_T("%s.%06d"), w_timestr, pkt_header->ts.tv_usec);
	LControl.SetItemText(nCount, 1, str);

	//显示包的长度
	CString packet_length_str;
	packet_length_str.Format(_T("%u"), pkt_header->caplen);
	LControl.SetItemText(nCount, 5, packet_length_str); 

	//显示IPv4数据包的摘要信息
    if (ntohs(eth->ether_type) == 0x0800) 
	{ 
		struct ipheader* ip = (struct ipheader*)
			(pkt_data + sizeof(struct ethheader));
		//显示源IP地址
		struct in_addr src_addr;
		src_addr.s_addr = ip->iph_sourceip.s_addr;
		char str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &(src_addr.s_addr), str, INET_ADDRSTRLEN);
		int len = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
		wchar_t* wstr = new wchar_t[len];
		MultiByteToWideChar(CP_ACP, 0, str, -1, wstr, len);
		CString src_addr_str;
		src_addr_str.Format(_T("%s"), wstr);
		LControl.SetItemText(nCount, 2, src_addr_str); 

		//显示目标IP地址
		struct in_addr dest_addr;
		dest_addr.s_addr = ip->iph_destip.s_addr;
		inet_ntop(AF_INET, &(dest_addr.s_addr), str, INET_ADDRSTRLEN);
		len = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
		wstr = new wchar_t[len];
		MultiByteToWideChar(CP_ACP, 0, str, -1, wstr, len);
		CString dest_addr_str;
		dest_addr_str.Format(_T("%s"), wstr);
		LControl.SetItemText(nCount, 3, dest_addr_str); 
		delete[] wstr;

		//区分ipv4包上层协议tcp，udp，icmp，进一步区分tcp上层协议http
		CString pstr;
		struct tcpheader* tcp;
		u_int size_ip;
		switch (ip->iph_protocol) {
		case IPPROTO_TCP:
			size_ip = ip->iph_ihl*4;
			tcp = (struct tcpheader*)
				(pkt_data + sizeof(struct ethheader)+size_ip);
			if (ntohs(tcp->tcp_dport) == 80 || ntohs(tcp->tcp_sport) == 80)
			{
				pstr = _T("HTTP");
				LControl.SetItemText(nCount, 4, pstr);
			}
			else if (ntohs(tcp->tcp_dport) == 443 || ntohs(tcp->tcp_sport) == 443)
			{
				pstr = _T("HTTPS");
				LControl.SetItemText(nCount, 4, pstr);
			}
			else
			{
				pstr = _T("TCP");
				LControl.SetItemText(nCount, 4, pstr);
			}
			nCount++;
			return 0;
		case IPPROTO_UDP:
			pstr = _T("UDP");
			LControl.SetItemText(nCount, 4, pstr);
			nCount++;
			return 0;
		case IPPROTO_ICMP:
			pstr = _T("ICMP");
			LControl.SetItemText(nCount, 4, pstr);
			nCount++;
			return 0;
		default:
			pstr = _T("IPV4");
			LControl.SetItemText(nCount, 4, pstr);
			nCount++;
			return 0;
		}
	}
   else if(ntohs(eth->ether_type) == 0x86DD)//显示IPv6数据包的摘要信息
   {
	   struct ipv6header* ip = (struct ipv6header*)
			(pkt_data + sizeof(struct ethheader));
	   //显示源IP地址
	   struct in6_addr src_addr;
	   src_addr = ip->ipv6_source;
	   char str[INET6_ADDRSTRLEN];
	   inet_ntop(AF_INET6, &src_addr, str, INET6_ADDRSTRLEN);
	   int len = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
	   wchar_t* wstr = new wchar_t[len];
	   MultiByteToWideChar(CP_ACP, 0, str, -1, wstr, len);
	   CString src_addr_str;
	   src_addr_str.Format(_T("%s"), wstr);
	   LControl.SetItemText(nCount, 2, src_addr_str); 

	   //显示目标IP地址
	   struct in6_addr dest_addr;
	   dest_addr = ip->ipv6_dest;
	   inet_ntop(AF_INET6, &dest_addr, str, INET6_ADDRSTRLEN);
	   len = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
	   wstr = new wchar_t[len];
	   MultiByteToWideChar(CP_ACP, 0, str, -1, wstr, len);
	   CString dest_addr_str;
	   dest_addr_str.Format(_T("%s"), wstr);
	   LControl.SetItemText(nCount, 3, dest_addr_str); 

	   CString pstr;
	   pstr = _T("IPV6");
	   LControl.SetItemText(nCount, 4, pstr);
	   nCount++;
	   return 0;
   }
   else if (ntohs(eth->ether_type) == 0x0806)//显示arp数据包的摘要信息
	{
	    struct arpheader* arp = (struct arpheader*)(pkt_data + sizeof(struct ethheader));
		//显示源IP地址
		struct in_addr src_addr;
		memcpy(&src_addr, arp->sender_ip, sizeof(arp->sender_ip));
		char str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &src_addr, str, INET_ADDRSTRLEN);
		int len = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
		wchar_t* wstr = new wchar_t[len];
		MultiByteToWideChar(CP_ACP, 0, str, -1, wstr, len);
		CString src_addr_str;
		src_addr_str.Format(_T("%s"), wstr);
		LControl.SetItemText(nCount, 2, src_addr_str); 

		//显示源IP地址
		struct in_addr dest_addr;
		memcpy(&dest_addr, arp->target_ip, sizeof(arp->target_ip));
		inet_ntop(AF_INET, &dest_addr, str, INET_ADDRSTRLEN);
		len = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
		wstr = new wchar_t[len];
		MultiByteToWideChar(CP_ACP, 0, str, -1, wstr, len);
		CString dest_addr_str;
		dest_addr_str.Format(_T("%s"), wstr);
		LControl.SetItemText(nCount, 3, dest_addr_str); 

		CString pstr;
		pstr = _T("ARP");
		LControl.SetItemText(nCount, 4, pstr);
		nCount++;
		return 0;
	}
    nCount++;
	return 0;
}
//详细解析TCP包，呈现在TreeControl控件中
void CNetworkSnifferDlg::DisplayPacketDetails_TCP(const u_char* pkt_data)
{
	// 清除TreeControl中的所有项
	mytree.DeleteAllItems();

	// 创建根节点
	HTREEITEM hRoot = mytree.InsertItem(_T("Packet Details"));

	// 解析以太网头
	ethheader* eth = (ethheader*)pkt_data;
	HTREEITEM hEth = mytree.InsertItem(_T("Ethernet Header"), hRoot);
	mytree.InsertItem(_T("Destination Host: ") + ConvertToHex(eth->ether_dhost, 6), hEth);
	mytree.InsertItem(_T("Source Host: ") + ConvertToHex(eth->ether_shost, 6), hEth);
	u_char ether_type[2];
	memcpy(ether_type, &eth->ether_type, 2);
	mytree.InsertItem(_T("Type: ") + ConvertToHex(ether_type, 2), hEth);

	// 解析IP头
	ipheader* iph = (ipheader*)(pkt_data + sizeof(ethheader));
	HTREEITEM hIph = mytree.InsertItem(_T("IP Header"), hRoot);
	// IP版本和头部长度
	CString ip_ver;
	ip_ver.Format(_T("Version: %d"), iph->iph_ver);
	mytree.InsertItem(ip_ver, hIph);
	CString ip_hl;
	ip_hl.Format(_T("Header Length: %d Byte"), iph->iph_ihl*4);
	mytree.InsertItem(ip_hl, hIph);

	// 服务类型
	CString ip_tos;
	ip_tos.Format(_T("Type of Service: %d"), iph->iph_tos);
	mytree.InsertItem(ip_tos, hIph);

	// IP包长度
	CString ip_len;
	ip_len.Format(_T("IP Packet Length: %d"), ntohs(iph->iph_len));
	mytree.InsertItem(ip_len, hIph);

	// 标识
	CString ip_id;
	ip_id.Format(_T("Identification: %d"), ntohs(iph->iph_ident));
	mytree.InsertItem(ip_id, hIph);

	// 分段标志和偏移
	CString ip_flag;
	ip_flag.Format(_T("Fragmentation Flags: %d"), iph->iph_flag);
	mytree.InsertItem(ip_flag, hIph);
	CString ip_offset;
	ip_offset.Format(_T("Flags Offset: %d"), iph->iph_offset);
	mytree.InsertItem(ip_offset, hIph);

	// 生存时间
	CString ip_ttl;
	ip_ttl.Format(_T("Time to Live: %d"), iph->iph_ttl);
	mytree.InsertItem(ip_ttl, hIph);

	// 协议类型
	CString ip_protocol;
	CString ip_protocol_desc;
	switch (iph->iph_protocol) {
	case 1:
		ip_protocol_desc = _T("ICMP");
		break;
	case 6:
		ip_protocol_desc = _T("TCP");
		break;
	case 17:
		ip_protocol_desc = _T("UDP");
		break;
	default:
		ip_protocol_desc = _T("Other Protocol");
	}
	ip_protocol.Format(_T("Protocol Type: %d (%s)"), iph->iph_protocol, ip_protocol_desc);
	mytree.InsertItem(ip_protocol, hIph);

	// IP数据报校验和
	CString ip_chksum;
	ip_chksum.Format(_T("IP Datagram Checksum: %d"), ntohs(iph->iph_chksum));
	mytree.InsertItem(ip_chksum, hIph);

	//源IP地址
	char str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(iph->iph_sourceip.s_addr), str, INET_ADDRSTRLEN);
	int len = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
	wchar_t* wstr = new wchar_t[len];
	MultiByteToWideChar(CP_ACP, 0, str, -1, wstr, len);
	CString addr_str;
	addr_str.Format(_T("%s"), wstr);
	mytree.InsertItem(_T("Source IP: ") + addr_str, hIph);
	//目标IP地址
	inet_ntop(AF_INET, &(iph->iph_destip.s_addr), str, INET_ADDRSTRLEN);
	len = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
	wstr = new wchar_t[len];
	MultiByteToWideChar(CP_ACP, 0, str, -1, wstr, len);
	addr_str.Format(_T("%s"), wstr);
	mytree.InsertItem(_T("Destination IP: ") + addr_str, hIph);
	delete[] wstr;

	// 解析TCP头，源端口和目标端口号
	tcpheader* tcph = (tcpheader*)(pkt_data + sizeof(ethheader) + iph->iph_ihl * 4);
	HTREEITEM hTcph = mytree.InsertItem(_T("TCP Header"), hRoot);
	CString port;
	port.Format(_T("%u"), ntohs(tcph->tcp_sport));
	mytree.InsertItem(_T("Source Port: ") + port, hTcph);
	port.Format(_T("%u"), ntohs(tcph->tcp_dport));
	mytree.InsertItem(_T("Destination Port: ") + port, hTcph);

	// 序列号
	CString seq;
	seq.Format(_T("Sequence Number: %u"), ntohl(tcph->tcp_seq));
	mytree.InsertItem(seq, hTcph);

	// 确认号
	CString ack;
	ack.Format(_T("Acknowledgement Number: %u"), ntohl(tcph->tcp_ack));
	mytree.InsertItem(ack, hTcph);

	// 数据偏移
	CString off;
	off.Format(_T("Data Offset: %u"), TH_OFF(tcph));
	mytree.InsertItem(off, hTcph);

	// TCP标志
	CString flags;
	flags.Format(_T("Flags: %u"), tcph->tcp_flags);
	mytree.InsertItem(flags, hTcph);

	// 窗口大小
	CString win;
	win.Format(_T("Window Size: %u"), ntohs(tcph->tcp_win));
	mytree.InsertItem(win, hTcph);

	// 校验和
	CString sum;
	sum.Format(_T("Checksum: %u"), ntohs(tcph->tcp_sum));
	mytree.InsertItem(sum, hTcph);

	// 紧急指针
	CString urp;
	urp.Format(_T("Urgent Pointer: %u"), ntohs(tcph->tcp_urp));
	mytree.InsertItem(urp, hTcph);
	// 展开所有节点
	mytree.Expand(hRoot, TVE_EXPAND);
}
//详细解析ICMP包
void CNetworkSnifferDlg::DisplayPacketDetails_ICMP(const u_char* pkt_data)
{
	// 清除TreeControl中的所有项
	mytree.DeleteAllItems();

	// 创建根节点
	HTREEITEM hRoot = mytree.InsertItem(_T("Packet Details"));

	// 解析以太网头
	ethheader* eth = (ethheader*)pkt_data;
	HTREEITEM hEth = mytree.InsertItem(_T("Ethernet Header"), hRoot);
	mytree.InsertItem(_T("Destination Host: ") + ConvertToHex(eth->ether_dhost, 6), hEth);
	mytree.InsertItem(_T("Source Host: ") + ConvertToHex(eth->ether_shost, 6), hEth);
	u_char ether_type[2];
	memcpy(ether_type, &eth->ether_type, 2);
	mytree.InsertItem(_T("Type: ") + ConvertToHex(ether_type, 2), hEth);

	// 解析IP头
	ipheader* iph = (ipheader*)(pkt_data + sizeof(ethheader));
	HTREEITEM hIph = mytree.InsertItem(_T("IP Header"), hRoot);
	// IP版本和头部长度
	CString ip_ver;
	ip_ver.Format(_T("Version: %d"), iph->iph_ver);
	mytree.InsertItem(ip_ver, hIph);
	CString ip_hl;
	ip_hl.Format(_T("Header Length: %d Byte"), iph->iph_ihl * 4);
	mytree.InsertItem(ip_hl, hIph);

	// 服务类型
	CString ip_tos;
	ip_tos.Format(_T("Type of Service: %d"), iph->iph_tos);
	mytree.InsertItem(ip_tos, hIph);

	// IP包长度
	CString ip_len;
	ip_len.Format(_T("IP Packet Length: %d"), ntohs(iph->iph_len));
	mytree.InsertItem(ip_len, hIph);

	// 标识
	CString ip_id;
	ip_id.Format(_T("Identification: %d"), ntohs(iph->iph_ident));
	mytree.InsertItem(ip_id, hIph);

	// 分段标志和偏移
	CString ip_flag;
	ip_flag.Format(_T("Fragmentation Flags: %d"), iph->iph_flag);
	mytree.InsertItem(ip_flag, hIph);
	CString ip_offset;
	ip_offset.Format(_T("Flags Offset: %d"), iph->iph_offset);
	mytree.InsertItem(ip_offset, hIph);

	// 生存时间
	CString ip_ttl;
	ip_ttl.Format(_T("Time to Live: %d"), iph->iph_ttl);
	mytree.InsertItem(ip_ttl, hIph);

	// 协议类型
	CString ip_protocol;
	CString ip_protocol_desc;
	switch (iph->iph_protocol) {
	case 1:
		ip_protocol_desc = _T("ICMP");
		break;
	case 6:
		ip_protocol_desc = _T("TCP");
		break;
	case 17:
		ip_protocol_desc = _T("UDP");
		break;
	default:
		ip_protocol_desc = _T("Other Protocol");
	}
	ip_protocol.Format(_T("Protocol Type: %d (%s)"), iph->iph_protocol, ip_protocol_desc);
	mytree.InsertItem(ip_protocol, hIph);

	// IP数据报校验和
	CString ip_chksum;
	ip_chksum.Format(_T("IP Datagram Checksum: %d"), ntohs(iph->iph_chksum));
	mytree.InsertItem(ip_chksum, hIph);

	//源IP地址
	char str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(iph->iph_sourceip.s_addr), str, INET_ADDRSTRLEN);
	int len = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
	wchar_t* wstr = new wchar_t[len];
	MultiByteToWideChar(CP_ACP, 0, str, -1, wstr, len);
	CString addr_str;
	addr_str.Format(_T("%s"), wstr);
	mytree.InsertItem(_T("Source IP: ") + addr_str, hIph);
	//目标IP地址
	inet_ntop(AF_INET, &(iph->iph_destip.s_addr), str, INET_ADDRSTRLEN);
	len = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
	wstr = new wchar_t[len];
	MultiByteToWideChar(CP_ACP, 0, str, -1, wstr, len);
	addr_str.Format(_T("%s"), wstr);
	mytree.InsertItem(_T("Destination IP: ") + addr_str, hIph);
	delete[] wstr;
	// 解析ICMP头
	icmpheader* icmph = (icmpheader*)(pkt_data + sizeof(ethheader) + iph->iph_ihl * 4);
	HTREEITEM hIcmph = mytree.InsertItem(_T("ICMP Header"), hRoot);

	// ICMP类型
	CString icmp_type;
	CString icmp_type_desc;
	switch (icmph->icmp_type) {
	case 0:
		icmp_type_desc = _T("Echo Reply");
		break;
	case 3:
		icmp_type_desc = _T("Destination Unreachable");
		break;
	case 8:
		icmp_type_desc = _T("Echo Request");
		break;
	default:
		icmp_type_desc = _T("Other Type");
	}
	icmp_type.Format(_T("Type: %u (%s)"), icmph->icmp_type, icmp_type_desc);
	mytree.InsertItem(icmp_type, hIcmph);

	// ICMP代码
	CString icmp_code;
	icmp_code.Format(_T("Code: %u"), icmph->icmp_code);
	mytree.InsertItem(icmp_code, hIcmph);

	// ICMP校验和
	CString icmp_chksum;
	icmp_chksum.Format(_T("Checksum: %u"), ntohs(icmph->icmp_chksum));
	mytree.InsertItem(icmp_chksum, hIcmph);

	// ICMP ID
	CString icmp_id;
	icmp_id.Format(_T("ID: %u"), ntohs(icmph->icmp_id));
	mytree.InsertItem(icmp_id, hIcmph);

	// ICMP序列号
	CString icmp_seq;
	icmp_seq.Format(_T("Sequence Number: %u"), ntohs(icmph->icmp_seq));
	mytree.InsertItem(icmp_seq, hIcmph);

	// 展开所有节点
	mytree.Expand(hRoot, TVE_EXPAND);
}
//详细解析UDP包
void CNetworkSnifferDlg::DisplayPacketDetails_UDP(const u_char* pkt_data)
{
	// 清除TreeControl中的所有项
	mytree.DeleteAllItems();

	// 创建根节点
	HTREEITEM hRoot = mytree.InsertItem(_T("Packet Details"));

	// 解析以太网头
	ethheader* eth = (ethheader*)pkt_data;
	HTREEITEM hEth = mytree.InsertItem(_T("Ethernet Header"), hRoot);
	mytree.InsertItem(_T("Destination Host: ") + ConvertToHex(eth->ether_dhost, 6), hEth);
	mytree.InsertItem(_T("Source Host: ") + ConvertToHex(eth->ether_shost, 6), hEth);
	u_char ether_type[2];
	memcpy(ether_type, &eth->ether_type, 2);
	mytree.InsertItem(_T("Type: ") + ConvertToHex(ether_type, 2), hEth);

	// 解析IP头
	ipheader* iph = (ipheader*)(pkt_data + sizeof(ethheader));
	HTREEITEM hIph = mytree.InsertItem(_T("IP Header"), hRoot);
	// IP版本和头部长度
	CString ip_ver;
	ip_ver.Format(_T("Version: %d"), iph->iph_ver);
	mytree.InsertItem(ip_ver, hIph);
	CString ip_hl;
	ip_hl.Format(_T("Header Length: %d Byte"), iph->iph_ihl * 4);
	mytree.InsertItem(ip_hl, hIph);

	// 服务类型
	CString ip_tos;
	ip_tos.Format(_T("Type of Service: %d"), iph->iph_tos);
	mytree.InsertItem(ip_tos, hIph);

	// IP包长度
	CString ip_len;
	ip_len.Format(_T("IP Packet Length: %d"), ntohs(iph->iph_len));
	mytree.InsertItem(ip_len, hIph);

	// 标识
	CString ip_id;
	ip_id.Format(_T("Identification: %d"), ntohs(iph->iph_ident));
	mytree.InsertItem(ip_id, hIph);

	// 分段标志和偏移
	CString ip_flag;
	ip_flag.Format(_T("Fragmentation Flags: %d"), iph->iph_flag);
	mytree.InsertItem(ip_flag, hIph);
	CString ip_offset;
	ip_offset.Format(_T("Flags Offset: %d"), iph->iph_offset);
	mytree.InsertItem(ip_offset, hIph);

	// 生存时间
	CString ip_ttl;
	ip_ttl.Format(_T("Time to Live: %d"), iph->iph_ttl);
	mytree.InsertItem(ip_ttl, hIph);

	// 协议类型
	CString ip_protocol;
	CString ip_protocol_desc;
	switch (iph->iph_protocol) {
	case 1:
		ip_protocol_desc = _T("ICMP");
		break;
	case 6:
		ip_protocol_desc = _T("TCP");
		break;
	case 17:
		ip_protocol_desc = _T("UDP");
		break;
	default:
		ip_protocol_desc = _T("Other Protocol");
	}
	ip_protocol.Format(_T("Protocol Type: %d (%s)"), iph->iph_protocol, ip_protocol_desc);
	mytree.InsertItem(ip_protocol, hIph);

	// IP数据报校验和
	CString ip_chksum;
	ip_chksum.Format(_T("IP Datagram Checksum: %d"), ntohs(iph->iph_chksum));
	mytree.InsertItem(ip_chksum, hIph);

	//源IP地址
	char str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(iph->iph_sourceip.s_addr), str, INET_ADDRSTRLEN);
	int len = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
	wchar_t* wstr = new wchar_t[len];
	MultiByteToWideChar(CP_ACP, 0, str, -1, wstr, len);
	CString addr_str;
	addr_str.Format(_T("%s"), wstr);
	mytree.InsertItem(_T("Source IP: ") + addr_str, hIph);
	//目标IP地址
	inet_ntop(AF_INET, &(iph->iph_destip.s_addr), str, INET_ADDRSTRLEN);
	len = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
	wstr = new wchar_t[len];
	MultiByteToWideChar(CP_ACP, 0, str, -1, wstr, len);
	addr_str.Format(_T("%s"), wstr);
	mytree.InsertItem(_T("Destination IP: ") + addr_str, hIph);
	delete[] wstr;

	// 解析UDP头，源端口和目标端口号
	udpheader* udph = (udpheader*)(pkt_data + sizeof(ethheader) + iph->iph_ihl * 4);
	HTREEITEM hUdph = mytree.InsertItem(_T("UDP Header"), hRoot);
	CString port;
	port.Format(_T("%u"), ntohs(udph->udp_sport));
	mytree.InsertItem(_T("Source Port: ") + port, hUdph);
	port.Format(_T("%u"), ntohs(udph->udp_dport));
	mytree.InsertItem(_T("Destination Port: ") + port, hUdph);

	// UDP长度
	CString ulen;
	ulen.Format(_T("UDP Length: %u"), ntohs(udph->udp_ulen));
	mytree.InsertItem(ulen, hUdph);

	// 校验和
	CString sum;
	sum.Format(_T("Checksum: %u"), ntohs(udph->udp_sum));
	mytree.InsertItem(sum, hUdph);

	// 展开所有节点
	mytree.Expand(hRoot, TVE_EXPAND);
}
//详细解析IPV6包
void CNetworkSnifferDlg::DisplayPacketDetails_IPV6(const u_char* pkt_data)
{
	// 清除TreeControl中的所有项
	mytree.DeleteAllItems();

	// 创建根节点
	HTREEITEM hRoot = mytree.InsertItem(_T("Packet Details"));

	// 解析以太网头
	ethheader* eth = (ethheader*)pkt_data;
	HTREEITEM hEth = mytree.InsertItem(_T("Ethernet Header"), hRoot);
	mytree.InsertItem(_T("Destination Host: ") + ConvertToHex(eth->ether_dhost, 6), hEth);
	mytree.InsertItem(_T("Source Host: ") + ConvertToHex(eth->ether_shost, 6), hEth);
	u_char ether_type[2];
	memcpy(ether_type, &eth->ether_type, 2);
	mytree.InsertItem(_T("Type: ") + ConvertToHex(ether_type, 2), hEth);

	// 解析IPv6头
	ipv6header* iph6 = (ipv6header*)(pkt_data + sizeof(ethheader));
	HTREEITEM hIph6 = mytree.InsertItem(_T("IPv6 Header"), hRoot);

	// IP版本
	CString ip_ver;
	ip_ver.Format(_T("Version: %d"), iph6->ipv6_version);
	mytree.InsertItem(ip_ver, hIph6);

	// 服务类型
	CString ip_tos;
	ip_tos.Format(_T("Traffic Class: %d"), iph6->ipv6_traffic_class);
	mytree.InsertItem(ip_tos, hIph6);

	// 流标签
	CString ip_flow;
	ip_flow.Format(_T("Flow Label: %d"), iph6->ipv6_flow_label);
	mytree.InsertItem(ip_flow, hIph6);

	// 载荷长度
	CString ip_len;
	ip_len.Format(_T("Payload Length: %d"), ntohs(iph6->ipv6_payload_len));
	mytree.InsertItem(ip_len, hIph6);

	// 下一个头部
	CString ip_next;
	CString ip_next_desc;
	switch (iph6->ipv6_next_header) {
	case 1:
		ip_next_desc = _T("ICMP");
		break;
	case 6:
		ip_next_desc = _T("TCP");
		break;
	case 17:
		ip_next_desc = _T("UDP");
		break;
	case 58:
		ip_next_desc = _T("ICMPv6");
		break;
	default:
		ip_next_desc = _T("Other Protocol");
	}
	ip_next.Format(_T("Next Header: %d (%s)"), iph6->ipv6_next_header, ip_next_desc);
	mytree.InsertItem(ip_next, hIph6);

	// 跳数限制
	CString ip_hop;
	ip_hop.Format(_T("Hop Limit: %d"), iph6->ipv6_hop_limit);
	mytree.InsertItem(ip_hop, hIph6);

	//源IP地址
	char str[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &(iph6->ipv6_source), str, INET6_ADDRSTRLEN);
	int len = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
	wchar_t* wstr = new wchar_t[len];
	MultiByteToWideChar(CP_ACP, 0, str, -1, wstr, len);
	CString addr_str;
	addr_str.Format(_T("%s"), wstr);
	mytree.InsertItem(_T("Source IP: ") + addr_str, hIph6);

	//目标IP地址
	inet_ntop(AF_INET6, &(iph6->ipv6_dest), str, INET6_ADDRSTRLEN);
	len = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
	wstr = new wchar_t[len];
	MultiByteToWideChar(CP_ACP, 0, str, -1, wstr, len);
	addr_str.Format(_T("%s"), wstr);
	mytree.InsertItem(_T("Destination IP: ") + addr_str, hIph6);
	delete[] wstr;

	// 展开所有节点
	mytree.Expand(hRoot, TVE_EXPAND);
}
//转换十六进制函数
CString CNetworkSnifferDlg::ConvertToHex(u_char* data, int len)
{
	CString str;
	for (int i = 0; i < len; ++i)
	{
		CString tmp;
		tmp.Format(_T("%02X "), data[i]);
		str += tmp;
	}
	return str;
}

//呈现捕获数据包的信息以十六进制形式在Edit Control控件中
void CNetworkSnifferDlg::DisplayPacketHex(const u_char* pkt_data, int data_length)
{
	CString packetDataHex;
	for (int i = 0; i < data_length; i++) {
		CString byteHex;
		byteHex.Format(_T("%02X "), pkt_data[i]);
		packetDataHex += byteHex;

		// 添加新行以每16个字节为一行显示
		if ((i + 1) % 16 == 0) {
			packetDataHex += _T("\r\n");
		}
	}
	myedit.SetWindowText(packetDataHex);
}

//清理按钮，清空之前保存的数据包和显示的信息
void CNetworkSnifferDlg::OnBnClickedButton4()
{
	// TODO: 在此添加控件通知处理程序代码
	for (int i = 0; i < pktDatas.GetSize(); i++) {
		free((void*)pktDatas[i]);
	}
	pktDatas.RemoveAll();
	for (int i = 0; i < pktHeaders.GetSize(); i++) {
		free((void*)pktHeaders[i]);
	}
	pktHeaders.RemoveAll();
	LControl.DeleteAllItems();
	mytree.DeleteAllItems();
	myedit.SetWindowText(_T(""));
	nCount = 0;
}

//触发函数，当选中ListControl中的一行时，显示数据包的详细信息以及十六进制全部信息
void CNetworkSnifferDlg::OnLvnItemchangedList1(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	if ((pNMLV->uChanged & LVIF_STATE) && (pNMLV->uNewState & LVIS_SELECTED))
	{
		int index = pNMLV->iItem;// index就是当前选中的行的索引
		DisplayPacketHex(pktDatas[index], pktHeaders[index]->caplen);
		CString str = LControl.GetItemText(index, 4);
		if (str == "TCP" || str == "HTTP" || str == "HTTPS")
		{
			DisplayPacketDetails_TCP(pktDatas[index]);
		}
		else if (str == "ICMP")
		{
			DisplayPacketDetails_ICMP(pktDatas[index]);
		}
		else if (str == "UDP")
		{
			DisplayPacketDetails_UDP(pktDatas[index]);
		}
		else if (str == "IPV6")
		{
			DisplayPacketDetails_IPV6(pktDatas[index]);
		}
		else
		{
			AfxMessageBox(_T("当前树形结构仅详细解析TCP数据包"));
		}
	}
	*pResult = 0;
}
