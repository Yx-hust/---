
// NetworkSnifferDlg.h: 头文件
//

#pragma once
#include "pcap.h"
#include "CNICDlg.h"


// CNetworkSnifferDlg 对话框
class CNetworkSnifferDlg : public CDialogEx
{
// 构造
public:
	CNetworkSnifferDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_NETWORKSNIFFER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;
	//pcap_if_t * myNIC;//被选中的网卡


	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
	
public:
	
	CListCtrl LControl;
	CTreeCtrl mytree;
	pcap_if_t* myNIC = NULL; 
	char* myfilter;
	int OnOff = 0;
	int nCount = 0;
	CArray<const struct pcap_pkthdr*, const struct pcap_pkthdr*>  pktHeaders;
	CArray<const u_char*, const u_char*>  pktDatas;
	afx_msg void OnLvnItemchangedList1(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnNic();
	afx_msg void Onfilter();
	static UINT CaptureThread(void* lpParam);
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButton2();
	int ShowList(struct pcap_pkthdr* pkt_header, const u_char* pkt_data);
	void DisplayPacketDetails_TCP(const u_char* pkt_data);
	void DisplayPacketDetails_ICMP(const u_char* pkt_data);
	void DisplayPacketDetails_UDP(const u_char* pkt_data);
	void DisplayPacketDetails_IPV6(const u_char* pkt_data);
	void DisplayPacketHex(const u_char* pkt_data,int data_length);
	CString ConvertToHex(u_char* data, int len);

	CEdit myedit;
	
	afx_msg void OnBnClickedButton4();
};
