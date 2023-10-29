#pragma once
#include "pcap.h"


// CNICDlg 对话框

class CNICDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CNICDlg)

public:
	CNICDlg(CWnd* pParent = nullptr);   // 标准构造函数
	virtual ~CNICDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG1 };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持
	DECLARE_MESSAGE_MAP()
	pcap_if_t* allNICs;//allNICs参数用于存放获取的适配器数据。如果查找失败，值为NULL.
	CString nicname;//被选中的网卡名字
	
public:
	// 网卡的选择ListControl	
	CListCtrl LNIC;
	pcap_if_t* cNIC;//被选中的网卡
	pcap_if_t* getNIC();
	afx_msg void OnLvnItemchangedList1(NMHDR* pNMHDR, LRESULT* pResult);
	virtual BOOL OnInitDialog();
	afx_msg void OnNMClickList1(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnBnClickedButton1();
};
