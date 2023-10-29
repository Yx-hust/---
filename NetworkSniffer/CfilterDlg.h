#pragma once


// CfilterDlg 对话框

class CfilterDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CfilterDlg)

public:
	CfilterDlg(CWnd* pParent = nullptr);   // 标准构造函数
	virtual ~CfilterDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG2 };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedCheck5();
	CButton tcp_box;
	CButton udp_box;
	CButton http_box;
	CButton ipv4_box;
	CButton ipv6_box;
	CButton icmp_box;
	CString ftcp;
	CString fudp;
	CString fhttp;
	CString fipv4;
	CString fipv6;
	CString ficmp;
	CString filters;
	afx_msg void OnBnClickedCheck1();
	afx_msg void OnBnClickedCheck2();
	afx_msg void OnBnClickedCheck3();
	afx_msg void OnBnClickedCheck4();
	afx_msg void OnBnClickedCheck6();
	afx_msg void OnBnClickedButton1();
};
