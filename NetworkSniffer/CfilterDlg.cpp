// CfilterDlg.cpp: 实现文件
//

#include "pch.h"
#include "NetworkSniffer.h"
#include "CfilterDlg.h"
#include "afxdialogex.h"


// CfilterDlg 对话框

IMPLEMENT_DYNAMIC(CfilterDlg, CDialogEx)

CfilterDlg::CfilterDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIALOG2, pParent)
{

}

CfilterDlg::~CfilterDlg()
{
}

void CfilterDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_CHECK1, tcp_box);
	DDX_Control(pDX, IDC_CHECK2, udp_box);
	DDX_Control(pDX, IDC_CHECK3, http_box);
	DDX_Control(pDX, IDC_CHECK4, ipv4_box);
	DDX_Control(pDX, IDC_CHECK5, ipv6_box);
	DDX_Control(pDX, IDC_CHECK6, icmp_box);
}


BEGIN_MESSAGE_MAP(CfilterDlg, CDialogEx)
	ON_BN_CLICKED(IDC_CHECK5, &CfilterDlg::OnBnClickedCheck5)
	ON_BN_CLICKED(IDC_CHECK1, &CfilterDlg::OnBnClickedCheck1)
	ON_BN_CLICKED(IDC_CHECK2, &CfilterDlg::OnBnClickedCheck2)
	ON_BN_CLICKED(IDC_CHECK3, &CfilterDlg::OnBnClickedCheck3)
	ON_BN_CLICKED(IDC_CHECK4, &CfilterDlg::OnBnClickedCheck4)
	ON_BN_CLICKED(IDC_CHECK6, &CfilterDlg::OnBnClickedCheck6)
	ON_BN_CLICKED(IDC_BUTTON1, &CfilterDlg::OnBnClickedButton1)
END_MESSAGE_MAP()



//每个复选框选中设置相应的过滤规则
void CfilterDlg::OnBnClickedCheck1()
{
	// TODO: 在此添加控件通知处理程序代码
	int state = tcp_box.GetCheck();
	// 勾选之后，执行的代码
	if (state == 1)
	{
		ftcp = _T("tcp or ");
	}
	// 取消选中后
	else
	{
		ftcp.Empty();
	}
}
void CfilterDlg::OnBnClickedCheck2()
{
	// TODO: 在此添加控件通知处理程序代码
	int state = udp_box.GetCheck();
	// 勾选之后，执行的代码
	if (state == 1)
	{
		fudp = _T("udp or ");
	}
	// 取消选中后
	else
	{
		fudp.Empty();
	}
}


void CfilterDlg::OnBnClickedCheck3()
{
	// TODO: 在此添加控件通知处理程序代码
	int state = http_box.GetCheck();
	// 勾选之后，执行的代码
	if (state == 1)
	{
		//通过过滤TCP协议并指定端口号80或443来间接过滤HTTP或HTTPS数据包
		fhttp = _T("(tcp port 80) or (tcp port 443) or ");
	}
	// 取消选中后
	else
	{
		fhttp.Empty();
	}
}


void CfilterDlg::OnBnClickedCheck4()
{
	// TODO: 在此添加控件通知处理程序代码
	int state = ipv4_box.GetCheck();
	// 勾选之后，执行的代码
	if (state == 1)
	{
		fipv4 = _T("ip or ");
	}
	// 取消选中后
	else
	{
		fipv4.Empty();
	}
}
void CfilterDlg::OnBnClickedCheck5()
{
	// TODO: 在此添加控件通知处理程序代码
	int state = ipv6_box.GetCheck();
	// 勾选之后，执行的代码
	if (state == 1)
	{
		fipv6 = _T("ip6 or ");
	}
	// 取消选中后
	else
	{
		fipv6.Empty();
	}
}
void CfilterDlg::OnBnClickedCheck6()
{
	// TODO: 在此添加控件通知处理程序代码
	int state = icmp_box.GetCheck();
	// 勾选之后，执行的代码
	if (state == 1)
	{
		ficmp = _T("icmp or");
	}
	// 取消选中后
	else
	{
		ficmp.Empty();
	}
}

//合并过滤规则
void CfilterDlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
	filters = ftcp + fudp + fhttp + fipv4 + fipv6 + ficmp;
	filters = filters.Left(filters.GetLength() - 3);
	filters = filters;
	CDialogEx::OnOK();
}
