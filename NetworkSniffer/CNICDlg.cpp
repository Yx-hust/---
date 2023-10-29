// CNICDlg.cpp: 实现文件
//

#include "pch.h"
#include "NetworkSniffer.h"
#include "CNICDlg.h"
#include "afxdialogex.h"
#include "pcap.h"


// CNICDlg 对话框

IMPLEMENT_DYNAMIC(CNICDlg, CDialogEx)

CNICDlg::CNICDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIALOG1, pParent)
{

}

CNICDlg::~CNICDlg()
{
}

void CNICDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, LNIC);
}


BEGIN_MESSAGE_MAP(CNICDlg, CDialogEx)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST1, &CNICDlg::OnLvnItemchangedList1)
	ON_NOTIFY(NM_CLICK, IDC_LIST1, &CNICDlg::OnNMClickList1)
	ON_BN_CLICKED(IDC_BUTTON1, &CNICDlg::OnBnClickedButton1)
END_MESSAGE_MAP()


// CNICDlg 消息处理程序


void CNICDlg::OnLvnItemchangedList1(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	*pResult = 0;
}



BOOL CNICDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  在此添加额外的初始化
	LNIC.SetExtendedStyle(LNIC.GetExtendedStyle() | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    LNIC.InsertColumn(0, _T("设备名"), LVCFMT_LEFT, 350);
	LNIC.InsertColumn(1, _T("设备描述"), LVCFMT_LEFT, 250);
	//获取所有网卡设备，"PCAP_SRC_IF_STRING"字符串指示用户希望从网络接口打开捕获。
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &allNICs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		exit(1);
	}
	for (pcap_if_t* d = allNICs; d != NULL; d = d->next)
	{
		LNIC.InsertItem(0, (CString)d->name);
		LNIC.SetItemText(0, 1, (CString)d->description);
	}

	return TRUE;  // return TRUE unless you set the focus to a control
				  // 异常: OCX 属性页应返回 FALSE
}


void CNICDlg::OnNMClickList1(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	*pResult = 0;
	NMLISTVIEW *pNMListView = (NMLISTVIEW*)pNMHDR;    
    if (pNMListView->iItem != -1)        // 如果判断成立说明有列表项被选择   
    {   
         // 获取被选择列表项的信息，并显示  
         nicname = LNIC.GetItemText(pNMListView->iItem, 0);     
         SetDlgItemText(IDC_EDIT1, nicname);

    }
}


void CNICDlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
	pcap_if_t* tmp;
	if (!nicname.IsEmpty())
	{
		for (tmp = allNICs; tmp != NULL; tmp = tmp->next)
		{
			if (tmp->name == nicname)
			{
				cNIC = tmp;
				MessageBox(_T("网卡绑定成功!"));
				CDialogEx::OnOK();
			}
		}
	}
	else
	{
		MessageBox(_T("请选择要绑定的网卡"));
	}
}
pcap_if_t* CNICDlg::getNIC()
{
	return cNIC;
}