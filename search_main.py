from PyQt5 import QtWidgets, QtCore
from PyQt5.QtWidgets import QMessageBox,QTableWidget,QTableWidgetItem,QCompleter
from PyQt5.QtCore import pyqtSignal, QObject, QThread,QFileInfo,QRegExp,QUrl,Qt
from Ui_search import Ui_allsearch
from bs4 import BeautifulSoup
import items
import favicon
from PyQt5.QtGui import QIcon,QRegExpValidator,QIntValidator,QDesktopServices
from threading import Thread
from urllib.parse import quote
from dateutil.parser import parse
from USER_AGENTS import USER_AGENTS
import re,sys,os,json,datetime,base64,requests,shodan,mmh3,random,xlwt
import subprocess
import time

items_list=items.items_all()

class MyWindow(QtWidgets.QMainWindow, Ui_allsearch):
    def __init__(self):
        super(MyWindow, self).__init__()
        self.setupUi(self)

        self.start_search_pushButton.clicked.connect(self.start_searching)
        self.proxy_test_pushButton.clicked.connect(self.start_proxy)
        self.statusBar().showMessage('by: mojie')
        self.init_start_keywords_lineEdit()
    
    def init_start_keywords_lineEdit(self):
        self.completer = QCompleter(items_list)
        self.completer.setFilterMode(Qt.MatchStartsWith)
        self.completer.setCompletionMode(QCompleter.PopupCompletion)
        self.start_keywords_lineEdit.setCompleter(self.completer)

    
    def fofa_key(self):
        with open('./config.ini','r',encoding='utf8') as f:
            info = f.readlines()
            email = re.findall(r'fofa_email="(.*?)"',info[0])
            key = re.findall(r'fofa_key="(.*?)"',info[1])
            return (email,key)

    
    def zoomeye_key(self):
        with open('./config.ini','r',encoding='utf8') as f:
            info = f.readlines()
            key = re.findall(r'zoomeye_key="(.*?)"',info[2])
            return key

    def quake_key(self):
        with open('./config.ini','r',encoding='utf8') as f:
            info = f.readlines()
            key = re.findall(r'quake_key="(.*?)"',info[3])
            return key

    def shodan_key(self):
        with open('./config.ini','r',encoding='utf8') as f:
            info = f.readlines()
            key = re.findall(r'shodan_key="(.*?)"',info[4])
            return key
    
    def censys_key(self):
        with open('./config.ini','r',encoding='utf8') as f:
            info = f.readlines()
            uid = re.findall(r'censys_uid="(.*?)"',info[5])
            secret = re.findall(r'censys_secret="(.*?)"',info[6])
            return (uid,secret)
    
    def binaryedge_key(self):
        with open('./config.ini','r',encoding='utf8') as f:
            info = f.readlines()
            key = re.findall(r'binaryedge_key="(.*?)"',info[7])
            return key
    
    def search_str_select(self):
        try:
            with open('./rules.json','r', encoding='utf8') as f:
                    info = json.load(f)
                    json_key,json_val = re.findall('(.*)=(.*)',self.start_keywords_lineEdit.text())[0]
                    json_str = json_key + '='
                    if json_str in info:
                        return [info[json_str],json_val]
                    else:
                        return self.start_keywords_lineEdit.text()
        except Exception as e:
            self.notice_output_textBrowser.setText("<font color='#ff0000'>" + str(e) + "<font>")

    def search_str_select_test(self):
        if '++' in self.start_keywords_lineEdit.text() or '--' in self.start_keywords_lineEdit.text() or '^^' in self.start_keywords_lineEdit.text():
            res = list(filter(None,re.split('\+\+|\-\-|\^\^',self.start_keywords_lineEdit.text())))
            strq_key = []
            for i in res:
                try:
                    with open('./rules.json','r', encoding='utf8') as f:
                            info = json.load(f)
                            # json_key,json_val = re.findall('(.*)=(.*)',i)[0]
                            json_c = re.split('[=]',i)
                            # print(json_c)
                            # print(json_key,json_val)
                            json_str = json_c[0] + '='
                            if json_str in info:
                                strq_key.append(info[json_str])
                                strq_key.append(json_c[1])
                                # return [info[json_str],json_c[1]]
                            else:
                                return strq_key.append(i)
                except Exception as e:
                    pass
            return strq_key
        elif '=' in self.start_keywords_lineEdit.text().strip():
            try:
                with open('./rules.json','r', encoding='utf8') as f:
                        info = json.load(f)
                        # json_key,json_val = re.findall('(.*)=(.*)',i)[0]
                        json_c = re.split('[=]',self.start_keywords_lineEdit.text().strip())
                        # print(json_key,json_val)
                        json_str = json_c[0] + '='
                        if json_str in info:
                            return [info[json_str],json_c[1]]
                        else:
                            return self.start_keywords_lineEdit.text().strip()
            except Exception as e:
                pass
        else:
            return self.start_keywords_lineEdit.text().strip()
    
    def search_flag(self):
        flag = re.findall('\+{2}|\-{2}|\^{2}',self.start_keywords_lineEdit.text())
        flag.append(' ')
        return flag
    
    def fofa_search_str(self):
        qstr_dic = {'++': '&&','--': '||','^^': '!=',' ': ' '}
        flag = self.search_flag()
        qstr = self.search_str_select_test()
        fofa_str = []
        for i in range(0,len(qstr),2):
            fofa_str.append(qstr[i][0]+'"'+qstr[i+1]+'"')

        fofa_fina_str = ''
        for i in range(len(fofa_str)):
            fofa_fina_str += (fofa_str[i] + qstr_dic[flag[i]])
        
        return fofa_fina_str

    def zoomeye_search_str(self):
        qstr_dic = {'++': '+','--': ' ','^^': '-',' ': ' '}
        flag = self.search_flag()
        qstr = self.search_str_select_test()
        zoomeye_str = []
        for i in range(0,len(qstr),2):
            zoomeye_str.append(qstr[i][1]+'"'+qstr[i+1]+'"')

        zoomeye_fina_str = ''
        for i in range(len(zoomeye_str)):
            zoomeye_fina_str += (zoomeye_str[i] + qstr_dic[flag[i]])
        return zoomeye_fina_str


    def quake_search_str(self):
        qstr_dic = {'++': 'AND','--': 'OR','^^': 'NOT',' ': ' '}
        flag = self.search_flag()
        qstr = self.search_str_select_test()
        quake_str = []
        for i in range(0,len(qstr),2):
            quake_str.append(qstr[i][2]+'"'+qstr[i+1]+'"')

        quake_fina_str = ''
        for i in range(len(quake_str)):
            quake_fina_str += (' '+quake_str[i] + ' ' + qstr_dic[flag[i]]+' ')
        
        return quake_fina_str
    
    def shodan_search_str(self):
        qstr_dic = {'++': ' ','--': ' ','^^': ' ',' ': ' '}
        flag = self.search_flag()
        qstr = self.search_str_select_test()
        shodan_str = []
        for i in range(0,len(qstr),2):
            shodan_str.append(qstr[i][3]+'"'+qstr[i+1]+'"')

        shodan_fina_str = ''
        for i in range(len(shodan_str)):
            shodan_fina_str += (' '+shodan_str[i] + ' ' + qstr_dic[flag[i]]+' ')
        return shodan_fina_str

    def censys_search_str(self):
        qstr_dic = {'++': 'AND','--': 'OR','^^': 'NOT',' ': ' '}
        flag = self.search_flag()
        qstr = self.search_str_select_test()
        censys_str = []
        for i in range(0,len(qstr),2):
            censys_str.append(qstr[i][4]+'"'+qstr[i+1]+'"')

        censys_fina_str = ''
        for i in range(len(censys_str)):
            censys_fina_str += (' '+censys_str[i] + ' ' + qstr_dic[flag[i]]+' ')
        
        return censys_fina_str



    
    def quake_icon(self):         
        filename = self.start_keywords_lineEdit.text().split('/')[-1]
        filename_name = filename.split('.')[-1]
        filepath = os.path.join('./icon', filename)
        requests.packages.urllib3.disable_warnings()
        file_data = requests.get(self.start_keywords_lineEdit.text(), allow_redirects=True,verify=False).content
        with open(filepath, 'wb') as handler:
            handler.write(file_data)
        icon_path = open('./icon/' + filename,'rb')
        md = hashlib.md5()
        md.update(icon_path.read())
        icon_hash = md.hexdigest()
        return icon_hash

    def fofa_shodan_icon(self):
        requests.packages.urllib3.disable_warnings()
        icon = mmh3.hash(codecs.lookup('base64').encode(requests.get(self.start_keywords_lineEdit.text(),verify=False).content)[0])
        return icon
    
    def filelog_time(self):
        fofa_ctime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(os.stat("./temp/fofa_search.log").st_ctime))
        fofa_ntime = datetime.datetime.now()
        fofa_file_creat_time = (parse(str(fofa_ntime)) - parse(fofa_ctime)).days
        zoomeye_ctime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(os.stat("./temp/zoomeye_search.log").st_ctime))
        zoomeye_ntime = datetime.datetime.now()
        zoomeye_file_creat_time = (parse(str(zoomeye_ntime)) - parse(zoomeye_ctime)).days
        quake_ctime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(os.stat("./temp/quake_search.log").st_ctime))
        quake_ntime = datetime.datetime.now()
        quake_file_creat_time = (parse(str(quake_ntime)) - parse(quake_ctime)).days
        shodan_ctime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(os.stat("./temp/quake_search.log").st_ctime))
        shodan_ntime = datetime.datetime.now()
        shodan_file_creat_time = (parse(str(shodan_ntime)) - parse(shodan_ctime)).days
        censys_ctime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(os.stat("./temp/censys_search.log").st_ctime))
        censys_ntime = datetime.datetime.now()
        censys_file_creat_time = (parse(str(censys_ntime)) - parse(censys_ctime)).days
        binaryedge_ctime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(os.stat("./temp/binaryedge_search.log").st_ctime))
        binaryedge_ntime = datetime.datetime.now()
        binaryedge_file_creat_time = (parse(str(binaryedge_ntime)) - parse(binaryedge_ctime)).days
        rapiddns_ctime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(os.stat("./temp/rapiddns_search.log").st_ctime))
        rapiddns_ntime = datetime.datetime.now()
        rapiddns_file_creat_time = (parse(str(rapiddns_ntime)) - parse(rapiddns_ctime)).days
        return [fofa_file_creat_time,zoomeye_file_creat_time,quake_file_creat_time,shodan_file_creat_time,censys_file_creat_time,binaryedge_file_creat_time,rapiddns_file_creat_time]
    
    # def start_get_proxy(self):
    #     print(self.proxy_checkBox.isChecked())
    #     t = get_proxy_list(self.fofa_key()[0][0],str(self.fofa_key()[1][0]))
    #     t.text_print.connect(self.proxy_output)
    #     t.start()


   
    def start_searching(self):
        if self.proxy_checkBox.isChecked() == True:
            proxy_flag = 'start'
        else:
            proxy_flag = 'stop'


        if len(self.start_keywords_lineEdit.text()) == 0:
            self.notice_output_textBrowser.setText("<font color='#ff0000'>" + '>请输入搜索关键字' + "<font>")
        else:
            iconame = ['jpg','png','ico']
            filename = self.start_keywords_lineEdit.text().split('.')[-1]
            if '//' in self.start_keywords_lineEdit.text() or filename in iconame:
                quake_icon = 'favicon: ' + '"' + str(self.quake_icon()) + '"'
                fofa_icon = 'icon_hash=' + '"' + str(self.fofa_shodan_icon()) + '"'
                shodan_icon = 'http.favicon.hash:' + str(self.fofa_shodan_icon())
                self.fofa_thread = fofa_search_qthread(self.start_time_spinBox.text(),fofa_icon,self.fofa_key()[0][0],self.fofa_key()[1][0])
                self.fofa_thread.text_print.connect(self.fofa_output)
                self.fofa_thread.notice_print.connect(self.notice_output)
                self.fofa_thread.count_print.connect(self.count_output)
                self.fofa_thread.res_print.connect(self.all_output)
                self.fofa_search_output_textBrowser.setText("<font color='#55ff00'>" + '==========================' + "<font>")
                self.zoomeye_search_output_textBrowser.setText("<font color='#55ff00'>" + '==========================' + "<font>")
                self.zoomeye_search_output_textBrowser.append("<font color='#ff0000'>" + '>Zoomeye不支持Icon查询' + "<font>")
                self.quake_thread = quake_search_qthread(self.quake_key()[0],quake_icon)
                self.quake_thread.text_print.connect(self.quake_output)
                self.quake_thread.notice_print.connect(self.notice_output)
                self.quake_thread.count_print.connect(self.count_output)
                self.quake_thread.res_print.connect(self.all_output)
                self.quake_search_output_textBrowser.setText("<font color='#55ff00'>" + '==========================' + "<font>")
                self.shodan_thread = shodan_search_qthread(self.shodan_key()[0],shodan_icon)
                self.shodan_thread.text_print.connect(self.shodan_output)
                self.shodan_thread.notice_print.connect(self.notice_output)
                self.shodan_thread.count_print.connect(self.count_output)
                self.shodan_thread.res_print.connect(self.all_output)
                self.shodan_search_output_textBrowser.setText("<font color='#55ff00'>" + '==========================' + "<font>")
                self.fofa_thread.start()
                self.quake_thread.start()
                self.shodan_thread.start()

            else:
                select_str = self.search_str_select()
                fofa_str = self.fofa_search_str()
                quake_str = self.quake_search_str()
                zoomeye_str = self.zoomeye_search_str()
                shodan_str = self.shodan_search_str()
                censys_str = self.censys_search_str()
                log_time = self.filelog_time()
                self.fofa_thread = fofa_search_qthread(self.start_time_spinBox.text(),fofa_str,self.fofa_key()[0][0],self.fofa_key()[1][0],self.start_keywords_lineEdit.text(),log_time[0],proxy_flag,self.fofa_checkBox.isChecked(),self.fofa_size_lineEdit.text())
                   # self.fofa_thread = fofa_search_qthread(self.start_time_spinBox.text(),select_str[0][0]+'"'+select_str[1]+'"',self.fofa_key()[0][0],self.fofa_key()[1][0])
                self.fofa_thread.text_print.connect(self.fofa_output)
                self.fofa_thread.notice_print.connect(self.notice_output)
                self.fofa_thread.count_print.connect(self.count_output)
                self.fofa_thread.res_print.connect(self.all_output)
                self.fofa_search_output_textBrowser.setText("<font color='#55ff00'>" + '==========================' + "<font>")
                self.zoomeye_thread = zoomeye_search_qthread(zoomeye_str,self.zoomeye_key()[0],self.start_time_spinBox.text(),self.start_keywords_lineEdit.text(),log_time[1],proxy_flag,self.zoomeye_checkBox.isChecked(),self.zoomeye_size_lineEdit.text())
                   # self.zoomeye_thread = zoomeye_search_qthread(select_str[0][1]+'"'+select_str[1]+'"',self.zoomeye_key()[0],self.start_time_spinBox.text())
                self.zoomeye_thread.text_print.connect(self.zoomeye_output)
                self.zoomeye_thread.notice_print.connect(self.notice_output)
                self.zoomeye_thread.count_print.connect(self.count_output)
                self.zoomeye_thread.res_print.connect(self.all_output)
                self.zoomeye_search_output_textBrowser.setText("<font color='#55ff00'>" + '==========================' + "<font>")
                self.quake_thread = quake_search_qthread(self.quake_key()[0],quake_str,self.start_keywords_lineEdit.text(),log_time[2],proxy_flag,self.quake_checkBox.isChecked(),self.quake_size_lineEdit.text())
                   # self.quake_thread = quake_search_qthread(self.quake_key()[0],select_str[0][2]+'"'+select_str[1]+'"')
                self.quake_thread.text_print.connect(self.quake_output)
                self.quake_thread.notice_print.connect(self.notice_output)
                self.quake_thread.count_print.connect(self.count_output)
                self.quake_thread.res_print.connect(self.all_output)
                self.quake_search_output_textBrowser.setText("<font color='#55ff00'>" + '==========================' + "<font>")
                self.shodan_thread = shodan_search_qthread(self.shodan_key()[0],shodan_str,self.start_keywords_lineEdit.text(),log_time[3],self.shodan_checkBox.isChecked(),self.shodan_size_lineEdit.text())
                   # self.shodan_thread = shodan_search_qthread(self.shodan_key()[0],select_str[0][3]+'"'+select_str[1]+'"')
                self.shodan_thread.text_print.connect(self.shodan_output)
                self.shodan_thread.notice_print.connect(self.notice_output)
                self.shodan_thread.count_print.connect(self.count_output)
                self.shodan_thread.res_print.connect(self.all_output)
                self.shodan_search_output_textBrowser.setText("<font color='#55ff00'>" + '==========================' + "<font>")
                self.censys_thread = censys_search_qthread(self.censys_key()[0][0],self.censys_key()[1][0],censys_str,self.start_keywords_lineEdit.text(),log_time[4],proxy_flag,self.censys_checkBox.isChecked(),self.censys_size_lineEdit.text())
                self.censys_thread.text_print.connect(self.censys_output)
                self.censys_thread.notice_print.connect(self.notice_output)
                self.censys_thread.count_print.connect(self.count_output)
                self.censys_thread.res_print.connect(self.all_output)
                self.censys_search_output_textBrowser.setText("<font color='#55ff00'>" + '==========================' + "<font>")
                self.binaryedge_thread = binaryedge_search_qthread(self.binaryedge_key()[0],self.start_keywords_lineEdit.text(),log_time[5],proxy_flag,self.binaryedge_checkBox.isChecked(),self.binaryedge_size_lineEdit.text())
                self.binaryedge_thread.text_print.connect(self.binaryedge_output)
                self.binaryedge_thread.notice_print.connect(self.notice_output)
                self.binaryedge_thread.count_print.connect(self.count_output)
                self.binaryedge_thread.res_print.connect(self.all_output)
                self.binaryedge_search_output_textBrowser.setText("<font color='#55ff00'>" + '==========================' + "<font>")
                self.rapiddns_qthread = rapiddns_search_qthread(self.start_keywords_lineEdit.text(),log_time[6],proxy_flag,self.fofa_checkBox.isChecked(),self.fofa_size_lineEdit.text())
                self.rapiddns_qthread.text_print.connect(self.all_output)
                self.rapiddns_qthread.count_print.connect(self.rapiddns_output)
                self.rapiddns_qthread.notice_print.connect(self.notice_output)
                
                self.fofa_thread.start()
                self.fofa_thread.quit()
                self.zoomeye_thread.start()
                self.zoomeye_thread.quit()
                self.quake_thread.start()
                self.quake_thread.quit()
                self.shodan_thread.start()
                self.shodan_thread.quit()
                self.censys_thread.start()
                self.censys_thread.quit()
                self.binaryedge_thread.start()
                self.binaryedge_thread.quit()
                self.rapiddns_qthread.start()
                self.rapiddns_qthread.quit()
                self.final_result_search_output_textBrowser.setText('')


        

    def start_proxy(self):
        email = self.fofa_key()[0][0]
        key = self.fofa_key()[1][0]
        proxy_aliving = []
        try:
            with open('./temp/proxylist','r',encoding='utf8') as f:
                proxy_count = len(f.readlines())
        except Exception:
            self.proxy_output_textBrowser.setText("<font color='#ffff00'>" + ">没有proxylist文件"+ "<font>")
        
        
        self.proxy_start = get_proxy_list(email,key)
        self.proxy_start.text_print.connect(self.proxy_output)
        self.proxy_start.start()
    
    def fofa_output(self,text):
        if '错误' in text:
            self.fofa_search_output_textBrowser.setText(str(text))
        else:
            self.fofa_search_output_textBrowser.append(str(text))
    
    def zoomeye_output(self,text):
        if '错误' in text:
            self.zoomeye_search_output_textBrowser.setText(str(text))
        else:
            self.zoomeye_search_output_textBrowser.append(str(text))
    
    def quake_output(self,text):
        if '错误' in text:
            self.quake_search_output_textBrowser.setText(str(text))
        else:
            self.quake_search_output_textBrowser.append(str(text))
    
    def shodan_output(self,text):
        if '错误' in text:
            self.shodan_search_output_textBrowser.setText(str(text))
        else:
            self.shodan_search_output_textBrowser.append(str(text))
    
    def censys_output(self,text):
        if '错误' in text:
            self.censys_search_output_textBrowser.setText(str(text))
        else:
            self.censys_search_output_textBrowser.append(str(text))
    
    def binaryedge_output(self,text):
        if '错误' in text:
            self.binaryedge_search_output_textBrowser.setText(str(text))
        elif '开始整理数据' in text:
            # self.start_res = result_clear(self.final_result_search_output_textBrowser.toPlainText())
            self.start_res = result_start()
            self.start_res.text_print.connect(self.result_start_output)
            self.start_res.start()

        else:
            self.binaryedge_search_output_textBrowser.append(str(text))
    
    def rapiddns_output(self,text):
        if '开始整理数据' in text:
            self.start_res = result_start()
            self.start_res.text_print.connect(self.result_start_output)
            self.start_res.start()
        else:
            pass
    

    def proxy_output(self,text):
        appendlist = ['发现存活代理','[+]','高质量代理']
        settextlist = ['代理请求失败','正在请求新代理','代理获取完成']
        if '发现存活代理' in text or '[+]' in text or '高质量代理' in text:
            self.proxy_output_textBrowser.append(str(text))
        elif '正在请求新代理' in text or '代理请求失败' in text or '代理获取完成' in text:
            self.proxy_output_textBrowser.setText(str(text))
        else:
            self.proxy_output_textBrowser.append(str(text))

    def result_start_output(self,text):
        if "start" in text:
            self.start_res = result_clear(self.final_result_search_output_textBrowser.toPlainText())
            self.start_res.text_print.connect(self.all_output)
            self.start_res.start()
        else:
            pass

    
    
    def notice_output(self,text):
        self.notice_output_textBrowser.append(str(text))
    
    def count_output(self,text):
        self.count_output_textBrowser.append(str(text))

    def all_output(self,text):
        if '开始整理数据' in text:
            self.final_result_search_output_textBrowser.setText('')
        else:
            self.final_result_search_output_textBrowser.append(str(text))

class result_start(QThread):
    text_print = pyqtSignal(str)
    notice_print = pyqtSignal(str)
    count_print = pyqtSignal(str)
    res_print = pyqtSignal(str)

    def __init__(self):
        super(result_start,self).__init__()

    def run(self):
        time.sleep(6)
        self.text_print.emit("start")



class result_clear(QThread):
    text_print = pyqtSignal(str)
    notice_print = pyqtSignal(str)
    count_print = pyqtSignal(str)
    res_print = pyqtSignal(str)

    def __init__(self,a):
        super(result_clear,self).__init__()
        self.res = a
    
    def run(self):
        # time.sleep(6)
        test = self.res.strip().replace('[+]','').split('\n')

        save_xls = time.strftime("%Y%m%d%H%M%S", time.localtime()) + '.xls'
        cout = 1
        book = xlwt.Workbook(encoding='utf-8')
        sheet = book.add_sheet('hostinfo',cell_overwrite_ok=True)
        sheet.write(0,0, 'Hostinfo')
        sheet.write(0,1, 'Protocol')
        sheet.write(0,2, 'Banner')
        for i in test:
            list_a = i.strip().replace('[+]','').split(',')
            if len(list_a) == 1:
                sheet.write(cout,0,list_a[0])
                sheet.write(cout,1,'Null')
                sheet.write(cout,2,'Null')
                cout += 1
            elif len(list_a) == 2:
                sheet.write(cout,0,list_a[0])
                sheet.write(cout,1,list_a[1])
                sheet.write(cout,2,'Null')
                cout += 1
            else:
                sheet.write(cout,0,list_a[0])
                sheet.write(cout,1,list_a[1])
                sheet.write(cout,2,list_a[2])
                cout += 1
        book.save('./result/'+save_xls)

        
        webtarget = {}
        nowtarget = {}
        # types = ['http','https','ssl/http']
        self.text_print.emit("<font color='#55ff00'>" + ">开始整理数据..." + "<font>")
        for i in test:
            x = i.split(',')
            if len(x) == 3:
                if all(v for v in i.split(',')) == False:
                    hostinfo = i.split(',')[0]
                    service = i.split(',')[1]
                    if hostinfo in webtarget.keys():
                        aa = webtarget[hostinfo]
                        # print(webtarget)
                        aa[0].append(service)
                    else:
                        webtarget[hostinfo] = [[service],[]]
                        # print(webtarget)
                    # print(hostinfo , service)
                else:
                    hostinfo = i.split(',')[0]
                    service = i.split(',')[1]
                    title = i.split(',')[2]
                    if hostinfo in webtarget.keys():
                        # print(webtarget)
                        aa = webtarget[hostinfo]
                        aa[0].append(service)
                        aa[1].append(title)
                    else:
                        webtarget[hostinfo] = [[service],[title]]
                    # print(hostinfo , service,title)
            else:
                if all(v for v in i.split(',')) == False:
                    pass
                else:
                    hostinfo = i.split(',')[0]
                    service = i.split(',')[1]
                    if hostinfo in webtarget.keys():
                        bb = webtarget[hostinfo]
                        bb[0].append(service)
                    elif hostinfo in nowtarget.keys():
                        bb = nowtarget[hostinfo]
                        bb.append(service)
                    else:
                        nowtarget[hostinfo] = [service]
        for i in webtarget.keys(): 
            service_https = ['https','http/ssl','https-simple-new'] 
            services = list(set(webtarget[i][0]))    
            title =   list(set(webtarget[i][1]))    
            services_ip = ''
            title_ip = ''
            if len(services) >= 2:
                for j in services:
                    services_ip = services_ip +j +'|'
                    if j == 'http':
                        host_t = j
                    elif j in service_https:
                        host_t = 'https'
                    else:
                        pass
                httpurl = '<a href=\"'+host_t +'://' + i + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + i  + '</span></a>'

                if len(title) >= 2:
                    for k in title:
                        title_ip = title_ip +k + '|'
                        
                    self.text_print.emit("<font color='#ffff00'>" + '资产: '+ httpurl +' 协议有变动: ' +services_ip+ "<font>")
                    self.text_print.emit("<font color='#ffff00'>" + '标题有变动: '+ title_ip + "<font>")
                    time.sleep(0.1)
                elif len(title) == 1:
                    self.text_print.emit("<font color='#55ff00'>" + '资产: '+ httpurl +' 协议有变动: ' +services[0]+ "<font>")
                    self.text_print.emit("<font color='#55ff00'>" + '标题: '+ title[0] + "<font>")
                    time.sleep(0.1)

                else:
                    self.text_print.emit("<font color='#ffff00'>" + '资产: '+ httpurl +' 协议有变动: ' +services_ip+ "<font>")
                    self.text_print.emit("<font color='#55ff00'>" + '标题: '+ 'None'+ "<font>")
                    time.sleep(0.1)

            else:
                if services[0] in service_https:
                    http_protocol = 'https'
                else:
                    http_protocol = services[0]

                httpurl = '<a href=\"'+ http_protocol +'://' + i + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + i  + '</span></a>'
                if len(title) >= 2:
                    for k in title:
                        title_ip = title_ip +k+ '|'                    
                    self.text_print.emit("<font color='#55ff00'>" + '资产: '+ httpurl +' 协议无变动: ' +http_protocol+ "<font>")
                    self.text_print.emit("<font color='#ffff00'>" + '标题有变动: '+ title_ip + "<font>")
                    time.sleep(0.1)
                elif len(title) == 1:
                    self.text_print.emit("<font color='#55ff00'>" + '资产: '+ httpurl +' 协议无变动: ' +http_protocol+ "<font>")
                    self.text_print.emit("<font color='#55ff00'>" + '标题: '+ title[0] + "<font>")
                    time.sleep(0.1)
                else:
                    self.text_print.emit("<font color='#55ff00'>" + '资产: '+ httpurl +' 协议无变动: ' +http_protocol+ "<font>")
                    self.text_print.emit("<font color='#55ff00'>" + '标题: None' + "<font>")
                    time.sleep(0.1)
        
        for inow in nowtarget.keys():
            services_host = list(set(nowtarget[inow]))
            protocol = ''
            if len(services_host) >= 2:
                for f in services_host:
                    protocol = protocol + f +'|'
                self.text_print.emit("<font color='#ffff00'>" + '资产: '+ inow +' 协议有变动: ' +protocol+ "<font>")
            else:
                self.text_print.emit("<font color='#55ff00'>" + '资产: '+ inow +' 协议无变动: ' +services_host[0]+ "<font>")




class fofa_search_qthread(QThread):
    text_print = pyqtSignal(str)
    notice_print = pyqtSignal(str)
    count_print = pyqtSignal(str)
    res_print = pyqtSignal(str)

    def __init__(self,a,b,c,d,e,f,g,h,i):
        super(fofa_search_qthread,self).__init__()
        self.headers = {
                        'Upgrade-Insecure-Requests': '1',
                        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36'
                    }
        day = re.findall('\d*',a)
        days = datetime.date.today() - datetime.timedelta(int(day[0]))
        self.basic_qstr = e.strip()
        self.qstr = b + '&&'  + 'after="' + str(days) + '"'
        #如不要title，可以加词语发('type='+'"'+'service'+'"' + '&&')
        self.base64_qstr = str(base64.b64encode(self.qstr.encode("utf-8")),'utf-8')
        self.email = c
        self.key = d
        self.log_time = f
        self.proxy_flag = g
        self.start_flag = h
        self.size = i

    
    def run(self):
        try:
            if self.start_flag == False:
                self.text_print.emit("<font color='#ff0000'>" + ">Fofa已关闭" + "<font>")
            else:
                if os.path.getsize('./temp/fofa_search.log') > 0:
                    with open('./temp/fofa_search.log','r',encoding='utf8') as fofa_log:
                        info = json.load(fofa_log)
                else:
                    info = {}

                if self.basic_qstr in list(info.keys()):
                    t0 = time.time()
                    select_list1 = []
                    histtory_search = info[self.basic_qstr]
                    for i in histtory_search['results']:
                        hostinfo = str(i[1]) + ":" + str(i[2])
                        select_list1.append(hostinfo)
                        if i[4] == 'http':
                            httpurl = '<a href=\"http://' + str(i[1]) + ":" + str(i[2]) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(i[1]) + ":" + str(i[2])  + '</span></a>'
                            self.text_print.emit("<font color='#55ff00'>" + "Host: " + httpurl + "<font>")
                            self.text_print.emit("<font color='#55ff00'>" + "Title: " + i[3] + "<font>")
                            self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + i[4] + "<font>")
                            self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                            self.res_print.emit("<font color='#55ff00'>" +"[+]" + httpurl +","+ i[4] +","+i[3]+ "<font>") 
                        elif i[4] == 'https': 
                            httpurl = '<a href=\"https://' + str(i[1]) + ":" + str(i[2]) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(i[1]) + ":" + str(i[2])  + '</span></a>'
                            self.text_print.emit("<font color='#55ff00'>" + "Host: " + httpurl + "<font>")
                            self.text_print.emit("<font color='#55ff00'>" + "Title: " + i[3] + "<font>")
                            self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + i[4] + "<font>")
                            self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                            self.res_print.emit("<font color='#55ff00'>" +"[+]" + httpurl +","+ i[4] +","+i[3]+ "<font>") 
                        elif 'app=' in self.basic_qstr:
                            httpurl = '<a href=\"http://' + str(i[1]) + ":" + str(i[2]) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(i[1]) + ":" + str(i[2])  + '</span></a>'
                            self.text_print.emit("<font color='#55ff00'>" + "Host: " + httpurl + "<font>")
                            self.text_print.emit("<font color='#55ff00'>" + "Title: " + i[3] + "<font>")
                            self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + i[4] + "<font>")
                            self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                            self.res_print.emit("<font color='#55ff00'>" +"[+]" + httpurl +","+ "http" +","+i[3]+ "<font>") 

                        else:  
                            self.text_print.emit("<font color='#55ff00'>" + "Host: " + i[1] + ":" + i[2] + "<font>")                       
                            self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + i[4] + "<font>")
                            self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                            self.res_print.emit("<font color='#55ff00'>" +"[+]" + i[1] + ":" + i[2] +","+ i[4] + "<font>") 
                    
                    self.notice_print.emit("<font color='#55ff00'>" + ">Fofa历史查询完成" + "<font>")  
                    self.count_print.emit("<font color='#55ff00'>" + "==================" + "<font>") 
                    self.count_print.emit("<font color='#55ff00'>" + ">Fofa当前资产:" + str(len(histtory_search['results'])) + "<font>")
                    self.count_print.emit("<font color='#55ff00'>" +  ">Fofa重复资产:" + str(len(select_list1)-len(list(set(select_list1))))  + "<font>")
                    self.count_print.emit("<font color='#55ff00'>" +  ">Fofa总计资产:" + str(histtory_search['size'])  + "<font>")                     
                    self.count_print.emit("<font color='#55ff00'>" +  ">耗时:" + str(round(time.time() - t0,4)) + "秒" + "<font>")
                    # self.text_print.emit("<font color='#55ff00'>" + '搜索完成' + "<font>")
                elif 'app=' in self.basic_qstr:
                    if '++' in self.basic_qstr or '--' in self.basic_qstr or '^^' in self.basic_qstr:
                        self.text_print.emit("<font color='#ff0000'>" + ">APP搜索不支持多语法" + httpurl + "<font>")
                    else:
                        with open("./apprule.json",'r',encoding='utf8') as f:
                            info_str = json.load(f)   
                        if self.basic_qstr not in info_str.keys():
                            self.text_print.emit("<font color='#ff0000'>" + ">APP语法未定义" + "<font>")
                        else:
                            basic_qstr = info_str[self.basic_qstr]['fofa']
                            base64_qstr = str(base64.b64encode(basic_qstr.encode("utf-8")),'utf-8')
                            proxy_alive = {}
                            t0 = time.time()
                            select_list = []  
                            api_url_http = 'http://fofa.so/api/v1/search/all?email=%s&key=%s&fields=host,ip,port,title,protocol,header,banner&size=%s&page=1&qbase64=%s'%(self.email,self.key,self.size,base64_qstr)              
                            api_url_https = 'https://fofa.so/api/v1/search/all?email=%s&key=%s&fields=host,ip,port,title,protocol,header,banner&size=%s&page=1&qbase64=%s'%(self.email,self.key,self.size,base64_qstr)
                            if self.proxy_flag == 'start':
                                with open('./temp/proxylist','r',encoding='utf8') as pt:
                                    pr = pt.readlines()
                                proxyinfo = random.choice(pr)
                                types = proxyinfo.strip().split(',')[0]
                                host = proxyinfo.strip().split(',')[1]
                                port = proxyinfo.strip().split(',')[2]
                                proxy_alive[types]=types + "://"+host+":"+port                                                          
                            else:
                                pass

                            if len(proxy_alive.keys()) == 1:
                                if list(proxy_alive.keys())[0] == 'http':
                                    res = requests.get(url=api_url_http,headers=self.headers,proxies={'http': "http://{0}:{1}".format(host,port)})
                                else:
                                    res = requests.get(url=api_url_https,headers=self.headers,proxies={'https': "https://{0}:{1}".format(host,port)}) 
                            else:
                                res = requests.get(url=api_url_https,headers=self.headers)
                            fofa_res = {}
                            fofa_res[self.basic_qstr] = res.json()
                            fofa_res_log_new = json.dumps(fofa_res,indent=3) 
                            if res.json()['error'] is True:
                                self.text_print.emit("<font color='#ff0000'>" + ">Fofa API错误" + "<font>")
                            else:
                                if len(res.json()['results']) == 0:
                                    self.text_print.emit("<font color='#ff0000'>" + ">Fofa没有相关资产" + "<font>")
                                else:                                      
                                    for i in res.json()['results']:
                                        hostinfo = str(i[1]) + ":" + str(i[2])
                                        select_list.append(hostinfo)
                                        if i[4] == 'http':
                                            httpurl = '<a href=\"http://' + str(i[1]) + ":" + str(i[2]) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(i[1]) + ":" + str(i[2])  + '</span></a>'
                                            self.text_print.emit("<font color='#55ff00'>" + "Host: " + httpurl + "<font>")
                                            self.text_print.emit("<font color='#55ff00'>" + "Title: " + i[3] + "<font>")
                                            self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + i[4] + "<font>")
                                            self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                                            self.res_print.emit("<font color='#55ff00'>" +"[+]" + httpurl +","+ i[4] +","+i[3]+ "<font>")
                                        elif i[4] == 'https': 
                                            httpurl = '<a href=\"https://' + str(i[1]) + ":" + str(i[2]) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(i[1]) + ":" + str(i[2])  + '</span></a>'
                                            self.text_print.emit("<font color='#55ff00'>" + "Host: " + httpurl + "<font>")
                                            self.text_print.emit("<font color='#55ff00'>" + "Title: " + i[3] + "<font>")
                                            self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + i[4] + "<font>")
                                            self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                                            self.res_print.emit("<font color='#55ff00'>" +"[+]" + httpurl +","+ i[4] +","+i[3]+ "<font>")
                                        elif "app=" in self.basic_qstr:
                                            httpurl = '<a href=\"http://' + str(i[1]) + ":" + str(i[2]) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(i[1]) + ":" + str(i[2])  + '</span></a>'
                                            self.text_print.emit("<font color='#55ff00'>" + "Host: " + httpurl + "<font>")
                                            self.text_print.emit("<font color='#55ff00'>" + "Title: " + i[3] + "<font>")
                                            self.text_print.emit("<font color='#55ff00'>" + "Protocol: http" + "<font>")
                                            self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                                            self.res_print.emit("<font color='#55ff00'>" +"[+]" + httpurl +","+ "http" +","+i[3]+ "<font>")

                                        else:  
                                            self.text_print.emit("<font color='#55ff00'>" + "Host: " + i[1] + ":" + i[2] + "<font>")                       
                                            # self.text_print.emit("<font color='#55ff00'>" + "Title: " + i[3] + "<font>")
                                            self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + i[4] + "<font>")
                                            self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                                            self.res_print.emit("<font color='#55ff00'>" +"[+]" + i[1] + ":" + i[3] +","+ "http" + "<font>") 


                                    

                            
                        
                                    self.notice_print.emit("<font color='#55ff00'>" + ">Fofa搜索完成" + "<font>")  
                                    self.count_print.emit("<font color='#55ff00'>" + "==================" +  "<font>") 
                                    self.count_print.emit("<font color='#55ff00'>" + ">Fofa当前资产:" + str(len(res.json()['results'])) + "<font>") 
                                    self.count_print.emit("<font color='#55ff00'>" +  ">Fofa重复资产:" + str(len(select_list)-len(list(set(select_list))))  + "<font>")
                                    self.count_print.emit("<font color='#55ff00'>" +  ">Fofa总计资产:" + str(res.json()['size'])  + "<font>")                     
                                    self.count_print.emit("<font color='#55ff00'>" +  ">耗时:" + str(round(time.time() - t0,4)) + "秒" + "<font>")
                                    if self.log_time > 5:
                                        os.remove("./temp/fofa_search.log")
                                        with open('./temp/fofa_search.log','w+',encoding='utf8') as fofa_log_write:
                                            fofa_log_write.write(fofa_res_log_new)
                                        self.notice_print.emit("<font color='#55ff00'>" + ">Fofa日志清理完成" + "<font>")
                                    else:
                                        with open('./temp/fofa_search.log','w',encoding='utf8') as fofa_log_write:
                                            info[self.basic_qstr] = res.json()
                                            fofa_res_log = json.dumps(info,indent=3) 
                                            fofa_log_write.write(fofa_res_log)
                                        self.notice_print.emit("<font color='#55ff00'>" + ">Fofa日志存储完成" + "<font>")


                else:
                    proxy_alive = {}
                    t0 = time.time()
                    select_list = []  
                    api_url_http = 'http://fofa.so/api/v1/search/all?email=%s&key=%s&fields=host,ip,port,title,protocol,header,banner&size=%s&page=1&qbase64=%s'%(self.email,self.key,self.size,self.base64_qstr)              
                    api_url_https = 'https://fofa.so/api/v1/search/all?email=%s&key=%s&fields=host,ip,port,title,protocol,header,banner&size=%s&page=1&qbase64=%s'%(self.email,self.key,self.size,self.base64_qstr)
                    if self.proxy_flag == 'start':
                        with open('./temp/proxylist','r',encoding='utf8') as pt:
                            pr = pt.readlines()
                        proxyinfo = random.choice(pr)
                        types = proxyinfo.strip().split(',')[0]
                        host = proxyinfo.strip().split(',')[1]
                        port = proxyinfo.strip().split(',')[2]
                        proxy_alive[types]=types + "://"+host+":"+port                                                          
                    else:
                        pass

                    if len(proxy_alive.keys()) == 1:
                        if list(proxy_alive.keys())[0] == 'http':
                            res = requests.get(url=api_url_http,headers=self.headers,proxies={'http': "http://{0}:{1}".format(host,port)})
                        else:
                            res = requests.get(url=api_url_https,headers=self.headers,proxies={'https': "https://{0}:{1}".format(host,port)}) 
                    else:
                        res = requests.get(url=api_url_https,headers=self.headers)
                    fofa_res = {}
                    fofa_res[self.basic_qstr] = res.json()
                    fofa_res_log_new = json.dumps(fofa_res,indent=3) 
                    if res.json()['error'] is True:
                        self.text_print.emit("<font color='#ff0000'>" + ">Fofa API错误" + "<font>")
                    else:
                        if len(res.json()['results']) == 0:
                            self.text_print.emit("<font color='#ff0000'>" + ">Fofa没有相关资产" + "<font>")
                        else:                                      
                            for i in res.json()['results']:
                                hostinfo = str(i[1]) + ":" + str(i[2])
                                select_list.append(hostinfo)
                                if i[4] == 'http':
                                    httpurl = '<a href=\"http://' + str(i[1]) + ":" + str(i[2]) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(i[1]) + ":" + str(i[2])  + '</span></a>'
                                    self.text_print.emit("<font color='#55ff00'>" + "Host: " + httpurl + "<font>")
                                    self.text_print.emit("<font color='#55ff00'>" + "Title: " + i[3] + "<font>")
                                    self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + i[4] + "<font>")
                                    self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                                    self.res_print.emit("<font color='#55ff00'>" +"[+]" + httpurl +","+ i[4] +","+i[3]+ "<font>")
                                elif i[4] == 'https': 
                                    httpurl = '<a href=\"https://' + str(i[1]) + ":" + str(i[2]) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(i[1]) + ":" + str(i[2])  + '</span></a>'
                                    self.text_print.emit("<font color='#55ff00'>" + "Host: " + httpurl + "<font>")
                                    self.text_print.emit("<font color='#55ff00'>" + "Title: " + i[3] + "<font>")
                                    self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + i[4] + "<font>")
                                    self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                                    self.res_print.emit("<font color='#55ff00'>" +"[+]" + httpurl +","+ i[4] +","+i[3]+ "<font>")
                                else:  
                                    self.text_print.emit("<font color='#55ff00'>" + "Host: " + i[1] + ":" + i[2] + "<font>")                       
                                    # self.text_print.emit("<font color='#55ff00'>" + "Title: " + i[3] + "<font>")
                                    self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + i[4] + "<font>")
                                    self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                                    self.res_print.emit("<font color='#55ff00'>" +"[+]" + i[1] + ":" + i[3] +","+ "http" + "<font>") 

                            

                    
                
                            self.notice_print.emit("<font color='#55ff00'>" + ">Fofa搜索完成" + "<font>")  
                            self.count_print.emit("<font color='#55ff00'>" + "==================" +  "<font>") 
                            self.count_print.emit("<font color='#55ff00'>" + ">Fofa当前资产:" + str(len(res.json()['results'])) + "<font>") 
                            self.count_print.emit("<font color='#55ff00'>" +  ">Fofa重复资产:" + str(len(select_list)-len(list(set(select_list))))  + "<font>")
                            self.count_print.emit("<font color='#55ff00'>" +  ">Fofa总计资产:" + str(res.json()['size'])  + "<font>")                     
                            self.count_print.emit("<font color='#55ff00'>" +  ">耗时:" + str(round(time.time() - t0,4)) + "秒" + "<font>")
                            if self.log_time > 5:
                                os.remove("./temp/fofa_search.log")
                                with open('./temp/fofa_search.log','w+',encoding='utf8') as fofa_log_write:
                                    fofa_log_write.write(fofa_res_log_new)
                                self.notice_print.emit("<font color='#55ff00'>" + ">Fofa日志清理完成" + "<font>")
                            else:
                                with open('./temp/fofa_search.log','w',encoding='utf8') as fofa_log_write:
                                    info[self.basic_qstr] = res.json()
                                    fofa_res_log = json.dumps(info,indent=3) 
                                    fofa_log_write.write(fofa_res_log)
                                self.notice_print.emit("<font color='#55ff00'>" + ">Fofa日志存储完成" + "<font>")

        except Exception as e:
            pass
        
        

class zoomeye_search_qthread(QThread):
    text_print = pyqtSignal(str)
    notice_print = pyqtSignal(str)
    count_print = pyqtSignal(str)
    res_print = pyqtSignal(str)

    def __init__(self,a,b,c,d,e,f,g,h):
        super(zoomeye_search_qthread,self).__init__()
        day = re.findall('\d*',c)
        days = datetime.date.today() - datetime.timedelta(int(day[0]))
        # qstr = a + ' +' + 'after:'+'"' +str(days) + '"'
        qstr = a 
        self.qstr = quote(qstr,'utf-8')
        # self.headers = {
        #                 "Authorization": b
        #             }
        self.headers = {                     
                        "User-Agent": random.choice(USER_AGENTS),
        }
        self.basic_qstr = d.strip()
        self.log_time = e
        self.proxy_flag = f
        self.start_flag = g
        self.size = h
    
    def run(self):
        try:
            if self.start_flag == False:
                self.text_print.emit("<font color='#ff0000'>" + ">Zoomeye已关闭" + "<font>")
            else:
                if os.path.getsize('./temp/zoomeye_search.log') > 0:
                    with open('./temp/zoomeye_search.log','r',encoding='utf8') as zoomeye_log:
                        info = json.load(zoomeye_log)
                else:
                    info = {}

                if self.basic_qstr in list(info.keys()):
                    t0 = time.time()
                    select_list = []
                    histtory_search = info[self.basic_qstr]
                    for i in histtory_search['matches']:
                        hostinfo = str(i['ip']) + ":" + str(i['portinfo']['port'])
                        select_list.append(hostinfo)
                        if i['portinfo']['service'] == 'http':
                            httpurl = '<a href=\"http://' + str(i['ip']) + ":" + str(i['portinfo']['port']) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(i['ip']) + ":" + str(i['portinfo']['port'])  + '</span></a>'
                            self.text_print.emit("<font color='#55ff00'>" + "Host: " +  httpurl + "<font>")                    
                            if 'title' in i['portinfo'].keys():
                                if i['portinfo']['title'] == None:
                                    title = 'Title: None'
                                    self.text_print.emit("<font color='#55ff00'>" + "Title: None" + "<font>")
                                else:
                                    title = str(i['portinfo']['title'][0])                    
                                    self.text_print.emit("<font color='#55ff00'>" + "Title: " + str(i['portinfo']['title'][0]) + "<font>")
                            else:
                                title = str(BeautifulSoup(i['raw_data'],'html.parser').title.string)    
                                self.text_print.emit("<font color='#55ff00'>" + "Title: " + title + "<font>")
                            self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + str(i['portinfo']['service']) + "<font>")
                            self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                            self.res_print.emit("<font color='#55ff00'>" + '[+]'+httpurl+','+str(i['portinfo']['service'])+','+title + "<font>")

                        elif i['portinfo']['service'] == 'https':
                            httpurl = '<a href=\"https://' + str(i['ip']) + ":" + str(i['portinfo']['port']) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(i['ip']) + ":" + str(i['portinfo']['port'])  + '</span></a>'
                            self.text_print.emit("<font color='#55ff00'>" + "Host: " +  httpurl + "<font>")                    
                            if 'title' in i['portinfo'].keys():
                                if i['portinfo']['title'] == None:
                                    title = 'Title: None'
                                    self.text_print.emit("<font color='#55ff00'>" + "Title: None" + "<font>")
                                else:
                                    title = str(i['portinfo']['title'][0])                        
                                    self.text_print.emit("<font color='#55ff00'>" + "Title: " + str(i['portinfo']['title'][0]) + "<font>")
                            else:
                                title = str(BeautifulSoup(i['raw_data'],'html.parser').title.string)                           
                                self.text_print.emit("<font color='#55ff00'>" + "Title: " + title + "<font>")
                            self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + str(i['portinfo']['service']) + "<font>")
                            self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                            self.res_print.emit("<font color='#55ff00'>" + '[+]'+httpurl+','+str(i['portinfo']['service'])+','+title + "<font>")

                        else:
                            self.text_print.emit("<font color='#55ff00'>" + "Host: " + str(i['ip']) + ":" + str(i['portinfo']['port']) + "<font>")
                            self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + str(i['portinfo']['service']) + "<font>")
                            self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                            self.res_print.emit("<font color='#55ff00'>" + '[+]'+ str(i['ip']) + ":" + str(i['portinfo']['port'])+',' +str(i['portinfo']['service']) + "<font>")
                    
                    self.notice_print.emit("<font color='#55ff00'>" + ">Zoomeye历史查询完成" + "<font>")
                    self.count_print.emit("<font color='#55ff00'>" + "==================" +  "<font>")
                    self.count_print.emit("<font color='#55ff00'>" + ">Zoomeye当前资产:" + str(len(histtory_search['matches'])) + "<font>")
                    self.count_print.emit("<font color='#55ff00'>" + ">Zoomeye重复资产:" + str(len(select_list)-len(list(set(select_list)))) + "<font>")
                    self.count_print.emit("<font color='#55ff00'>" + ">Zoomeye总计资产:" + str(histtory_search['total'])  + "<font>")
                    self.count_print.emit("<font color='#55ff00'>" + ">耗时:" + str(round(time.time() - t0,4)) + "秒" + "<font>")
                elif "app=" in self.basic_qstr:
                    if '++' in self.basic_qstr or '--' in self.basic_qstr or '^^' in self.basic_qstr:
                        self.text_print.emit("<font color='#ff0000'>" + '>APP暂不支持多语法' + "<font>")
                    else:
                        proxy_alive = {}
                        t0 = time.time()                
                        select_list = []
                        with open("./apprule.json",'r',encoding='utf8') as f:
                            info_str = json.load(f)   
                        if self.basic_qstr not in info_str.keys():
                            self.text_print.emit("<font color='#ff0000'>" + '>APP语法未定义' + "<font>")
                        else:
                            basic_qstr = info_str[self.basic_qstr]['zoomeye']
                            app_qstr = quote(basic_qstr,'utf-8')
                            # response = requests.get(url="https://api.zoomeye.org/host/search?query="+self.qstr, headers=self.headers)
                            api_url_http = 'http://www.zoomeye.org/search?t=host&q='
                            # api_url_https = 'https://api.zoomeye.org/host/search?query='
                            api_url_https = 'https://www.zoomeye.org/search?t=host&q='
                            if self.proxy_flag == 'start':
                                with open('./temp/proxylist','r',encoding='utf8') as pt:
                                    pr = pt.readlines()
                                proxyinfo = random.choice(pr)
                                types = proxyinfo.strip().split(',')[0]
                                host = proxyinfo.strip().split(',')[1]
                                port = proxyinfo.strip().split(',')[2]
                                if port == '80' or port == '443':
                                    proxy_alive[types]=types + "://"+host 
                                    host_infop =  proxyinfo.strip().split(',')[1]
                                else:
                                    proxy_alive[types]=types + "://"+host+":"+port  
                                    host_infop =  proxyinfo.strip().split(',')[1]+":"+proxyinfo.strip().split(',')[2]                                                        
                            else:
                                pass
                            
                            if len(proxy_alive.keys()) == 1:
                                if list(proxy_alive.keys())[0] == 'http':
                                    response = requests.get(url=api_url_http+app_qstr,headers=self.headers,proxies={'http': 'http://{0}'.format(host_infop)})
                                else:
                                    response = requests.get(url=api_url_https+app_qstr,headers=self.headers,proxies={'https': 'https://{0}'.format(host_infop)}) 
                            else:
                                response = requests.get(url=api_url_https+app_qstr,headers=self.headers,timeout=5)
                            # response = requests.get(url=api_url_https+app_qstr,headers=self.headers)
                            zoomeye_res = {}
                            zoomeye_res[self.basic_qstr] = response.json()
                            zoomeye_res_log_new = json.dumps(zoomeye_res,indent=3) 
                            if 'total' not in response.json().keys():
                                if 'error' in response.json().keys():
                                    self.text_print.emit("<font color='#ff0000'>" + '>Zoomeye API错误' + "<font>")
                                else:
                                    self.text_print.emit("<font color='#ff0000'>" + '>Zoomeye 未知错误' + "<font>")
                            else:
                                if response.json()['total'] == 0:
                                    self.text_print.emit("<font color='#ff0000'>" + '>Zoomeye没有相关资产' + "<font>")
                                else:                    
                                    for i in response.json()['matches']:
                                        hostinfo = str(i['ip']) + ":" + str(i['portinfo']['port'])
                                        select_list.append(hostinfo)
                                        if i['portinfo']['service'] == 'http':
                                            httpurl = '<a href=\"http://' + str(i['ip']) + ":" + str(i['portinfo']['port']) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(i['ip']) + ":" + str(i['portinfo']['port'])  + '</span></a>'
                                            self.text_print.emit("<font color='#55ff00'>" + "Host: " +  httpurl + "<font>")                    
                                            if 'title' in i['portinfo'].keys():
                                                if i['portinfo']['title'] == None:
                                                    title = 'Title: None'
                                                    self.text_print.emit("<font color='#55ff00'>" + "Title: None" + "<font>")
                                                else:
                                                    title = str(i['portinfo']['title'][0])                    
                                                    self.text_print.emit("<font color='#55ff00'>" + "Title: " + str(i['portinfo']['title'][0]) + "<font>")
                                            else:
                                                if BeautifulSoup(i['raw_data'],'html.parser').title == None:
                                                    title = 'None'
                                                else:
                                                    title = str(BeautifulSoup(i['raw_data'],'html.parser').title.string) 
                                            
                                            self.text_print.emit("<font color='#55ff00'>" + "Title: " + title + "<font>")
                                            self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + str(i['portinfo']['service']) + "<font>")
                                            self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                                            self.res_print.emit("<font color='#55ff00'>" + '[+]' + httpurl+','+str(i['portinfo']['service'])+','+title + "<font>")
                                        elif i['portinfo']['service'] == 'https':
                                            httpurl = '<a href=\"https://' + str(i['ip']) + ":" + str(i['portinfo']['port']) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(i['ip']) + ":" + str(i['portinfo']['port'])  + '</span></a>'
                                            self.text_print.emit("<font color='#55ff00'>" + "Host: " +  httpurl + "<font>")                    
                                            if 'title' in i['portinfo'].keys():
                                                if i['portinfo']['title'] == None:
                                                    title = 'Title: None'
                                                    self.text_print.emit("<font color='#55ff00'>" + "Title: None" + "<font>")
                                                else:
                                                    title = str(i['portinfo']['title'][0])                        
                                                    self.text_print.emit("<font color='#55ff00'>" + "Title: " + str(i['portinfo']['title'][0]) + "<font>")
                                            else:
                                                if BeautifulSoup(i['raw_data'],'html.parser').title == None:
                                                    title = 'None'
                                                else:
                                                    title = str(BeautifulSoup(i['raw_data'],'html.parser').title.string)

                                            self.text_print.emit("<font color='#55ff00'>" + "Title: " + title + "<font>")
                                            self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + str(i['portinfo']['service']) + "<font>")
                                            self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                                            self.res_print.emit("<font color='#55ff00'>" + '[+]' + httpurl+','+str(i['portinfo']['service'])+','+title + "<font>")

                                        else:
                                            self.text_print.emit("<font color='#55ff00'>" + "Host: " + str(i['ip']) + ":" + str(i['portinfo']['port']) + "<font>")
                                            self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + str(i['portinfo']['service']) + "<font>")
                                            self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                                            self.res_print.emit("<font color='#55ff00'>" + '[+]' + str(i['ip']) + ":" + str(i['portinfo']['port'])+','+str(i['portinfo']['service']) + "<font>")
                            
                                    self.notice_print.emit("<font color='#55ff00'>" + ">Zoomeye搜索完成" + "<font>")
                                    self.count_print.emit("<font color='#55ff00'>" + "==================" + "<font>")
                                    self.count_print.emit("<font color='#55ff00'>" + ">Zoomeye当前资产:" + str(len(response.json()['matches'])) + "<font>")
                                    self.count_print.emit("<font color='#55ff00'>" + ">Zoomeye重复资产:" + str(len(select_list)-len(list(set(select_list)))) + "<font>")
                                    self.count_print.emit("<font color='#55ff00'>" + ">Zoomeye总计资产:" + str(response.json()['total'])  + "<font>")
                                    self.count_print.emit("<font color='#55ff00'>" + ">耗时:" + str(round(time.time() - t0,4)) + "秒" + "<font>")
                                    if self.log_time > 5:
                                        os.remove("./temp/zoomeye_search.log")
                                        with open('./temp/zoomeye_search.log','w+',encoding='utf8') as zoomeye_log_write:
                                            zoomeye_log_write.write(zoomeye_res_log_new)
                                        self.notice_print.emit("<font color='#55ff00'>" + ">Zoomeye日志清理完成" + "<font>")
                                    else:
                                        with open('./temp/zoomeye_search.log','w',encoding='utf8') as zoomeye_log_write:
                                            info[self.basic_qstr] = response.json()
                                            zoomeye_res_log = json.dumps(info,indent=3) 
                                            zoomeye_log_write.write(zoomeye_res_log)

                                        self.notice_print.emit("<font color='#55ff00'>" + ">Zoomeye日志存储完成" + "<font>")

                else:
                    proxy_alive = {}
                    t0 = time.time()                
                    select_list = []
                    # response = requests.get(url="https://api.zoomeye.org/host/search?query="+self.qstr, headers=self.headers)
                    # api_url_http = 'http://api.zoomeye.org/host/search?query='
                    # api_url_https = 'https://api.zoomeye.org/host/search?query='
                    api_url_http = 'http://www.zoomeye.org/search?t=host&q='
                    # api_url_https = 'https://api.zoomeye.org/host/search?query='
                    api_url_https = 'https://www.zoomeye.org/search?t=host&q='
                    if self.proxy_flag == 'start':
                        with open('./temp/proxylist','r',encoding='utf8') as pt:
                            pr = pt.readlines()
                        proxyinfo = random.choice(pr)
                        types = proxyinfo.strip().split(',')[0]
                        host = proxyinfo.strip().split(',')[1]
                        port = proxyinfo.strip().split(',')[2]
                        if port == '80' or port == '443':
                            proxy_alive[types]=types + "://"+host 
                            host_infop =  proxyinfo.strip().split(',')[1]
                        else:
                            proxy_alive[types]=types + "://"+host+":"+port  
                            host_infop =  proxyinfo.strip().split(',')[1]+":"+proxyinfo.strip().split(',')[2]                                                        
                    else:
                        pass
                    
                    if len(proxy_alive.keys()) == 1:
                        if list(proxy_alive.keys())[0] == 'http':
                            response = requests.get(url=api_url_http+self.qstr,headers=self.headers,proxies={'http': 'http://{0}'.format(host_infop)})
                        else:
                            response = requests.get(url=api_url_https+self.qstr,headers=self.headers,proxies={'https': 'https://{0}'.format(host_infop)}) 
                    else:
                        response = requests.get(url=api_url_https+self.qstr,headers=self.headers,timeout=5)
                    # response = requests.get(url=api_url_https+self.qstr,headers=self.headers)
                    zoomeye_res = {}
                    zoomeye_res[self.basic_qstr] = response.json()
                    zoomeye_res_log_new = json.dumps(zoomeye_res,indent=3) 
                    if 'total' not in response.json().keys():
                        if 'error' in response.json().keys():
                            self.text_print.emit("<font color='#ff0000'>" + '>Zoomeye API错误' + "<font>")
                        else:
                            self.text_print.emit("<font color='#ff0000'>" + '>Zoomeye 未知错误' + "<font>")
                    else:
                        if response.json()['total'] == 0:
                            self.text_print.emit("<font color='#ff0000'>" + '>Zoomeye没有相关资产' + "<font>")
                        else:                
                            for i in response.json()['matches']:
                                hostinfo = str(i['ip']) + ":" + str(i['portinfo']['port'])
                                select_list.append(hostinfo)
                                if i['portinfo']['service'] == 'http':
                                    httpurl = '<a href=\"http://' + str(i['ip']) + ":" + str(i['portinfo']['port']) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(i['ip']) + ":" + str(i['portinfo']['port'])  + '</span></a>'
                                    self.text_print.emit("<font color='#55ff00'>" + "Host: " +  httpurl + "<font>")                    
                                    
                                    if 'title' in i['portinfo'].keys():
                                        if i['portinfo']['title'] == None:
                                            title = 'Title: None'
                                            self.text_print.emit("<font color='#55ff00'>" + "Title: None" + "<font>")
                                        else:
                                            title = str(i['portinfo']['title'][0])                    
                                            self.text_print.emit("<font color='#55ff00'>" + "Title: " + str(i['portinfo']['title'][0]) + "<font>")
                                    else:
                                        if BeautifulSoup(i['raw_data'],'html.parser').title == None:
                                            title = 'None'
                                        else:
                                            title = str(BeautifulSoup(i['raw_data'],'html.parser').title.string)
                                                
                                    self.text_print.emit("<font color='#55ff00'>" + "Title: " + title + "<font>")
                                    self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + str(i['portinfo']['service']) + "<font>")
                                    self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                                    self.res_print.emit("<font color='#55ff00'>" + '[+]' + httpurl+','+str(i['portinfo']['service'])+','+title + "<font>")
                                elif i['portinfo']['service'] == 'https':
                                    httpurl = '<a href=\"https://' + str(i['ip']) + ":" + str(i['portinfo']['port']) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(i['ip']) + ":" + str(i['portinfo']['port'])  + '</span></a>'
                                    self.text_print.emit("<font color='#55ff00'>" + "Host: " +  httpurl + "<font>")                    
                                    if 'title' in i['portinfo'].keys():
                                        if i['portinfo']['title'] == None:
                                            title = 'Title: None'
                                            self.text_print.emit("<font color='#55ff00'>" + "Title: None" + "<font>")
                                        else:
                                            title = str(i['portinfo']['title'][0])                        
                                            self.text_print.emit("<font color='#55ff00'>" + "Title: " + str(i['portinfo']['title'][0]) + "<font>")
                                    else:
                                        if BeautifulSoup(i['raw_data'],'html.parser').title == None:
                                            title = 'None'
                                        else:
                                            title = str(BeautifulSoup(i['raw_data'],'html.parser').title.string)

                                    self.text_print.emit("<font color='#55ff00'>" + "Title: " + title + "<font>")
                                    self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + str(i['portinfo']['service']) + "<font>")
                                    self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                                    self.res_print.emit("<font color='#55ff00'>" + '[+]' + httpurl+','+str(i['portinfo']['service'])+','+title + "<font>")

                                else:
                                    self.text_print.emit("<font color='#55ff00'>" + "Host: " + str(i['ip']) + ":" + str(i['portinfo']['port']) + "<font>")
                                    self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + str(i['portinfo']['service']) + "<font>")
                                    self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                                    self.res_print.emit("<font color='#55ff00'>" + '[+]' + str(i['ip']) + ":" + str(i['portinfo']['port'])+','+str(i['portinfo']['service']) + "<font>")
                    
                            self.notice_print.emit("<font color='#55ff00'>" + ">Zoomeye搜索完成" + "<font>")
                            self.count_print.emit("<font color='#55ff00'>" + "==================" + "<font>")
                            self.count_print.emit("<font color='#55ff00'>" + ">Zoomeye当前资产:" + str(len(response.json()['matches'])) + "<font>")
                            self.count_print.emit("<font color='#55ff00'>" + ">Zoomeye重复资产:" + str(len(select_list)-len(list(set(select_list)))) + "<font>")
                            self.count_print.emit("<font color='#55ff00'>" + ">Zoomeye总计资产:" + str(response.json()['total'])  + "<font>")
                            self.count_print.emit("<font color='#55ff00'>" + ">耗时:" + str(round(time.time() - t0,4)) + "秒" + "<font>")
                            if self.log_time > 5:
                                os.remove("./temp/zoomeye_search.log")
                                with open('./temp/zoomeye_search.log','w+',encoding='utf8') as zoomeye_log_write:
                                    zoomeye_log_write.write(zoomeye_res_log_new)
                                self.notice_print.emit("<font color='#55ff00'>" + ">Zoomeye日志清理完成" + "<font>")
                            else:
                                with open('./temp/zoomeye_search.log','w',encoding='utf8') as zoomeye_log_write:
                                    info[self.basic_qstr] = response.json()
                                    zoomeye_res_log = json.dumps(info,indent=3) 
                                    zoomeye_log_write.write(zoomeye_res_log)

                                self.notice_print.emit("<font color='#55ff00'>" + ">Zoomeye日志存储完成" + "<font>")
        except Exception as e:
            self.text_print.emit("<font color='#ff0000'>" + str(e) + "<font>")

class quake_search_qthread(QThread):
    text_print = pyqtSignal(str)
    notice_print = pyqtSignal(str)
    count_print = pyqtSignal(str)
    res_print = pyqtSignal(str)

    def __init__(self,a,b,c,d,e,f,g):
        super(quake_search_qthread,self).__init__()
        self.headers = {
            "X-QuakeToken": a
        }
        self.data = {
            "query": b,
            "start": 0,
            "size": g
        }
        self.basic_qstr = c.strip()
        self.log_time = d
        self.proxy_flag = e
        self.start_flag = f
    
    def run(self):
        try:
            if self.start_flag == False:
                self.text_print.emit("<font color='#ff0000'>" + ">Quake已关闭" + "<font>")
            else:
                if os.path.getsize('./temp/quake_search.log') > 0:
                    with open('./temp/quake_search.log','r',encoding='utf8') as quake_log:
                        info = json.load(quake_log)
                else:
                    info = {}
                    
                
                if self.basic_qstr in list(info.keys()):
                    t0 = time.time()
                    select_list = []
                    histtory_search = info[self.basic_qstr]                
                    for i in histtory_search['data']:
                        hostinfo = str(i['ip']) + ":" + str(i['port'])
                        select_list.append(hostinfo)
                        if i['service']['name'] == 'http':
                            if 'http' in i['service'].keys():
                                title_ip = i['service']['http']['title']
                            elif 'response' in i['service'].keys():
                                if BeautifulSoup(i['service']['response'],'html.parser').title == None:
                                    title_ip = 'None'
                                else:
                                    title_ip = str(BeautifulSoup(i['service']['response'],'html.parser').title.string)
                            else:
                                title_ip = 'None'
                            try:
                                httpurl = '<a href=\"http://' + str(i['ip']) + ":" + str(i['port']) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(i['ip']) + ":" + str(i['port'])  + '</span></a>'                           
                                self.text_print.emit("<font color='#55ff00'>" + "Host: " + httpurl + "<font>")
                                self.text_print.emit("<font color='#55ff00'>" + "Title: " + title_ip + "<font>")
                                self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + str(i['service']['name']) + "<font>")
                                self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                                self.res_print.emit("<font color='#55ff00'>" + '[+]'+httpurl+','+ str(i['service']['name']) +','+title_ip+ "<font>")
                            except Exception as e:
                                pass
                        elif i['service']['name'] == 'http/ssl':
                            # or i['service']['name'] == 'https/ssl'
                            if 'http/ssl' in i['service'].keys():
                                title_ip = i['service']['http/ssl']['title']
                            elif 'response' in i['service'].keys():
                                if BeautifulSoup(i['service']['response'],'html.parser').title == None:
                                    title_ip = 'None'
                                else:
                                    title_ip = str(BeautifulSoup(i['service']['response'],'html.parser').title.string)
                            else:
                                title_ip = 'None'

                                
                            httpurl = '<a href=\"https://' + str(i['ip']) + ":" + str(i['port']) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(i['ip']) + ":" + str(i['port'])  + '</span></a>'                           
                            self.text_print.emit("<font color='#55ff00'>" + "Host: " + httpurl + "<font>")
                            self.text_print.emit("<font color='#55ff00'>" + "Title: " + title_ip + "<font>")
                            self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + str(i['service']['name']) + "<font>")
                            self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                            self.res_print.emit("<font color='#55ff00'>" + '[+]'+httpurl+','+ str(i['service']['name']) +','+str(title_ip)+ "<font>")
                        else:
                            self.text_print.emit("<font color='#55ff00'>" + "Host: " + str(i['ip']) + ":" + str(i['port']) + "<font>")
                            self.text_print.emit("<font color='#55ff00'>" + "protocol: " + str(i['service']['name']) + "<font>")
                            self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                            self.res_print.emit("<font color='#55ff00'>" + '[+]'+str(i['ip']) + ":" + str(i['port'])+','+ str(i['service']['name']) + "<font>")
                    self.notice_print.emit("<font color='#55ff00'>" + ">Quake历史查询完成" + "<font>")
                    self.count_print.emit("<font color='#55ff00'>" + "==================" + "<font>")
                    self.count_print.emit("<font color='#55ff00'>" + ">Quake当前资产:" + str(histtory_search['meta']['pagination']['count']) + "<font>")
                    self.count_print.emit("<font color='#55ff00'>" + ">Quake重复资产:" + str(len(select_list)-len(list(set(select_list)))) + "<font>")
                    self.count_print.emit("<font color='#55ff00'>" + ">Quake总计资产:" + str(histtory_search['meta']['pagination']['total']) + "<font>")
                    self.count_print.emit("<font color='#55ff00'>" + ">耗时:" + str(round(time.time() - t0,4)) + "秒" + "<font>")
                elif "app=" in self.basic_qstr:
                    if '++' in self.basic_qstr or '--' in self.basic_qstr or '^^' in self.basic_qstr:
                        self.text_print.emit("<font color='#ff0000'>" + '>APP暂不支持多语法' + "<font>")
                    else:
                        with open("./apprule.json",'r',encoding='utf8') as f:
                            info_str = json.load(f) 
                        if self.basic_qstr not in info_str.keys():
                            self.text_print.emit("<font color='#ff0000'>" + '>APP语法未定义' + "<font>")
                        else:
                            basic_qstr = info_str[self.basic_qstr]['quake']
                            datastr = {
                                        "query": basic_qstr,
                                        "start": 0,
                                        "size": 10
                                    }
                            basic_qstr = info_str[self.basic_qstr]['zoomeye']
                            proxy_alive = {}
                            t0 = time.time()
                            select_list = []
                            response_quake = requests.post(url="https://quake.360.cn/api/v3/search/quake_service", headers=self.headers, json=datastr)
                            # if self.proxy_flag == 'start':
                            #     with open('./temp/proxylist','r',encoding='utf8') as pt:
                            #         pr = pt.readlines()
                            #     proxyinfo = random.choice(pr)
                            #     types = proxyinfo.strip().split(',')[0]
                            #     host = proxyinfo.strip().split(',')[1]
                            #     port = proxyinfo.strip().split(',')[2]
                            #     if port == '80' or port == '443':
                            #         proxy_alive[types]=types + "://"+host 
                            #         host_infop =  proxyinfo.strip().split(',')[1]
                            #     else:
                            #         proxy_alive[types]=types + "://"+host+":"+port  
                            #         host_infop =  proxyinfo.strip().split(',')[1]+":"+proxyinfo.strip().split(',')[2]                                                        
                            # else:
                            #     pass
                        
                            # if len(proxy_alive.keys()) == 1:
                            #     if list(proxy_alive.keys())[0] == 'http':
                            #         response_quake = requests.post(url="http://quake.360.cn/api/v3/search/quake_service",headers=self.headers,json=self.data,proxies={'http': 'http://{0}'.format(host_infop)})
                            #     else:
                            #         response_quake = requests.post(url="https://quake.360.cn/api/v3/search/quake_service",headers=self.headers,json=self.data,proxies={'https': 'https://{0}'.format(host_infop)}) 
                            # else:
                            #     response_quake = requests.post(url="https://quake.360.cn/api/v3/search/quake_service",headers=self.headers,json=self.data)

                            quake_res = {}
                            quake_res[self.basic_qstr] = response_quake.json()
                            quake_res_log_new = json.dumps(quake_res,indent=3) 
                            if response_quake.status_code == 401:
                                self.text_print.emit("<font color='#ff0000'>" + ">Quake账号密码错误" + "<font>")
                            else:
                                if len(response_quake.json()['data']) <= 0:
                                    self.text_print.emit("<font color='#ff0000'>" + ">Quake没有相关资产" + "<font>")
                                else:
                                    for i in response_quake.json()['data']:
                                        hostinfo = str(i['ip']) + ":" + str(i['port'])
                                        select_list.append(hostinfo)
                                        if i['service']['name'] == 'http': 
                                            if 'http' in i['service'].keys():
                                                title_ip = i['service']['http']['title']
                                            elif 'response' in i['service'].keys():
                                                if BeautifulSoup(i['service']['response'],'html.parser').title == None:
                                                    title_ip = 'None'
                                                else:
                                                    title_ip = str(BeautifulSoup(i['service']['response'],'html.parser').title.string)
                                            else:
                                                title_ip = 'None'
                                            try:
                                                httpurl = '<a href=\"http://' + str(i['ip']) + ":" + str(i['port']) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(i['ip']) + ":" + str(i['port'])  + '</span></a>'                           
                                                self.text_print.emit("<font color='#55ff00'>" + "Host: " + httpurl + "<font>")
                                                self.text_print.emit("<font color='#55ff00'>" + "Title: " + title_ip + "<font>")
                                                self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + str(i['service']['name']) + "<font>")
                                                self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                                                self.res_print.emit("<font color='#55ff00'>" + '[+]'+httpurl+','+ str(i['service']['name']) +','+title_ip+ "<font>")
                                            except Exception as e:
                                                pass
                                        elif i['service']['name'] == 'http/ssl': 
                                            #  or i['service']['name'] == 'https/ssl'
                                            if 'http/ssl' in i['service'].keys():
                                                    title_ip = i['service']['http/ssl']['title']
                                            elif 'response' in i['service'].keys():
                                                if BeautifulSoup(i['service']['response'],'html.parser').title == None:
                                                    title_ip = 'None'
                                                else:
                                                    title_ip = str(BeautifulSoup(i['service']['response'],'html.parser').title.string)
                                            else:
                                                title_ip = 'None'
                                            httpurl = '<a href=\"https://' + str(i['ip']) + ":" + str(i['port']) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(i['ip']) + ":" + str(i['port'])  + '</span></a>'                           
                                            self.text_print.emit("<font color='#55ff00'>" + "Host: " + httpurl + "<font>")
                                            self.text_print.emit("<font color='#55ff00'>" + "Title: " + str(title_ip) + "<font>")
                                            self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + str(i['service']['name']) + "<font>")
                                            self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                                            self.res_print.emit("<font color='#55ff00'>" + '[+]'+httpurl+','+ str(i['service']['name']) +','+str(title_ip)+ "<font>")
                                        else:
                                            self.text_print.emit("<font color='#55ff00'>" + "Host: " + str(i['ip']) + ":" + str(i['port']) + "<font>")
                                            self.text_print.emit("<font color='#55ff00'>" + "protocol: " + str(i['service']['name']) + "<font>")
                                            self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                                            self.res_print.emit("<font color='#55ff00'>" + '[+]'+ str(i['ip']) + ":" + str(i['port']) +','+ str(i['service']['name']) + "<font>")
                                    self.notice_print.emit("<font color='#55ff00'>" + ">Quake搜索完成" + "<font>")
                                    self.count_print.emit("<font color='#55ff00'>" + "==================" + "<font>")
                                    self.count_print.emit("<font color='#55ff00'>" + ">Quake当前资产:" + str(response_quake.json()['meta']['pagination']['count']) + "<font>")
                                    self.count_print.emit("<font color='#55ff00'>" + ">Quake重复资产:" + str(len(select_list)-len(list(set(select_list)))) + "<font>")
                                    self.count_print.emit("<font color='#55ff00'>" + ">Quake总计资产:" + str(response_quake.json()['meta']['pagination']['total']) + "<font>")
                                    self.count_print.emit("<font color='#55ff00'>" + ">耗时:" + str(round(time.time() - t0,4)) + "秒" + "<font>")
                                    if self.log_time > 5:
                                        os.remove("./temp/quake_search.log")
                                        with open('./temp/quake_search.log','w+',encoding='utf8') as quake_log_write:
                                            quake_log_write.write(quake_res_log_new)
                                            self.notice_print.emit("<font color='#55ff00'>" + ">Quake日志清理完成" + "<font>")
                                    else:
                                        with open('./temp/quake_search.log','w',encoding='utf8') as quake_log_write:
                                            info[self.basic_qstr] = response_quake.json()
                                            quake_res_log = json.dumps(info,indent=3) 
                                            quake_log_write.write(quake_res_log)

                                        self.notice_print.emit("<font color='#55ff00'>" + ">Quake日志存储完成" + "<font>")
                else:
                    proxy_alive = {}
                    t0 = time.time()
                    select_list = []
                    response_quake = requests.post(url="https://quake.360.cn/api/v3/search/quake_service", headers=self.headers, json=self.data)
                    # if self.proxy_flag == 'start':
                    #     with open('./temp/proxylist','r',encoding='utf8') as pt:
                    #         pr = pt.readlines()
                    #     proxyinfo = random.choice(pr)
                    #     types = proxyinfo.strip().split(',')[0]
                    #     host = proxyinfo.strip().split(',')[1]
                    #     port = proxyinfo.strip().split(',')[2]
                    #     if port == '80' or port == '443':
                    #         proxy_alive[types]=types + "://"+host 
                    #         host_infop =  proxyinfo.strip().split(',')[1]
                    #     else:
                    #         proxy_alive[types]=types + "://"+host+":"+port  
                    #         host_infop =  proxyinfo.strip().split(',')[1]+":"+proxyinfo.strip().split(',')[2]                                                        
                    # else:
                    #     pass
                
                    # if len(proxy_alive.keys()) == 1:
                    #     if list(proxy_alive.keys())[0] == 'http':
                    #         response_quake = requests.post(url="http://quake.360.cn/api/v3/search/quake_service",headers=self.headers,json=self.data,proxies={'http': 'http://{0}'.format(host_infop)})
                    #     else:
                    #         response_quake = requests.post(url="https://quake.360.cn/api/v3/search/quake_service",headers=self.headers,json=self.data,proxies={'https': 'https://{0}'.format(host_infop)}) 
                    # else:
                    #     response_quake = requests.post(url="https://quake.360.cn/api/v3/search/quake_service",headers=self.headers,json=self.data)

                    quake_res = {}
                    quake_res[self.basic_qstr] = response_quake.json()
                    quake_res_log_new = json.dumps(quake_res,indent=3) 
                    if response_quake.status_code == 401:
                        self.text_print.emit("<font color='#ff0000'>" + ">Quake账号密码错误" + "<font>")
                    else:
                        if len(response_quake.json()['data']) <= 0:
                            self.text_print.emit("<font color='#ff0000'>" + ">Quake没有相关资产" + "<font>")
                        else:
                            for i in response_quake.json()['data']:
                                hostinfo = str(i['ip']) + ":" + str(i['port'])
                                select_list.append(hostinfo)
                                if i['service']['name'] == 'http': 
                                    if 'http' in i['service'].keys():
                                        title_ip = i['service']['http']['title']
                                    elif 'response' in i['service'].keys():
                                        if BeautifulSoup(i['service']['response'],'html.parser').title == None:
                                            title_ip = 'None'
                                        else:
                                            title_ip = str(BeautifulSoup(i['service']['response'],'html.parser').title.string)
                                    else:
                                        title_ip = 'None'
                                    try:
                                        httpurl = '<a href=\"http://' + str(i['ip']) + ":" + str(i['port']) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(i['ip']) + ":" + str(i['port'])  + '</span></a>'                           
                                        self.text_print.emit("<font color='#55ff00'>" + "Host: " + httpurl + "<font>")
                                        self.text_print.emit("<font color='#55ff00'>" + "Title: " + title_ip + "<font>")
                                        self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + str(i['service']['name']) + "<font>")
                                        self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                                        self.res_print.emit("<font color='#55ff00'>" + '[+]'+httpurl+','+ str(i['service']['name']) +','+title_ip+ "<font>")
                                    except Exception as e:
                                        pass
                                elif i['service']['name'] == 'http/ssl': 
                                    #  or i['service']['name'] == 'https/ssl'
                                    if 'http/ssl' in i['service'].keys():
                                            title_ip = i['service']['http/ssl']['title']
                                    elif 'response' in i['service'].keys():
                                        if BeautifulSoup(i['service']['response'],'html.parser').title == None:
                                            title_ip = 'None'
                                        else:
                                            title_ip = str(BeautifulSoup(i['service']['response'],'html.parser').title.string)
                                    else:
                                        title_ip = 'None'
                                    httpurl = '<a href=\"https://' + str(i['ip']) + ":" + str(i['port']) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(i['ip']) + ":" + str(i['port'])  + '</span></a>'                           
                                    self.text_print.emit("<font color='#55ff00'>" + "Host: " + httpurl + "<font>")
                                    self.text_print.emit("<font color='#55ff00'>" + "Title: " + str(title_ip) + "<font>")
                                    self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + str(i['service']['name']) + "<font>")
                                    self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                                    self.res_print.emit("<font color='#55ff00'>" + '[+]'+httpurl+','+ str(i['service']['name']) +','+str(title_ip)+ "<font>")
                                else:
                                    self.text_print.emit("<font color='#55ff00'>" + "Host: " + str(i['ip']) + ":" + str(i['port']) + "<font>")
                                    self.text_print.emit("<font color='#55ff00'>" + "protocol: " + str(i['service']['name']) + "<font>")
                                    self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                                    self.res_print.emit("<font color='#55ff00'>" + '[+]'+ str(i['ip']) + ":" + str(i['port']) +','+ str(i['service']['name']) + "<font>")
                            self.notice_print.emit("<font color='#55ff00'>" + ">Quake搜索完成" + "<font>")
                            self.count_print.emit("<font color='#55ff00'>" + "==================" + "<font>")
                            self.count_print.emit("<font color='#55ff00'>" + ">Quake当前资产:" + str(response_quake.json()['meta']['pagination']['count']) + "<font>")
                            self.count_print.emit("<font color='#55ff00'>" + ">Quake重复资产:" + str(len(select_list)-len(list(set(select_list)))) + "<font>")
                            self.count_print.emit("<font color='#55ff00'>" + ">Quake总计资产:" + str(response_quake.json()['meta']['pagination']['total']) + "<font>")
                            self.count_print.emit("<font color='#55ff00'>" + ">耗时:" + str(round(time.time() - t0,4)) + "秒" + "<font>")
                            if self.log_time > 5:
                                os.remove("./temp/quake_search.log")
                                with open('./temp/quake_search.log','w+',encoding='utf8') as quake_log_write:
                                    quake_log_write.write(quake_res_log_new)
                                    self.notice_print.emit("<font color='#55ff00'>" + ">Quake日志清理完成" + "<font>")
                            else:
                                with open('./temp/quake_search.log','w',encoding='utf8') as quake_log_write:
                                    info[self.basic_qstr] = response_quake.json()
                                    quake_res_log = json.dumps(info,indent=3) 
                                    quake_log_write.write(quake_res_log)

                                self.notice_print.emit("<font color='#55ff00'>" + ">Quake日志存储完成" + "<font>")
        except Exception as e:
            self.text_print.emit("<font color='#ff0000'>" + ">Quake API错误" + "<font>")


class shodan_search_qthread(QThread):
    text_print = pyqtSignal(str)
    notice_print = pyqtSignal(str)
    count_print = pyqtSignal(str)
    res_print = pyqtSignal(str)

    def __init__(self,a,b,c,d,e,f):
        super(shodan_search_qthread,self).__init__()
        self.key = a
        self.qstr = b
        self.basic_qstr = c.strip()
        self.log_time = d
        self.start_flag = e
        self.size = f
    
    def run(self):
        if self.start_flag == False:
            self.text_print.emit("<font color='#ff0000'>" + ">Shodan已关闭" + "<font>")
        else:
            if os.path.getsize('./temp/shodan_search.log') > 0:
                with open('./temp/shodan_search.log','r',encoding='utf8') as shodan_log:
                    info = json.load(shodan_log)
            else:
                info = {}

            if self.basic_qstr in list(info.keys()):
                select_list = []
                t0 = time.time()
                histtory_search = info[self.basic_qstr]
                for i in histtory_search['matches']:
                    hostinfo = str(i['ip_str']) + ":" + str(i['port'])
                    select_list.append(hostinfo)
                    if i['_shodan']['module'] == 'http' :  
                        httpurl = '<a href=\"http://' + str(i['ip_str']) + ":" + str(i['port']) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(i['ip_str']) + ":" + str(i['port'])  + '</span></a>'                  
                        self.text_print.emit("<font color='#55ff00'>" + "Host: " + httpurl + "<font>")                    
                        self.text_print.emit("<font color='#55ff00'>" + "Title: " + str(i['http']['title']) + "<font>")
                        self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + str(i['_shodan']['module']) + "<font>")
                        self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                        self.res_print.emit("<font color='#55ff00'>" + '[+]' +httpurl+','+str(i['_shodan']['module'])+','+str(i['http']['title'])+ "<font>")
                    elif i['_shodan']['module'] == 'https' or i['_shodan']['module'] == 'https-simple-new':
                        httpurl = '<a href=\"https://' + str(i['ip_str']) + ":" + str(i['port']) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(i['ip_str']) + ":" + str(i['port'])  + '</span></a>'                  
                        self.text_print.emit("<font color='#55ff00'>" + "Host: " + httpurl + "<font>")
                        if 'http' not in i:
                            title = "Title: None"
                            self.text_print.emit("<font color='#55ff00'>" + "Title: " + 'None' + "<font>")
                        else: 
                            title = str(i['http']['title'])              
                            self.text_print.emit("<font color='#55ff00'>" + "Title: " + str(i['http']['title']) + "<font>")
                        self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + str(i['_shodan']['module']) + "<font>")
                        self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                        self.res_print.emit("<font color='#55ff00'>" + '[+]' +httpurl+','+str(i['_shodan']['module'])+','+title+ "<font>")
                    else:            
                        self.text_print.emit("<font color='#55ff00'>" + "Host: " + str(i['ip_str']) + ":" + str(i['port'])  + "<font>")
                        self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + str(i['_shodan']['module']) + "<font>")
                        self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                        self.res_print.emit("<font color='#55ff00'>" + '[+]'+str(i['ip_str']) + ":" + str(i['port'])+','+str(i['_shodan']['module']) + "<font>")
                self.notice_print.emit("<font color='#55ff00'>" + ">Shodan历史查询完成" + "<font>")
                self.count_print.emit("<font color='#55ff00'>" + "==================" + "<font>")
                self.count_print.emit("<font color='#55ff00'>" + ">Shodan当前资产:" + str(len(histtory_search['matches'])) + "<font>")
                self.count_print.emit("<font color='#55ff00'>" + ">Shodan重复资产:" + str(len(select_list)-len(list(set(select_list)))) + "<font>")
                self.count_print.emit("<font color='#55ff00'>" + ">Shodan总计资产:" + str(histtory_search['total']) +  "<font>")
                self.count_print.emit("<font color='#55ff00'>" + ">耗时:" + str(round(time.time() - t0,4)) + "秒"  + "<font>") 
                
            else:
                shodan_api = shodan.Shodan(self.key)
                select_list = []
                t0 = time.time()
                if 'app=' in self.basic_qstr:
                    self.text_print.emit("<font color='#ff0000'>" + ">Shodan不支持APP搜索" + "<font>")
                else:
                    try:
                        results = shodan_api.search(self.qstr)
                        shodan_res = {}
                        shodan_res[self.basic_qstr] = results
                        shodan_res_log_new = json.dumps(shodan_res,indent=3) 
                        if results['total'] == 0:
                            self.text_print.emit("<font color='#ff0000'>" + ">Shodan没有相关资产" + "<font>")
                        else:
                            for i in results['matches']:
                                hostinfo = str(i['ip_str']) + ":" + str(i['port'])
                                select_list.append(hostinfo)
                                if i['_shodan']['module'] == 'http' :  
                                    httpurl = '<a href=\"http://' + str(i['ip_str']) + ":" + str(i['port']) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(i['ip_str']) + ":" + str(i['port'])  + '</span></a>'                  
                                    self.text_print.emit("<font color='#55ff00'>" + "Host: " + httpurl + "<font>")                    
                                    self.text_print.emit("<font color='#55ff00'>" + "Title: " + str(i['http']['title']) + "<font>")
                                    self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + str(i['_shodan']['module']) + "<font>")
                                    self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                                    self.res_print.emit("<font color='#55ff00'>" + '[+]' +httpurl+','+str(i['_shodan']['module'])+','+str(i['http']['title'])+ "<font>")
                                elif i['_shodan']['module'] == 'https' or i['_shodan']['module'] == 'https-simple-new':
                                    httpurl = '<a href=\"https://' + str(i['ip_str']) + ":" + str(i['port']) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(i['ip_str']) + ":" + str(i['port'])  + '</span></a>'                  
                                    self.text_print.emit("<font color='#55ff00'>" + "Host: " + httpurl + "<font>")
                                    if 'http' not in i:
                                        title = "Title: None"
                                        self.text_print.emit("<font color='#55ff00'>" + "Title: " + 'None' + "<font>")
                                    else:   
                                        title = str(i['http']['title'])            
                                        self.text_print.emit("<font color='#55ff00'>" + "Title: " + str(i['http']['title']) + "<font>")
                                    self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + str(i['_shodan']['module']) + "<font>")
                                    self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                                    self.res_print.emit("<font color='#55ff00'>" + '[+]' +httpurl+','+str(i['_shodan']['module'])+','+title+ "<font>")
                                else:            
                                    self.text_print.emit("<font color='#55ff00'>" + "Host: " + str(i['ip_str']) + ":" + str(i['port'])  + "<font>")
                                    self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + str(i['_shodan']['module']) + "<font>")
                                    self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                                    self.res_print.emit("<font color='#55ff00'>" + '[+]'+str(i['ip_str']) + ":" + str(i['port'])+','+str(i['_shodan']['module']) + "<font>")
                            
                            self.notice_print.emit("<font color='#55ff00'>" + ">Shodan查询完成" + "<font>")
                            self.count_print.emit("<font color='#55ff00'>" + "==================" + "<font>")
                            self.count_print.emit("<font color='#55ff00'>" + ">Shodan当前资产:" + str(len(results['matches'])) + "<font>")
                            self.count_print.emit("<font color='#55ff00'>" + ">Shodan重复资产:" + str(len(select_list)-len(list(set(select_list)))) + "<font>")
                            self.count_print.emit("<font color='#55ff00'>" + ">Shodan总计资产:" + str(results['total']) +  "<font>")
                            self.count_print.emit("<font color='#55ff00'>" + ">耗时:" + str(round(time.time() - t0,4)) + "秒"  + "<font>")
                            if self.log_time > 5:
                                os.remove("./temp/shodan_search.log")
                                with open('./temp/shodan_search.log','w+',encoding='utf8') as shodan_log_write:
                                    shodan_log_write.write(shodan_res_log_new)
                                self.notice_print.emit("<font color='#55ff00'>" + ">Shodan日志清理完成" + "<font>")
                            else:
                                with open('./temp/shodan_search.log','w',encoding='utf8') as shodan_log_write:
                                    info[self.basic_qstr] = results
                                    shodan_res_log = json.dumps(info,indent=3) 
                                    shodan_log_write.write(shodan_res_log)
                                self.notice_print.emit("<font color='#55ff00'>" + ">Shoan日志存储完成" + "<font>")
                    except shodan.APIError as e:
                        self.text_print.emit("<font color='#ff0000'>" + ">Shodan API错误" + "<font>")



class censys_search_qthread(QThread):
    text_print = pyqtSignal(str)
    notice_print = pyqtSignal(str)
    count_print = pyqtSignal(str)
    res_print = pyqtSignal(str)

    def __init__(self,a,b,c,d,e,f,g,h):
        super(censys_search_qthread,self).__init__()
        self.uid = a
        self.secret = b
        self.qstr = c
        self.basic_qstr = d.strip()
        self.log_time = e
        self.size = int(int(h)/10)
        self.censys_str = {
            "query": self.qstr,
            "page":self.size,
            "fields":["ip","protocols","ports"]
        }
        self.api_url = "https://www.censys.io/api/v1"
        self.proxy_flag = f
        self.start_flag = g
        
    
    def run(self):
        if self.start_flag == False:
            self.text_print.emit("<font color='#ff0000'>" + ">Censys已关闭" + "<font>")
        else:
            if os.path.getsize('./temp/censys_search.log') > 0:
                try:
                    with open('./temp/censys_search.log','r',encoding='utf8') as censys_log:
                        info = json.load(censys_log)
                except Exception:
                    self.notice_print.emit("<font color='#ff0000'>" + ">Censys日志文件不存在" + "<font>")
            else:
                info = {}

            if self.basic_qstr in list(info.keys()):
                select_list = []
                t0 = time.time()
                histtory_search = info[self.basic_qstr]
                for i in histtory_search['results'][0]['protocols']:
                    info_ip = i.split('/')
                    hostinfo = str(histtory_search['results'][0]['ip']) + ":" + str(info_ip[0])
                    select_list.append(hostinfo)
                    if info_ip[1] == 'http' or info_ip[1] == 'https':
                        httpurl = '<a href=\"'+ info_ip[1] +'://' + str(histtory_search['results'][0]['ip']) + ":" + str(info_ip[0]) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(histtory_search['results'][0]['ip']) + ":" + str(info_ip[0])  + '</span></a>'
                        title_ip = 'None'
                        self.text_print.emit("<font color='#55ff00'>" + "Host: " + httpurl + "<font>")
                        self.text_print.emit("<font color='#55ff00'>" + "Title: " + title_ip + "<font>")
                        self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + str(info_ip[1]) + "<font>")
                        self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                        self.res_print.emit("<font color='#55ff00'>" + '[+]' + httpurl+','+str(info_ip[1]) +','+ title_ip + "<font>")
                    else:
                        self.text_print.emit("<font color='#55ff00'>" + "Host: " + str(histtory_search['results'][0]['ip']) + ":" + str(info_ip[0])  + "<font>")
                        self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + str(info_ip[1]) + "<font>")
                        self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                        self.res_print.emit("<font color='#55ff00'>" + '[+]'+str(histtory_search['results'][0]['ip']) + ":" + str(info_ip[0])+','+str(info_ip[1]) + "<font>")

                self.notice_print.emit("<font color='#55ff00'>" + ">Censys历史查询完成" + "<font>")
                self.count_print.emit("<font color='#55ff00'>" + "==================" + "<font>")
                self.count_print.emit("<font color='#55ff00'>" + ">Censys当前资产:" + str(len(histtory_search['results'][0]['protocols'])) + "<font>")
                self.count_print.emit("<font color='#55ff00'>" + ">Censys重复资产:" + str(len(select_list)-len(list(set(select_list)))) + "<font>")
                self.count_print.emit("<font color='#55ff00'>" + ">Censys总计资产:" + str(len(histtory_search['results'][0]['protocols'])) +  "<font>")
                self.count_print.emit("<font color='#55ff00'>" + ">耗时:" + str(round(time.time() - t0,4)) + "秒"  + "<font>")
                
            else:
                qstr_list = ["ip","ips","domain"]
                select_list = []
                t0 = time.time()
                if '++' in self.basic_qstr or '--' in self.basic_qstr or '^^' in self.basic_qstr:
                    self.text_print.emit("<font color='#ff0000'>" + ">Censys暂不支持多语法搜索"  + "<font>")
                else:

                    if self.basic_qstr.split('=')[0] in qstr_list:
                        # qstrb = re.findall('\d*\.\d*\.\d*\.\d*',self.qstr)[0]
                        try:
                            censys_res = requests.post(url="https://www.censys.io/api/v1/search/ipv4",data=json.dumps(self.censys_str),auth=(self.uid, self.secret))
                            if 'error_type' in censys_res.json().keys():
                                if censys_res.json()['error_type'] == 'unauthorized':
                                    self.text_print.emit("<font color='#ff0000'>" + ">Censys API 错误" + "<font>")
                                elif censys_res.json()['error_type'] == 'es_transport_error':
                                    self.text_print.emit("<font color='#ff0000'>" + ">没有资产信息" + "<font>")
                                else:
                                    self.text_print.emit("<font color='#ff0000'>" + ">Censys API 错误" + "<font>")
                            else:
                                
                                if len(censys_res.json()['results']) == 0:
                                    self.text_print.emit("<font color='#ff0000'>" + ">没有资产信息" + "<font>")
                                else:
                                    censys_res1 = {}
                                    censys_res1[self.basic_qstr] = censys_res.json()
                                    censys_res_log_new = json.dumps(censys_res1,indent=3) 
                                    for i in censys_res.json()['results'][0]['protocols']:
                                        info_ip = i.split('/')
                                        hostinfo = str(censys_res.json()['results'][0]['ip']) + ":" + str(info_ip[0])
                                        select_list.append(hostinfo)
                                        if info_ip[1] == 'http' or info_ip[1] == 'https':
                                            title_ip = 'None'
                                            httpurl = '<a href=\"'+ info_ip[1] +'://' + str(censys_res.json()['results'][0]['ip']) + ":" + str(info_ip[0]) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(censys_res.json()['results'][0]['ip']) + ":" + str(info_ip[0])  + '</span></a>'
                                            self.text_print.emit("<font color='#55ff00'>" + "Host: " + httpurl + "<font>")
                                            self.text_print.emit("<font color='#55ff00'>" + "Title: " + title_ip + "<font>")
                                            self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + str(info_ip[1]) + "<font>")
                                            self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                                            self.res_print.emit("<font color='#55ff00'>" +'[+]'+ httpurl +','+ str(info_ip[1]) +',' + title_ip+"<font>")
                                        else:
                                            self.text_print.emit("<font color='#55ff00'>" + "Host: " + str(censys_res.json()['results'][0]['ip']) + ":" + str(info_ip[0])  + "<font>")
                                            self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + str(info_ip[1]) + "<font>")
                                            self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                                            self.res_print.emit("<font color='#55ff00'>" + '[+]' + str(censys_res.json()['results'][0]['ip']) + ":" + str(info_ip[0]) +','+str(info_ip[1]) + "<font>")
                                    self.notice_print.emit("<font color='#55ff00'>" + ">Censys查询完成" + "<font>")
                                    self.count_print.emit("<font color='#55ff00'>" + "==================" + "<font>")
                                    self.count_print.emit("<font color='#55ff00'>" + ">Censys当前资产:" + str(len(censys_res.json()['results'][0]['protocols'])) + "<font>")
                                    self.count_print.emit("<font color='#55ff00'>" + ">Censys重复资产:" + str(len(select_list)-len(list(set(select_list)))) + "<font>")
                                    self.count_print.emit("<font color='#55ff00'>" + ">Censys总计资产:" + str(len(censys_res.json()['results'][0]['protocols'])) +  "<font>")
                                    self.count_print.emit("<font color='#55ff00'>" + ">耗时:" + str(round(time.time() - t0,4)) + "秒"  + "<font>")
                                    if self.log_time > 5:
                                        try:
                                            os.remove("./temp/censys_search.log")
                                            with open('./temp/censys_search.log','w+',encoding='utf8') as censys_log_write:
                                                censys_log_write.write(censys_res_log_new)
                                            self.notice_print.emit("<font color='#55ff00'>" + ">Censys日志清理完成" + "<font>")
                                        except Exception:
                                            self.notice_print.emit("<font color='#ff0000'>" + ">Censys日志文件不存在" + "<font>")
                                    else:
                                        try:
                                            with open('./temp/censys_search.log','w',encoding='utf8') as censys_log_write:
                                                info[self.basic_qstr] = censys_res.json()
                                                censys_res_log = json.dumps(info,indent=3) 
                                                censys_log_write.write(censys_res_log)
                                            self.notice_print.emit("<font color='#55ff00'>" + ">Censys日志存储完成" + "<font>")
                                        except Exception:
                                            self.notice_print.emit("<font color='#ff0000'>" + ">Censys日志文件不存在" + "<font>")
                        except Exception:
                            self.text_print.emit("<font color='#ff0000'>" + ">Censys连接超时"  + "<font>")
                        
                    else:
                        if "app=" in self.basic_qstr:
                            self.text_print.emit("<font color='#ff0000'>" + ">Censys不支持APP搜索"  + "<font>")
                        else:
                            self.text_print.emit("<font color='#ff0000'>" + ">Censys暂时只支持IP,IPS,DOAMIN"  + "<font>")
            

class binaryedge_search_qthread(QThread):
    text_print = pyqtSignal(str)
    notice_print = pyqtSignal(str)
    count_print = pyqtSignal(str)
    res_print = pyqtSignal(str)

    def __init__(self,a,b,c,d,e,f):
        super(binaryedge_search_qthread,self).__init__()
        self.header = {
            "X-Key": a
        }
        # self.qstr = b
        self.basic_qstr = b.strip()
        self.log_time = c        
        self.api_ip = "https://api.binaryedge.io/v2/query/ip/"
        self.api_domain = "https://api.binaryedge.io/v2/query/domains/subdomain/"
        self.proxy_flag =d
        self.start_flag = e
        self.size = f

    
    def run(self):
        if self.start_flag == False:
            self.text_print.emit("<font color='#ff0000'>" + ">Binaryedge已关闭" + "<font>")
        else:
            if os.path.getsize('./temp/binaryedge_search.log') > 0:
                try:
                    with open('./temp/binaryedge_search.log','r',encoding='utf8') as binaryedge_log:
                        info = json.load(binaryedge_log)
                except Exception:
                    self.notice_print.emit("<font color='#ff0000'>" + ">Binaryedge日志文件不存在" + "<font>")
            else:
                info = {}

            if self.basic_qstr in list(info.keys()):
                select_list = []
                t0 = time.time()
                histtory_search = info[self.basic_qstr]
                if 'ip=' in self.basic_qstr:
                    for i in histtory_search['events']:
                        target = i['results'][0]['target']['ip']
                        target_port = i['results'][0]['target']['port']
                        hostinfo = str(target) + ":" + str(target_port)
                        for j in i['results']:
                            if 'service' in j['result']['data'].keys():
                                protocol_ip = j['result']['data']['service']['name']
                                break

                        select_list.append(hostinfo)
                        if protocol_ip == 'http' or protocol_ip == 'ssl/http':
                            for t in i['results']:
                                if 'response' in t['result']['data'].keys():
                                    # title_ip = str(BeautifulSoup(t['result']['data']['response']['body']['content'],'html.parser').title.string)
                                    if t['result']['data']['response']['title'] == None:
                                        title_ip = 'None'
                                    else:
                                        title_ip = t['result']['data']['response']['title']
                                    break
                                elif 'service' in t['result']['data'].keys():
                                    # title_ip = str(BeautifulSoup(t['result']['data']['service']['banner'],'html.parser').title.string)
                                    if BeautifulSoup(t['result']['data']['service']['banner'],'html.parser').title == None:
                                        title_ip = 'None'   
                                    else:                                    
                                        title_ip = str(BeautifulSoup(t['result']['data']['service']['banner'],'html.parser').title.string)
                                    break


                            

                            httpurl = '<a href=\"'+ protocol_ip +'://' + str(target) + ":" + str(target_port) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(target) + ":" + str(target_port)  + '</span></a>'
                            self.text_print.emit("<font color='#55ff00'>" + "Host: " + httpurl + "<font>")
                            self.text_print.emit("<font color='#55ff00'>" + "Title: " + title_ip + "<font>")
                            self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + str(protocol_ip) + "<font>")
                            self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                            self.res_print.emit("<font color='#55ff00'>" + '[+]'+httpurl+','+str(protocol_ip)+','+title_ip + "<font>")
                        else:
                            self.text_print.emit("<font color='#55ff00'>" + "Host: " + str(hostinfo ) + "<font>")
                            self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + str(protocol_ip) + "<font>")
                            self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                            self.res_print.emit("<font color='#55ff00'>" + '[+]' + str(hostinfo )+','+  str(protocol_ip)+ "<font>")

                    self.notice_print.emit("<font color='#55ff00'>" + ">Binaryedge历史查询完成" + "<font>")
                    self.count_print.emit("<font color='#55ff00'>" + "==================" + "<font>")
                    self.count_print.emit("<font color='#55ff00'>" + ">Binaryedge当前资产:" + str(len(histtory_search['events'])) + "<font>")
                    self.count_print.emit("<font color='#55ff00'>" + ">Binaryedge重复资产:" + str(len(select_list)-len(list(set(select_list)))) + "<font>")
                    self.count_print.emit("<font color='#55ff00'>" + ">Binaryedge总计资产:" + str(histtory_search['total']) +  "<font>")
                    self.count_print.emit("<font color='#55ff00'>" + ">耗时:" + str(round(time.time() - t0,4)) + "秒"  + "<font>")
                    # self.text_print.emit('开始整理数据')
                elif 'domain=' in self.basic_qstr:
                    for i in histtory_search['events']:
                        httpurl = '<a href=\"https://' + str(i) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(i) + '</span></a>'
                        self.text_print.emit("<font color='#55ff00'>" + "Host: " + str(i) + "<font>")
                        self.text_print.emit("<font color='#55ff00'>" + "Protocol: domain"  + "<font>")
                        # self.text_print.emit("<font color='#55ff00'>" + "Title: None" + "<font>")
                        self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                        select_list.append(i)
                        self.res_print.emit("<font color='#55ff00'>" + '[+]' + httpurl +','+  "https"+ ','+"None"+"<font>")
                    self.notice_print.emit("<font color='#55ff00'>" + ">Binaryedge历史查询完成" + "<font>")
                    self.count_print.emit("<font color='#55ff00'>" + "==================" + "<font>")
                    self.count_print.emit("<font color='#55ff00'>" + ">Binaryedge当前资产:" + str(len(histtory_search['events'])) + "<font>")
                    self.count_print.emit("<font color='#55ff00'>" + ">Binaryedge重复资产:" + str(len(select_list)-len(list(set(select_list)))) + "<font>")
                    self.count_print.emit("<font color='#55ff00'>" + ">Binaryedge总计资产:" + str(histtory_search['total']) +  "<font>")
                    self.count_print.emit("<font color='#55ff00'>" + ">耗时:" + str(round(time.time() - t0,4)) + "秒"  + "<font>")
                    # self.text_print.emit('开始整理数据')

                
            else:
                select_list = []
                t0 = time.time()
                if '++' in self.basic_qstr or '--' in self.basic_qstr or '^^' in self.basic_qstr:
                    self.text_print.emit("<font color='#ff0000'>" + ">Binaryedge暂不支持多语法搜索"  + "<font>")
                    # self.text_print.emit('开始整理数据')
                else:
                    if 'ip=' in self.basic_qstr:
                        qstrb = self.basic_qstr.split('=')[-1]
                        # qstrb = re.findall('\d*\.\d*\.\d*\.\d*',self.basic_qstr)[0]
                        try:
                            binaryedge_res = requests.get(self.api_ip + qstrb,headers=self.header)
                            if len(binaryedge_res.json().keys()) <=3:
                                if 'token'in binaryedge_res.json()['message']:
                                    self.text_print.emit("<font color='#ff0000'>" + ">Binaryedge api错误" + "<font>")
                                    # self.text_print.emit('开始整理数据')
                                elif 'plan'in binaryedge_res.json()['message']:
                                    self.text_print.emit("<font color='#ff0000'>" + ">Binaryedge 账号套餐不支持" + "<font>")
                                    # self.text_print.emit('开始整理数据')
                                else:
                                    self.text_print.emit("<font color='#ff0000'>" + ">Binaryedge 语法不正确或者没有相关资产" + "<font>")
                                    # self.text_print.emit('开始整理数据')
                                
                            else:
                                if binaryedge_res.json()['total'] == 0:
                                    self.text_print.emit("<font color='#ff0000'>" + ">Binaryedge没有相关资产" + "<font>")
                                    # self.text_print.emit('开始整理数据')
                                else:
                                    binaryedge_res1 = {}
                                    binaryedge_res1[self.basic_qstr] = binaryedge_res.json()
                                    binaryedge_res_log_new = json.dumps(binaryedge_res1,indent=3)
                                    for i in binaryedge_res.json()['events']:
                                        target = i['results'][0]['target']['ip']
                                        target_port = i['results'][0]['target']['port']
                                        hostinfo = str(target) + ":" + str(target_port)

                                        for j in i['results']:
                                            if 'service' in j['result']['data'].keys():
                                                protocol_ip = j['result']['data']['service']['name']
                                                break

                                        
                                        
                                        select_list.append(hostinfo)
                                        if protocol_ip == 'http' or protocol_ip == 'ssl/http':
                                            for t in i['results']:
                                                if 'response' in t['result']['data'].keys():
                                                    # title_ip = str(BeautifulSoup(t['result']['data']['response']['body']['content'],'html.parser').title.string)
                                                    if t['result']['data']['response']['title'] == None:
                                                        title_ip = 'None'
                                                    else:
                                                        title_ip = t['result']['data']['response']['title']
                                                    break
                                                elif 'service' in t['result']['data'].keys():
                                                    if BeautifulSoup(t['result']['data']['service']['banner'],'html.parser').title == None:
                                                        title_ip = 'None'   
                                                    else:                                    
                                                        title_ip = str(BeautifulSoup(t['result']['data']['service']['banner'],'html.parser').title.string)
                                                    break
                                        
                                            httpurl = '<a href=\"'+ protocol_ip +'://' + str(target) + ":" + str(target_port) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(target) + ":" + str(target_port)  + '</span></a>'
                                            self.text_print.emit("<font color='#55ff00'>" + "Host: " + httpurl + "<font>")
                                            self.text_print.emit("<font color='#55ff00'>" + "Title: " + title_ip + "<font>")
                                            self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + str(protocol_ip) + "<font>")
                                            self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                                            self.res_print.emit("<font color='#55ff00'>" + '[+]'+httpurl+','+ str(protocol_ip) +','+title_ip + "<font>")
                                        else:
                                            self.text_print.emit("<font color='#55ff00'>" + "Host: " + str(hostinfo ) + "<font>")
                                            self.text_print.emit("<font color='#55ff00'>" + "Protocol: " + str(protocol_ip) + "<font>")
                                            self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                                            self.res_print.emit("<font color='#55ff00'>" + '[+]'+str(hostinfo )+','+str(protocol_ip) + "<font>")

                                    self.notice_print.emit("<font color='#55ff00'>" + ">Binaryedge查询完成" + "<font>")
                                    self.count_print.emit("<font color='#55ff00'>" + "==================" + "<font>")
                                    self.count_print.emit("<font color='#55ff00'>" + ">Binaryedge当前资产:" + str(len(binaryedge_res.json()['events'])) + "<font>")
                                    self.count_print.emit("<font color='#55ff00'>" + ">Binaryedge重复资产:" + str(len(select_list)-len(list(set(select_list)))) + "<font>")
                                    self.count_print.emit("<font color='#55ff00'>" + ">Binaryedge总计资产:" + str(binaryedge_res.json()['total']) +  "<font>")
                                    self.count_print.emit("<font color='#55ff00'>" + ">耗时:" + str(round(time.time() - t0,4)) + "秒"  + "<font>")
                                    # self.text_print.emit('开始整理数据')
                                    if self.log_time > 5:
                                        try:
                                            with open('./temp/binaryedge_search.log','w+',encoding='utf8') as binaryedge_log_write:
                                                binaryedge_log_write.write(binaryedge_res_log_new)
                                            self.notice_print.emit("<font color='#55ff00'>" + ">Binaryedge日志清理完成" + "<font>")
                                        except Exception:
                                            self.notice_print.emit("<font color='#ff0000'>" + ">Binaryedge日志文件不存在" + "<font>")
                                    else:
                                        try:
                                            with open('./temp/binaryedge_search.log','w',encoding='utf8') as binaryedge_log_write:
                                                info[self.basic_qstr] = binaryedge_res.json()
                                                binaryedge_res_log = json.dumps(info,indent=3) 
                                                binaryedge_log_write.write(binaryedge_res_log)
                                            self.notice_print.emit("<font color='#55ff00'>" + ">Binaryedge日志存储完成" + "<font>")
                                        except Exception:
                                            self.notice_print.emit("<font color='#ff0000'>" + ">Binaryedge日志文件不存在" + "<font>")
                        except Exception:
                            self.text_print.emit("<font color='#ff0000'>" + ">Binaryedge连接超时"  + "<font>")
                            # self.text_print.emit('开始整理数据')
                        
                    elif 'domain=' in self.basic_qstr:
                        qstrb = self.basic_qstr.split('=')[-1]
                        try:
                            binaryedge_res = requests.get(self.api_domain + qstrb,headers=self.header)
                            if len(binaryedge_res.json().keys()) <=3:
                                if 'token'in binaryedge_res.json()['message']:
                                    self.text_print.emit("<font color='#ff0000'>" + ">Binaryedge api错误" + "<font>")
                                    # self.text_print.emit('开始整理数据')
                                elif 'plan'in binaryedge_res.json()['message']:
                                    self.text_print.emit("<font color='#ff0000'>" + ">Binaryedge 账号套餐不支持" + "<font>")
                                    # self.text_print.emit('开始整理数据')
                                elif 'Bad domain'in binaryedge_res.json()['message']:
                                    self.text_print.emit("<font color='#ff0000'>" + ">Binaryedge 域名没有相关结果" + "<font>")
                                    # self.text_print.emit('开始整理数据')
                                else:
                                    self.text_print.emit("<font color='#ff0000'>" + binaryedge_res.json() + "<font>")
                                    # self.text_print.emit('开始整理数据')
                            else:
                                binaryedge_res1 = {}
                                binaryedge_res1[self.basic_qstr] = binaryedge_res.json()
                                binaryedge_res_log_new = json.dumps(binaryedge_res1,indent=3)
                                for i in binaryedge_res.json()['events']:                            
                                    self.text_print.emit("<font color='#55ff00'>" + "Host: " + str(i) + "<font>")
                                    self.text_print.emit("<font color='#55ff00'>" + "Protocol: domain" + "<font>")
                                    self.text_print.emit("<font color='#55ff00'>" + "Title: None" + "<font>")
                                    self.text_print.emit("<font color='#55ff00'>" + '==========================' + "<font>")
                                    self.res_print.emit("<font color='#55ff00'>" + '[+]'+str(i)+ ',' +'https' +','+ 'None' + "<font>")
                                    select_list.append(i)

                                self.notice_print.emit("<font color='#55ff00'>" + ">Binaryedge查询完成" + "<font>")
                                self.count_print.emit("<font color='#55ff00'>" + "==================" + "<font>")
                                self.count_print.emit("<font color='#55ff00'>" + ">Binaryedge当前资产:" + str(len(binaryedge_res.json()['events'])) + "<font>")
                                self.count_print.emit("<font color='#55ff00'>" + ">Binaryedge重复资产:" + str(len(select_list)-len(list(set(select_list)))) + "<font>")
                                self.count_print.emit("<font color='#55ff00'>" + ">Binaryedge总计资产:" + str(binaryedge_res.json()['total']) +  "<font>")
                                self.count_print.emit("<font color='#55ff00'>" + ">耗时:" + str(round(time.time() - t0,4)) + "秒"  + "<font>")
                                # self.text_print.emit('开始整理数据')
                                if self.log_time > 5:
                                    try:
                                        os.remove('./temp/binaryedge_search.log')
                                        with open('./temp/binaryedge_search.log','w+',encoding='utf8') as binaryedge_log_write:
                                            binaryedge_log_write.write(binaryedge_res_log_new)
                                        self.notice_print.emit("<font color='#55ff00'>" + ">Binaryedge日志清理完成" + "<font>")
                                    except Exception:
                                        self.notice_print.emit("<font color='#ff0000'>" + ">Binaryedge日志文件不存在" + "<font>")
                                else:
                                    try:
                                        with open('./temp/binaryedge_search.log','w',encoding='utf8') as binaryedge_log_write:
                                            info[self.basic_qstr] = binaryedge_res.json()
                                            binaryedge_res_log = json.dumps(info,indent=3) 
                                            binaryedge_log_write.write(binaryedge_res_log)
                                        self.notice_print.emit("<font color='#55ff00'>" + ">Binaryedge日志存储完成" + "<font>")
                                    except Exception:
                                        self.notice_print.emit("<font color='#ff0000'>" + ">Binaryedge日志文件不存在" + "<font>")
                        except Exception:
                            self.text_print.emit("<font color='#ff0000'>" + ">Binaryedge连接超时"  + "<font>")
                            # self.text_print.emit('开始整理数据')
                        



                    else:
                        self.text_print.emit("<font color='#ff0000'>" + ">Binaryedge暂不支持此扫描"  + "<font>")
                        # self.text_print.emit('开始整理数据')

            
class rapiddns_search_qthread(QThread):
    text_print = pyqtSignal(str)
    notice_print = pyqtSignal(str)
    count_print = pyqtSignal(str)
    res_print = pyqtSignal(str)

    def __init__(self,a,b,c,d,e):
        super(rapiddns_search_qthread,self).__init__()
        self.basic_qstr = a.strip()
        self.log_time = b        
        self.proxy_flag = c
        self.headers = {                     
                        "User-Agent": random.choice(USER_AGENTS),
        }
        self.start_flag = d
        self.size = e
    
    def run(self):
        if self.start_flag ==False:
            pass
        else:
            if os.path.getsize('./temp/rapiddns_search.log') > 0:
                try:
                    with open('./temp/rapiddns_search.log','r',encoding='utf8') as rapiddns_search_1:
                        info = json.load(rapiddns_search_1)
                except Exception:
                    pass
            else:
                info = {}
            

            if self.basic_qstr in list(info.keys()):
                histtory_search = info[self.basic_qstr]
                for i in histtory_search['data']:
                    httpurl = '<a href=\"http://' + str(i['name']) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(i['name'])  + '</span></a>'
                    self.text_print.emit("<font color='#55ff00'>" + "[+]"+ httpurl +','+ 'http' +',' +'title: None'+ "<font>")
                self.notice_print.emit("<font color='#55ff00'>" + ">Rapiddns历史查询完成" + "<font>")
                self.count_print.emit('开始整理数据')

            else:
                if "ip=" in self.basic_qstr:
                    try:
                        ip_name = requests.get(url='https://rapiddns.io/api/v1/'+ self.basic_qstr.split('=')[1] +'?size='+self.size+'&page=1&t=1',headers=self.headers)
                        if ip_name.json()['total'] == 0:
                            self.count_print.emit('开始整理数据')
                            pass
                        else:
                            rapiddns_res = {}
                            rapiddns_res[self.basic_qstr] = ip_name.json()
                            rapiddns_res_log_new = json.dumps(rapiddns_res,indent=3)
                            for i in ip_name.json()['data']:
                                httpurl = '<a href=\"http://' + str(i['name']) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(i['name'])  + '</span></a>'
                                self.text_print.emit("<font color='#55ff00'>" + "[+]"+ httpurl +','+ 'http' +',' +'title: None'+ "<font>")
                            
                            self.notice_print.emit("<font color='#55ff00'>" + ">Rapiddns查询完成" + "<font>")
                            self.count_print.emit('开始整理数据')

                            if self.log_time > 30:
                                try:
                                    os.remove('./temp/rapiddns_search.log')
                                    with open('./temp/rapiddns_search.log','w+',encoding='utf8') as rapiddns_log_write:
                                        rapiddns_log_write.write(rapiddns_res_log_new)
                                    self.notice_print.emit("<font color='#55ff00'>" + ">Rapiddns日志清除完成" + "<font>")
                                except Exception:
                                    pass
                            else:
                                try:
                                    with open('./temp/rapiddns_search.log','w',encoding='utf8') as rapiddns_log_write:
                                        info[self.basic_qstr] = ip_name.json()
                                        rapiddns_res_log = json.dumps(info,indent=3) 
                                        rapiddns_log_write.write(rapiddns_res_log)
                                    self.notice_print.emit("<font color='#55ff00'>" + ">Rapiddns日志存储完成" + "<font>")
                                except Exception:
                                    pass
                            
                    except Exception:
                        self.count_print.emit('开始整理数据')
                        pass
                elif "ips=" in self.basic_qstr:
                    try:
                        ip_name = requests.get(url='https://rapiddns.io/api/v1/'+ self.basic_qstr.split('=')[1] +'?size='+self.size+'&page=1&t=1',headers=self.headers)
                        if ip_name.json()['total'] == 0:
                            self.count_print.emit('开始整理数据')
                            pass
                        else:
                            rapiddns_res = {}
                            rapiddns_res[self.basic_qstr] = ip_name.json()
                            rapiddns_res_log_new = json.dumps(rapiddns_res,indent=3)
                            for i in ip_name.json()['data']:
                                httpurl = '<a href=\"http://' + str(i['name']) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(i['name'])  + '</span></a>'
                                self.text_print.emit("<font color='#55ff00'>" + "[+]"+ i['name'] +','+ 'http' +',' +'title: None'+ "<font>")
                            self.notice_print.emit("<font color='#55ff00'>" + ">Rapiddns查询完成" + "<font>")
                            self.count_print.emit('开始整理数据')
                            if self.log_time > 30:
                                try:
                                    os.remove('./temp/rapiddns_search.log')
                                    with open('./temp/rapiddns_search.log','w+',encoding='utf8') as rapiddns_log_write:
                                        rapiddns_log_write.write(rapiddns_res_log_new)
                                    self.notice_print.emit("<font color='#55ff00'>" + ">Rapiddns日志清除完成" + "<font>")
                                except Exception:
                                    pass
                            else:
                                try:
                                    with open('./temp/rapiddns_search.log','w',encoding='utf8') as rapiddns_log_write:
                                        info[self.basic_qstr] = ip_name.json()
                                        rapiddns_res_log = json.dumps(info,indent=3) 
                                        rapiddns_log_write.write(rapiddns_res_log)
                                    self.notice_print.emit("<font color='#55ff00'>" + ">Rapiddns日志存储完成" + "<font>")
                                except Exception:
                                    pass
                    except Exception:
                        self.count_print.emit('开始整理数据')
                        pass
                elif "domain=" in self.basic_qstr:
                    try:                   
                        ip_name = requests.get(url='https://rapiddns.io/api/v1/'+ self.basic_qstr.split('=')[1] +'?size='+self.size+'&page=1&t=0',headers=self.headers)
                        if ip_name.json()['total'] == 0:
                            self.count_print.emit('开始整理数据')
                            pass
                        else:
                            rapiddns_res = {}
                            rapiddns_res[self.basic_qstr] = ip_name.json()
                            rapiddns_res_log_new = json.dumps(rapiddns_res,indent=3)
                            for i in ip_name.json()['data']:
                                httpurl = '<a href=\"http://' + str(i['name']) + '\"><span style=\" text-decoration: underline; color:#55ff00;\">' + str(i['name'])  + '</span></a>'
                                self.text_print.emit("<font color='#55ff00'>" + "[+]"+ i['name'] +','+ 'http' +',' +'title: None'+ "<font>")
                            self.notice_print.emit("<font color='#55ff00'>" + ">Rapiddns查询完成" + "<font>")
                            self.count_print.emit('开始整理数据')
                            if self.log_time > 30:
                                try:
                                    os.remove('./temp/rapiddns_search.log')
                                    with open('./temp/rapiddns_search.log','w+',encoding='utf8') as rapiddns_log_write:
                                        rapiddns_log_write.write(rapiddns_res_log_new)
                                    self.notice_print.emit("<font color='#55ff00'>" + ">Rapiddns日志清除完成" + "<font>")
                                except Exception:
                                    pass
                            else:
                                try:
                                    with open('./temp/rapiddns_search.log','w',encoding='utf8') as rapiddns_log_write:
                                        info[self.basic_qstr] = ip_name.json()
                                        rapiddns_res_log = json.dumps(info,indent=3) 
                                        rapiddns_log_write.write(rapiddns_res_log)
                                    self.notice_print.emit("<font color='#55ff00'>" + ">Rapiddns日志存储完成" + "<font>")
                                except Exception:
                                    pass
                    except Exception:
                        self.count_print.emit('开始整理数据')
                        pass
                else:
                    self.count_print.emit('开始整理数据')
                    pass


    

class get_proxy_list(QThread):
    text_print = pyqtSignal(str)
    notice_print = pyqtSignal(str)
    count_print = pyqtSignal(str)

    def __init__(self,a,b):
        super(get_proxy_list,self).__init__()
        self.email = a
        self.key = b
        self.headers = {                     
                        "User-Agent": random.choice(USER_AGENTS),
        }
        
    
    def run(self):
        proxy_ctime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(os.stat("./temp/proxylist").st_ctime))
        proxyunalive_ctime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(os.stat("./temp/proxylist_unalive").st_ctime))
        proxy_ntime = datetime.datetime.now()
        proxy_file_creat_time = (parse(str(proxy_ntime)) - parse(proxy_ctime)).days
        proxy_file_unalive_creat_time = (parse(str(proxy_ntime)) - parse(proxyunalive_ctime)).days
        if proxy_file_creat_time > 1:
            os.remove("./temp/proxylist")
            with open("./temp/proxylist",'w+',encoding='utf8') as f:
                f.write('')
        else:
            pass

        if proxy_file_unalive_creat_time > 2:
            os.remove("./temp/proxylist_unalive")
            with open("./temp/proxylist_unalive",'w+',encoding='utf8') as f:
                f.write('')
        else:
            pass

        try:
            fatezero_proxy = requests.get(url='http://proxylist.fatezero.org/proxy.list',headers=self.headers)
        except Exception:
            self.text_print.emit("<font color='#ff0000'>" + ">代理请求失败" + "<font>")
        proxy_untest=[]
        with open("./temp/proxylist_unalive" ,'r',encoding='utf8') as f:
            for i in f.readlines():
                proxy_untest.append(i.strip())

        if fatezero_proxy.status_code == 200:
            fatezero_list =fatezero_proxy.text.split('\n')
            fatezero_list_ip = []

            for fatezero_str in fatezero_list:
                if fatezero_str:
                    fatezero_json = json.loads(fatezero_str)
                    host = fatezero_json['host']
                    port = fatezero_json['port']
                    types = fatezero_json['type']
                    fatezero_list_ip.append([types, host, port])

            fatezero_list_ip_alive = []
            self.text_print.emit("<font color='#55ff00'>" + ">正在请求新代理.." + "<font>")
            for proxy_ip in fatezero_list_ip:
                # print(proxy_ip[0],proxy_ip[1],proxy_ip[2])
                log_proxy_ip = str(proxy_ip[0]) +","+ str(proxy_ip[1]) +","+ str(proxy_ip[2])
                if log_proxy_ip not in proxy_untest:
                    if proxy_ip[0] == 'https':
                        try:
                            fatezero_alive = requests.get(url="https://myip.ipip.net",proxies={proxy_ip[0]: "{0}://{1}:{2}".format(proxy_ip[0],proxy_ip[1],proxy_ip[2])},timeout=5)                        
                            if proxy_ip[1] in fatezero_alive.text:
                                self.text_print.emit("<font color='#55ff00'>" + ">发现存活代理：" + "<font>")
                                self.text_print.emit("<font color='#55ff00'>" + "[+]" + str(proxy_ip[0])+ " " +str(proxy_ip[1]) +":"+ str(proxy_ip[2]) + "<font>")
                                fatezero_list_ip_alive.append(proxy_ip)
                                with open("./temp/proxylist" ,'a',encoding='utf8') as f:
                                    f.write(log_proxy_ip)
                                    f.write('\n')
                            else:
                                
                                with open("./temp/proxylist_unalive" , 'a' ,encoding="utf8") as f:
                                    f.write(log_proxy_ip)
                                    f.write('\n')
                        except Exception as e:
                            erro = e

                        
                    elif proxy_ip[0] == 'http':
                        try:
                            fatezero_alive_http = requests.get(url="http://myip.ipip.net",proxies={proxy_ip[0]: "{0}://{1}:{2}".format(proxy_ip[0],proxy_ip[1],proxy_ip[2])},timeout=5)
                            if proxy_ip[1] in fatezero_alive_http.text:
                                self.text_print.emit("<font color='#55ff00'>" + ">发现存活代理：" + "<font>")
                                self.text_print.emit("<font color='#55ff00'>" + "[+]" + str(proxy_ip[0])+ " " + str(proxy_ip[1]) +":"+ str(proxy_ip[2]) + "<font>")
                                fatezero_list_ip_alive.append(proxy_ip)
                                with open("./temp/proxylist" ,'a',encoding='utf8') as f:
                                    f.write(log_proxy_ip)
                                    f.write('\n')
                            else:
                                
                                with open("./temp/proxylist_unalive" , 'a' ,encoding="utf8") as f:
                                    f.write(log_proxy_ip)
                                    f.write('\n')
                        except Exception as e:
                            erro = e
                    
                    else:
                        pass
                else:
                    pass

            self.text_print.emit("<font color='#55ff00'>" + ">代理获取完成：" + str(proxy_ip[1]) +":"+ str(proxy_ip[2]) + "<font>")
            self.text_print.emit("<font color='#55ff00'>" + ">共获取：" + str(len(fatezero_list_ip_alive)) + "条" + "高质量代理"+ "<font>")
        else:
            api_url = 'https://fofa.so/api/v1/search/all?email='+ self.email +'&key='+ self.key +'&fields=hostinfo&size=10&page=1&qbase64=Ym9keT0iZ2V0IGFsbCBwcm94eSBmcm9tIHByb3h5IHBvb2wi'
            
            try:
                fofa_res = requests.get(url=api_url,headers=self.headers).json()['results']        
                for i in fofa_res:
                    proxy_pool_hosts = []
                    try:
                        proxy_pool = requests.get(url='http://'+ i +'/get_all',headers=self.headers)
                        for j in proxy_pool.json():
                            retry_count = 3
                            types = 'http'
                            host = j['proxy'].split(':')[0]
                            port =  j['proxy'].split(':')[1]

                            while retry_count > 0:   
                                try:
                                    pool_alive_http = requests.get(url="http://myip.ipip.net",proxies={types: "{0}://{1}:{2}".format(types,host,port)})
                                    break                                        
                                except Exception:
                                    retry_count -= 1

                            if host in pool_alive_http.text:
                                proxyinfo = types+","+host+","+port
                                with open("./temp/proxylist",'a',encoding='utf8') as f:
                                    f.write(proxyinfo)
                            else:
                                del_proxy =requests.get("http://"+ i +"/delete/?proxy={}".format(j['proxy']))
                    
                    except Exception:
                        pass
            except Exception:
                self.text_print.emit("<font color='#ff0000'>" + ">Fofa请求失败" + "<font>")

        

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    myshow = MyWindow()
    myshow.setWindowRole
    myshow.setWindowIcon(QIcon(':/favicon.ico'))
    myshow.show()
    sys.exit(app.exec_())