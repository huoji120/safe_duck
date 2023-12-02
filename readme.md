### 安全鸭 
一款linux下的安全产品目的是满足个人安全需求,基于netfilter 

### 测试
目前只测试了Ubuntu和debian,其他系统没有测试,debbian的内核版本是4.19.0-17-amd64,Ubuntu的内核版本是5.4.0-80-generic,其他版本没有测试,如果你的系统内核版本不是这两个版本,那么请自行测试,如果有问题请提交issue,我会尽快修复.

### 功能
- [x] 1.防火墙
    - [x] 1.SYN扫描保护
    - [x] 2.SSH登录爆破防护
    - [x] 3.本地日志记录
    - [x] 4.端口爆破防护
    - [] 5.Web CC攻击防护
    - [] 6.自定义规则
- [] 2.入侵检测
    - [] 1.文件监控
    - [] 2.进程监控
    - [] 3.端口监控
    - [] 4.日志监控
    - [] 5.自定义规则
- [] 3.服务器控制
    - [x] 1.数据可视化
    - [] 2.服务器管理
    - [] 3.IOC查询
    - [] 4.自定义规则

### 开发计划
暂时没有开发计划,因为目前暂时满足我的需求了,等我哪天无聊或者失业了要找工作才会继续深入他.但是你可以贡献这个项目,我希望有人帮忙来写服务端,我虽然写了一部分但是考虑到协议对接之类的太麻烦了太累了所以也就写了一些.

### 安装
直接 
```bash
cd linux_kernel
make
然后sudo insmod safe_duck.ko即可完成内核模块的安装
```
如果你想卸载内核模块,那么就
```bash
sudo rmmod safe_duck.ko
```
不出意外就出现了safe_duck.ko文件,如果提示需要安装内核头文件,那么就安装内核头文件,然后再make一次就好了. 
阿里云的机器的内核头文件在 
https://snapshot.debian.org/package/linux/ 
比如我的
https://snapshot.debian.org/package/linux/4.19.194-1/#linux-headers-4.19.0-17-amd64_4.19.194-1 
https://snapshot.debian.org/package/linux/4.19.194-1/#linux-headers-4.19.0-17-common_4.19.194-1 

r3模块负责日志记录,编译
```bash
cd linux_service
cmake .
make
```
### 使用 
目前版本很粗糙,装好后就自动开启防护,目前只有SYN和SSH端口爆破防护,因为太懒了懒得动了.

### 学分 
如果你想跟我一起完善这个项目或者对继续开发这个项目有兴趣请联系我: 
https://key08.com/
