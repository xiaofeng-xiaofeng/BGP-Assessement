# BGP网络脆弱性评估系统   

> 版本：1.0  

> 发布日期：2015-07-02

> 软件作者：李国磊

> 邮箱地址：liglniuniu@gmail.com

##软件说明：
BGP网络脆弱性评估系统是基于对网络中的BGP路由器的发现、测量，进而以BGP路由器的角度对网络的整体安全进行评估和分析的工具。该软件主要分为三个步骤：BGP路由器的发现、BGP路由器的测量和BGP路由器的评估。为了减轻由于网络或电源等故障导致程序运行中断所造成的损失，这里将程序分为了多个步骤。一旦程序在某个步骤中断，即可从该步骤重新进行，不需要再次从头开始运行。

##软件运行要求：

1. Ubuntu 64bit系统（版本为12.04或以上）
2. python（版本2.7或以上）
3. Mongodb						下载地址：https://www.mongodb.org/
4. Pymongo						下载地址：https://pypi.python.org/pypi/pymongo/#downloads
5. zmap						下载地址：https://zmap.io/download.html
6. nmap						下载地址：http://nmap.org/download.html
7. iffinder（版本138或以上）		下载地址：http://www.caida.org/tools/measurement/iffinder/download/iffinder-1.38.tar.gz
8. basemap模块（该模块的依赖模块较多，主要有：matplotlib、numpy、GEOS、PROJ4、PIL、ipaddr和geoip等模块），该模块用于绘制IP地址地理位置分布示意图。如果没有安装或安装有误，将无法生成IP地址地理位置分布示意图。（版本1.0.7或以上）。下载地址：https://downloads.sourceforge.net/project/matplotlib/matplotlib-toolkits/basemap-1.0.7/basemap-1.0.7.tar.gz
9. python-cymru-services（该模块的依赖模块有：py2-ipaddress、adns和python-adns），该模块主要用于程序IP地址的ASN查询。如果没有安装或安装有误，当未在数据库中查找到给定IP地址的ASN时，无法给出与其同一AS内的BGP路由器接口地址。下载地址：https://pypi.python.org/pypi/py2-ipaddress
10. django						下载地址：https://www.djangoproject.com/
11. 150GB以上的硬盘空间


##系统软件安装说明：
系统采用的编程语言为`python`，只需将文件从压缩包内提取至某一文件夹内即可。需要说明的是：在下载并编译`iffinder`软件之后，需要将编译所生成的iffinder文件拷贝至系统所在的文件夹内。

`python`画图工具模块`basemap`及其依赖模块安装过程中容易出错，在这里提供一些安装说明，仅供参考：
1. matplotlib的安装，要求版本不低于1.0.0

	`sudo apt-get install python-matplotlib`
	
2. python的安装，要求版本不低于2.4

	`sudo apt-get install python`
	
3. numpy的安装，要求版本不低于1.2.1

  ```
	sudo apt-get install python-dev
	sudo python setup.py install
	```
	
4. `GEOS（Geometry Engine - Open Source）`的安装，要求版本不低于3.1.1

  ```
	cd geos-3.3.3
	export GEOS_DIR=<where you want the libs and headers to go>
	# A reasonable choice on a Unix-like system is /usr/local, or
	# if you don't have permission to write there, your home directory.
	export GEOS_DIR=/usr/local/lib
	./configure --prefix=$GEOS_DIR
	make; make install
	```
	
	在安装的时候有一点问题：
	提示出现下述问题：`../../libtool: line 990: g++: command not found`
	应对方法：安装	`libgtk2.0-dev ` ，然后 `make  clean`， 最后 `sudo make install`
	
5. PROJ4（Cartographic Projections Library）的安装
  
  ```
	./configure
	make
	make check
	sudo make install
	```
	
6. PIL（Python Imaging Library）的安装
  

	`python setup.py install`

	
7. basemap的安装

	`python setup.py install`
	
	有可能会提示未安装GEOS，这是因为未发现GEOS_DIR这个环境变量的缘故，在setup.py文件的第30行，可以将GEOS_DIR的值手动填写进去。
	如：GEOS_dir="/usr/local/lib"	这里假定第4步设定的GEOS_DIR=/usr/local/lib
	
8. ipaddr的安装

	`python setup.py install`
	
9. geoip的安装

	`python setup.py install`



##系统软件使用说明：

```
Usage: main.py  [options] arg
Options:
  -h,	--help						show this help message and exit
  -i	INTERFACE_NAME			Specify network interface for scanning
  -B	BANDWIDTH					Set send rate in bits/second (supports suffixes G, M,and K)
  -p	DESTINATION_PORT			TCP port for SYN scan
  -n	Times_of_probing				Number of probes to send to each IP (default=`1')
  --port-scan						Scan ip in ipfile and  insert proper ip into database!
  --asn-lookup					Lookup ASN for ip in ipfile and insert ASN into database!
  --geo-lookup					Lookup geo_info for ip in ipfile and insert geo_info into database!
  --os-detect						Detect the os fingerprint and insert os fingerprint into database!
  --alias-resolution-iffinder			Do alias resolution  for ip in ipfile with iffinder and insert alias-resolution-result into database!
  --insert-ip						Just insert and update ip in database!
  --insert-port						Just insert and update open port in database!
  --insert-os-fingerprint			Just insert and update os type and device type in database!
  --insert-iffinder-alias-result		Just insert and update result of iffinder alias resolution in database!
  --update-statistics-collection		Update the statistics collection of database!  It doesn't need any argument!
```

系统提供的这些参数，依据各自的用途可分为四类：

  * 系统扫描参数（如-i、-B、-p、-n，这些参数用于指定进行网络扫描时的网络接口、扫描带宽、扫描的TCP端口和每个IP地址的扫描次数）
  * 系统运行步骤（系统共可分为一下几个步骤：port-scan、asn-lookup、geo-lookup、os-detect和alias-resolution-iffinder，一旦系统在执行某个步骤时崩溃，可直接使用该参数从崩溃的步骤开始继续运行，而不必从头开始，节约了时间。或者认为某个步骤结果不理想，可直接指定参数运行该步骤以得出更理想的结果。）
  * 数据库参数（由于系统运行时间较长，当数据库系统崩溃、损坏或需要进行服务器迁移时，该参数使得使用者能够利用以前运行程序所得到的结果文件快速恢复数据库，大大缩短数据库的恢复时间）。
  * `--update-statistics-collection`参数是一个特例，不需要指定额外的参数值，主要用于更新数据库的统计信息，能够极大地加快数据库的响应速度。



系统使用示例：
设ipfile为一个ip地址文件，文件每一行均为一个地址或地址块，且均符合CIDR（无类别域间路由，Classless Inter-Domain Routing）规则。如：

```
1.2.3.4
1.2.5.0/24
.....
```


	1. 对该地址文件进行探测和扫描的命令为：
		./main.py	[-i   eth0]	[-B    1M]	[-p   179]	[-n  1]	ipfile
		系统将自动进行扫描和探测，并将结果储存进数据库。该命令默认执行所有步骤。

	2. 单独进行指纹探测的命令为：
		./main.py   [-i   eth0]	--os-detect	ipfile-result
		系统将自动进行操作系统指纹探测，并将结果储存进数据库。ipfile-result为前面对ipfile进行端口扫描之后所获取的结果文件，里面包含了所有开放了指定端口的IP地址

	3.更新数据库统计信息的命令为：
		./main.py	--update-statistics-collection
		系统将自动更新数据库的统计信息，并将这些统计信息储存进数据库，用于后续查询，该命令参数不需要指定任何其它参数和对参数进行赋值。



