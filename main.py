#! /usr/bin/env python


###############################################################################################
#Scan the given port specified by "FIRST_SCANNED_PORT" for IP block in the file in first step.
#Scan the given port in PORT_LIST for output of first step.
#If the file has too many IPs,it will scan for serveral times.
#Edited by ligl,2015-03-11
###############################################################################################
import pymongo
import os
import subprocess
import datetime, time
import sys
#this two lines of code will solve the encoding problem of function "str()"
reload(sys)
sys.setdefaultencoding('utf-8')

#These module is self_defined python file.
from scan import *
from geo_location_lookup_draw import *
from os_detection_into_db import *
from alias_resolution_by_iffinder  import *
from update_statistics  import *

#get the path of python file and change the working directory.
#os.getcwd() will get the path of working directory.
#sometimes the path of python file is different from the working directory.
CURRENT_DIR = os.path.abspath( os.path.dirname(__file__) )
os.chdir(CURRENT_DIR)

INTERFACE = "eth0"
BANDWIDTH = "1M"
PROBE_TIMES = 1
#The script will scan "FIRST_SCANNED_PORT" and scan the given port in "PORT_LIST" for the output of first step. 
FIRST_SCANNED_PORT = 179	#the scanned port for "sys.argv[0]" in first round scanning.
PORT_LIST = ["1-100",'161','179','443']
INTERVAL_BETWEEN_SCANNING =50	#Unit of measurement is second,specify the time between two scannings, it must be in [30,1000].
MAX_THREAD_FOR_OS_DETECTION = 5
#The blank space will make mistake in scan function of second step.replace illegal character ":" with "-" 
TIMESTAMP = str(datetime.datetime.now())		#timestamp for final output file
TIMESTAMP = TIMESTAMP.replace(":" , "-")

#########################################################################################################################
from optparse import OptionParser
class  process_opt:
	def getopt(self):
		usage = "usage: %prog  [options] arg"
		parser = OptionParser(usage)
		#add option for zmap
		#value of metavar will be displayed as the value of parameter.
		parser.add_option( "-i", dest="interface",		metavar="INTERFACE_NAME",	default="eth0",	help="Specify network interface to use" )
		parser.add_option( "-B",dest="bandwidth",	metavar="BANDWIDTH",		default="1M",  	help="Set send rate in bits/second (supports suffixes G, M and K)" )
		parser.add_option( "-p",dest="dest_port",	metavar="DESTINATION_PORT",default="179", 	help="TCP port for SYN scan" )
		parser.add_option( "-n",dest="probe_times",	metavar="Times_of_probing",					default="1" ,		help="Number of probes to send to each IP (default=`1')" )
		#action="stort_false" will make the '-q' be a short parameter, which has no value.
		parser.add_option("--port-scan",  dest="port_scan" ,   metavar="ipfile",  action="store_true", default=False, help="Scan ip in ipfile and  insert proper ip into database!" )
		parser.add_option("--asn-lookup", dest="asn_lookup",   metavar="ipfile",  action="store_true", default=False, help="Lookup ASN for ip in ipfile and insert ASN into database!")
		parser.add_option("--geo-lookup", dest="geo_lookup",   metavar="ipfile",  action="store_true", default=False, help="Lookup geo_info for ip in ipfile and insert geo_info into database!")
		parser.add_option("--os-detect", dest="os_detect" ,   metavar="ipfile",  action="store_true", default=False, help="Detect the os fingerprint and insert os fingerprint into database!")
		parser.add_option("--alias-resolution-iffinder",dest="alias_resolution_iffinder" ,   metavar="ipfile",  action="store_true", default=False,help="Do alias resolution  for ip in ipfile with iffinder and insert alias-resolution-result into database!")
		#such options are used to insert scanned data into database!
		parser.add_option("--insert-ip",   dest="insert_ip"  ,   metavar="scanning_result_file",  action="store_true", default=False, help="Just insert and update ip in database!" )
		parser.add_option("--insert-port", dest="insert_port", metavar="scanning_result_for_multi_port",  action="store_true", default=False, help="Just insert and update open port in database!" )
		parser.add_option("--insert-os-fingerprint",   dest="insert_os_fingerprint"  ,  metavar="os_detection_result_file",  action="store_true", default=False, help="Just insert and update os type and device type in database!" )
		parser.add_option("--insert-iffinder-alias-result", dest="insert_iffinder_alias_result",  metavar="alias_resolution_result_file",  action="store_true", default=False, help="Just insert and update result of iffinder alias resolution in database!" )
		parser.add_option("--update-statistics-collection", dest="update_statistics_collection", action="store_true", default=False, help="Update the statistics collection of database!  Don't need any argument!" )
		(options,args) = parser.parse_args()
		if len(args)>=1	or 	options.update_statistics_collection :
			print "options is: ",options
			print "args is: ",args
			return options,args
		else:
			parser.error("incorrect number of arguments")
			return False,False

	def start(self):
		global	INTERFACE
		global	BANDWIDTH
		global	FIRST_SCANNED_PORT	
		global	PROBE_TIMES	
		#Must put function "getopt" ahead the script, otherwise the input parameters won't work!
		#parse the parameter in command line and modify the corresponding value in global parameter!.
		options,args = self.getopt()
		if args:
			if options.interface:
				print "spcify the interface"
				INTERFACE = options.interface
			if options.bandwidth:
				BANDWIDTH = options.bandwidth
			if options.dest_port:
				FIRST_SCANNED_PORT = options.dest_port
			if options.probe_times:
				PROBE_TIMES = options.probe_times
		print "Interface used for scanning is: %s"%str(INTERFACE)
		print "Bandwidth used for scanning is: %s"%str(BANDWIDTH)
		print "First scanned port is: %s"%str(FIRST_SCANNED_PORT)
		print "Number of probing packet for each ip is: %s"%str(PROBE_TIMES)

temp=process_opt()
temp.start()

#########################################################################################################################
#this class is responsible for connecting with mongodb
class db_connect:
	def __init__(self,dbname='bgp_router_db'):
		self.dbname = dbname
	def connect(self):
		try:
			self.client=pymongo.MongoClient('127.0.0.1',27017)
			self.db=self.client[ self.dbname ]
			self.collection=self.db['bgp_router_collection']
			return True
		except Exception as e:
			print "Cann't connect database!"
			print e
			return False
	def close(self):
		#close the connection,because the interval between inserting into database is very long.
		self.client.close()

#########################################################################################################################
#just can a given port, need to insert into mongodb.
class first_round_scanning:
	#scan the ip block and the output of this step will be the input of second_step.
	def __init__(self,ipfile,port=FIRST_SCANNED_PORT):
		self.ipfile = str(ipfile)
		#print "____________________________________________"
		#print self.ipfile
		self.port  = str(port)	#In first round scanning only "FIRST_SCANNED_PORT" will be scanned.
		self.timestamp = False

	#get the time stamp of latest modified output file.
	def get_last_timestamp(self):
		try:
			modify_time = 0
			file_list = os.listdir(os.getcwd())
			for fn in file_list:
				if os.path.isfile(fn)  :
					index = fn.find(self.port+"_"+self.ipfile+"_")
					if index==0 and (len(fn.strip()) == len(self.port+"_"+self.ipfile+"_")+26) : 
						temp_time = float( os.path.getmtime(fn) )
						if temp_time > modify_time:
							modify_time = temp_time 
							#Since the length of timestamp is 26Byte.
							timestamp = fn.strip()[len(self.port+"_"+self.ipfile+"_"): ] 
			if modify_time:
				#print "time stamp is: ",timestamp
				return timestamp.strip()
			else:
				return False
		except Exception as e:
			print "&&**",e
			return False

	#get the subfile list and return the list.
	def get_subfile_list(self):		
		subfile_list = []
		file_list = os.listdir(os.getcwd())
		#Get the time stamp of last scanning.
		#The value may be false,if there are old output of first round scanning.		
		for fn in file_list:
			if os.path.isfile(fn)  :
				index = fn.find(self.ipfile+"_standardised_sub_")
				if fn.strip() == self.ipfile+"_standardised_sub_"+"0":
					#It means that last scanning finished in very early stage.
					#We need a new scanning instead of an old timestamp.
					subfile_list = []						
					break
				elif index==0 :
					subfile_list.append(fn.strip())
		return subfile_list

	def start(self):
		try:
			#Check whether the last scanning succeeds.	
			#But just work for those stopped in first step.
			subfile_list = self.get_subfile_list()
			#If the last scanning didn't succeed,we need to continue with the last scanning.
			if len(subfile_list)>0:	
				print "Continue with last scanning"
				self.timestamp = self.get_last_timestamp() 	#Get the timestamp of last scanning!
				self.output_file = str(self.port)+"_"+self.ipfile+"_"+self.timestamp		
				for fn in subfile_list:
					try:
						#scan_collect is a class for scanning given port and collect output of subipfile in the scan.py
						s = scan_collect(fn,self.port,self.timestamp,BANDWIDTH,INTERFACE,PROBE_TIMES)
						#collect the output of sub ipfile into a final result file with an old timestamp.
						s.collect_output()
						time.sleep(INTERVAL_BETWEEN_SCANNING)
					except Exception as e:
						print e
						return False
			#A new scanning starts.
			else:
				print "Start a new scanning....."
				self.timestamp = TIMESTAMP	#New timestamp will be used.
				self.output_file = str(self.port)+"_"+self.ipfile+"_"+self.timestamp	#To be input_filename for second_round_scan
				#process_file is a class for standardising and splitting ipfile in the scan.py .
				a = process_file(self.ipfile,BANDWIDTH)
				sub_file_num = a.split_file()
				#We will scan the given "port" for "subfile".			
				if sub_file_num:
					try:
						for i in range(sub_file_num):
							#Due to a new scanning,the third parameter can be ignored. 
							#The "TIMESTAMP" will be used to name output file.
							#supported parameters are whitelist_file, port, timestamp, bandwidth, interface, probe_times
							s = scan_collect(self.ipfile+ "_standardised"+"_sub_"+str(i),  self.port, self.timestamp,BANDWIDTH,INTERFACE,PROBE_TIMES)
							s.collect_output()
							#stop scanning temporarlly in order to cheat monitoring system of cloud host.
							time.sleep(INTERVAL_BETWEEN_SCANNING)
						#sometimes there are some subfiles which aren't scanned or deleted,we need to scan and delete them.
						subfile_list = self.get_subfile_list()
						if len(subfile_list)>0:
							 for fn in subfile_list:
								#Due to a new scanning,the third parameter can be ignored. 
								#The "TIMESTAMP" will be used to name output file.
								s = scan_collect(fn,self.port,self.timestamp,BANDWIDTH,INTERFACE,PROBE_TIMES)
								s.collect_output()
								#stop scanning temporarlly in order to cheat monitoring system of cloud host.
								time.sleep(INTERVAL_BETWEEN_SCANNING)	
					except Exception as e:
						print "&&&&&####   ",e
						#return False			
			#insert result into database.
			temp = db_connect()
			if temp.connect():
				collection = temp.collection
				try:
					hipfile = open(self.ipfile)
					lines = hipfile.readlines()
					for line in lines:
						#insert an ip into database if there isn't such document.
						#otherwise it won't do anything.
						#"PORT" will be reset, "DATE" will add new date into list when there isn't such date in list.
						#collection.insert_one({'IP':line.strip(),'CC':None,	'CITY':None,	'ASN':None,	'LONGTITUDE':None,	'LATITUDE':None,	'SUSPICIOUS_IP':False, 'ALIAS_SET_NUM_IFFINDER':-1,   'ALIAS_SET_SIZE_IFFINDER':1, 'ALIAS_SET_NUM_IFFINDER':-1,   'ALIAS_SET_SIZE_IFFINDER':1,				'PORT':[int(self.port)], 'OS_TYPE':None,	'DEVICE_TYPE':None,	'DATE':[]  })
						collection.update_one({'IP':line.strip()},	{'$set':{'IP':line.strip(),'CC':None,	'CITY':None,	'ASN':None,  'LONGTITUDE':None,  'LATITUDE':None,	
'SUSPICIOUS_IP':False, 'ALIAS_SET_NUM_IFFINDER':-1,   'ALIAS_SET_SIZE_IFFINDER':1,	'ALIAS_SET_NUM_MIDAR':-1,   'ALIAS_SET_SIZE_MIDAR':1,  'PORT':[int(self.port)], 'OS_TYPE':None,	'DEVICE_TYPE':None,	'DATE':[]	}}, True)
						collection.update_one({'IP':line.strip()},{'$addToSet':{'DATE':self.timestamp[:10]}})					
					hipfile.close()
					temp.close()
				except Exception as e:
					print "fail to insert rusult into databse!"
					print e
					hipfile.close()
					temp.close()
			else:
				print "Fail to connect database!"
				return False
			return True
		except Exception as e:
			print "Fail to scan %s"%self.ipfile
			print  e
			return False

#########################################################################################################################
#process the PORT_LIST
class  process_port:
	def start(self,port_list):
		global PORT_LIST
		temp=[]
		for elem in port_list:
			if str(elem).find("-") != -1:
				#this element is a sub_port_list, for example: 1-20 
				try:
					start_end = str(elem).split("-")
					#print "start_end is: ",start_end
					for i in range(int(start_end[0]),int(start_end[-1])+1):
						temp.append(i)
				except:
					print "abnormal port: %s"%str(elem)
			else:
				#this element is a normal port.
				try:
					temp.append(int(elem))
				except:
					print "abnormal port: %s"%str(elem)
		return temp


#########################################################################################################################
class second_round_scanning:
	def __init__(self,output_file,timestamp):
		global PORT_LIST
		self.output_file = output_file.strip()
		self.timestamp   = timestamp
		#process the port in the PORT_LIST
		temp=process_port()
		PORT_LIST=temp.start(PORT_LIST)

	def start(self):
		try:
			for port in PORT_LIST :
				#Since the "subfile" of first round output is deleted in collect_output function.
				#So we must regenerate subfile of  first round output.
				a = process_file(self.output_file,BANDWIDTH)
				sub_file_num = a.split_file()
				for i in range(sub_file_num):
					#Due to a new scanning,the third parameter can be ignored. 
					#The "TIMESTAMP" will be used to name output file.
					s = scan_collect(self.output_file+"_standardised"+"_sub_"+str(i), port, self.timestamp,BANDWIDTH,INTERFACE)
					s.collect_output()
					#stop scanning temporarlly in order to cheat monitoring system of cloud host.
					time.sleep(INTERVAL_BETWEEN_SCANNING)
			#insert port and supicious mark into database
			temp = db_connect()
			if temp.connect():
				for port in PORT_LIST :
					collection = temp.collection
					#insert the port open stat into database.
					try:
						hipfile = open(str(port)+"_"+self.output_file)
						lines = hipfile.readlines()
						for line in lines:
							#insert an ips into database if there isn't such document.
							#otherwise it won't do anything.
							collection.update_one({'IP':line.strip()},{'$addToSet':{'PORT':int(port)}})
						hipfile.close()
						os.remove(str(port)+"_"+self.output_file)
					except Exception as e:
						print "fail to insert rusult into databse!"
						print e
						hipfile.close()
						os.remove(str(port)+"_"+self.output_file)
				#mark the suspicious ip which open too many port.
				for item in collection.find():
					try:
						if len(item['PORT']) > 20:
							collection.update_one( {'IP':item['IP']},{'$set':{'SUSPICIOUS_IP':True}} )
					except Exception as e:
						print "something was wrong when change the vaule of SUSPICIOUS_IP"
						print e
				temp.close()	 #close the connection with mongodb.
			else:
				print "Fail to connect database!"
				temp.close() 	#close the connection with mongodb.
				return False								
			return True
		except Exception as e:
			print "&&&&&####   ",e
			print "Fail to scan for %s"%self.output_file
			return False

##################################################################################################################################################
def main():
	try:
		temp=process_opt()
		options,args=temp.getopt()
		if args	or 	options.update_statistics_collection:
			#######################################################
			#Detect the attribute of given ip in ipfile and insert its attributes into database!
			if options.port_scan:
				#Scan the given port of ip in ipfile and filter the abnormal ips which open too much meaningless ports!.
				for subfile in args:
					print "Begin to scan given ports for ip in %s......"%str(subfile)
					a = first_round_scanning(subfile,FIRST_SCANNED_PORT)	#Now the first step begins. 
					if a.start():
						print "Start the second round scanning...."
						b = second_round_scanning(a.output_file,a.timestamp)
						if b.start():
							print "succeed to scan ports!"
						else:
							print "fail to scan ports!"

			elif options.asn_lookup:
				#Get the ASN of ips and insert them into database!. 
				for subfile in args:
					print "Begin to get asn  for ip in %s......"%str(subfile)
					temp = get_asn_from_cymru(subfile)
					temp.start()

			elif options.geo_lookup:
				#Search the geo_information for ip in args, then insert geo_information into database and draw a map based on their location!
				for subfile in args:
					print "Begin to get geo_information for ip in %s and draw map......"%str(subfile)
					start_draw(subfile)

			elif options.os_detect:
				#Detect the os fingerprint and insert os fingerprint into database!
				for subfile in args:
					print "Begin to get os_info for ip in %s......"%str(subfile)
					temp = get_os_fingerprint(args[0],MAX_THREAD_FOR_OS_DETECTION)

			elif options.alias_resolution_iffinder:
				#Do alias resolution for ip in args and insert alias-resolution-result into database!
				for subfile in args:
					print "Begin to do alias resolution with iffinder for ip in %"%str(subfile)
					iffinder_alias_resolution(subfile)


			###########################################################
			#Insert ip attributes into database from old-data-file without detecting them!
			elif options.insert_ip:
				#Insert ip which open given port into database without scanning ip!
				try:
					temp = db_connect()
					if temp.connect():
						collection = temp.collection
					else:
						print "fail to connect database!"
						sys.exit()
				except:
					print "fail to connect database!"
					sys.exit()
				for subfile in args:
					print "The name of subfie is: ",str(subfile)
					if  os.path.isfile(subfile):
						try:
							badnum = 0
							ipnum = 0
							hfile = open( str(subfile))
							lines = hfile.readlines()
							port = int(subfile.split("/")[-1].split('_')[0])	#get the port from the file name.
							#print "########port is:",port
						except Exception as e:
							print "Cann't open ",subfile
							print e
							continue
						try:
							for line in lines:
								try:
									#Insert a document when there isn't such document!
									if  not  collection.find({'IP':line.strip()}).count():
										collection.update_one({'IP':line.strip()},	{'$set':{'IP':line.strip(),'CC':None,	'CITY':None,	'ASN':None,	'LONGTITUDE':None,	'LATITUDE':None,	'SUSPICIOUS_IP':False, 'ALIAS_SET_NUM_IFFINDER':-1,   'ALIAS_SET_SIZE_IFFINDER':1,    	'ALIAS_SET_NUM_MIDAR':-1,   'ALIAS_SET_SIZE_MIDAR':1,  'PORT':[int(port)], 'OS_TYPE':None,	'DEVICE_TYPE':None,	'DATE':[ TIMESTAMP[:10] ]}}, True)
									ipnum += 1	
								except Exception as e:
									badnum += 1
									print e
									print line.strip()
							print "succeed to insert port: %d into database!" %int(port)
							print "There are %d ips"%ipnum
							print "There are %d bad ip"%badnum
						except Exception as e:
							print "fail to insert ipfile into database!"
							print e
				temp.close()


			########################################################
			elif options.insert_port:
				#just insert or update ip in the database!
				#connect database.
				try:
					temp = db_connect()
					if temp.connect():
						collection = temp.collection
					else:
						print "fail to connect database!"
						sys.exit()
				except:
					print "fail to connect database!"
					sys.exit()

				for subfile in args:
					print "The name of subfie is: ",str(subfile)
					if  os.path.isfile(subfile):
						try:
							badnum = 0
							ipnum = 0
							hfile = open( str(subfile).strip() )
							lines = hfile.readlines()
							port = int(subfile.split("/")[-1].split('_')[0])	#get the port from the file name.
							#print "########port is:",port
						except Exception as e:
							print "Cann't open ",subfile
							print e
							continue
						try:
							for line in lines:
								try:
									collection.update_one({'IP':line.strip()},{'$addToSet':{'PORT':int(port)}})
									ipnum += 1	
								except Exception as e:
									badnum += 1
									print e
									print line.strip()
							print "succeed to insert port: %d into database!" %int(port)
							print "There are %d ips"%ipnum
							print "There are %d bad ip"%badnum						
						except Exception as e:
							print "fail to insert portfile into database!"
							print e
				#mark the suspicious ip which open too many port.
				for item in collection.find():
					try:
						if len(item['PORT']) > 20:
							collection.update_one( {'IP':item['IP']},{'$set':{'SUSPICIOUS_IP':True}} )
					except Exception as e:
						print e
						print "fail to mark suspicious ip!"
				#close the connection with database!
				temp.close()

			elif options.insert_os_fingerprint:
				#just insert or update ip in the database!
				for subfile in args:
					print "Begin to process os_detection_file: ",str(subfile)
					if  os.path.isfile(subfile):
						temp=process_os_detect_output( str(subfile))
						if temp.start():
							print "Succeed to insert os fingerprint into database!"
							return True
						else:
							print "Fail to insert os fingerprint into database!"
							return False

			elif options.insert_iffinder_alias_result:
				#just insert or update ip in the database!
				for subfile in args:
					print "Begin to process iffinder_alias_resolution_file: ",str(subfile)
					if  os.path.isfile(subfile):
						temp=process_iffinder_output( str(subfile))
						if temp.start():
							print "Succeed to insert output of iffinder alias resolution into database!"
							return True
						else:
							print "Fail to insert output of iffinder alias resolution into database!!"
							return False

			########################################################
			#Create or update the statistics collection for bgp_router_collection.
			elif options.update_statistics_collection:
				#Update statistics collection in the database!
				print "begin to update the statistics collection...."
				temp=update_statistics_collection()
				temp.start()	

			########################################################
			#Do  port-scanning, ip-filterring, geo-lookup, asn-lookup, os-detection, update-statistics-collection,  alias-resolution for ip in ipfile.
			#In other words,  do all jobs in this section.
			else:
				target_file=str(args[0])	#get the ipfile name from the command line.				
				a = first_round_scanning(target_file,FIRST_SCANNED_PORT)	#Now the first step begins. 
				if a.start():
					print "*****************************************"
					print "Start the second round scanning...."
					#print "&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&"
					#print "The timestamp is: ",a.timestamp
					#print "&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&"
					b = second_round_scanning(a.output_file,a.timestamp)
					b.start()		
					#start to lookup location and draw location map.
					print "try to get asn for ip ......"
					#time.sleep(30)
					c = get_asn_from_cymru(a.output_file)
					if c.start():
						print "Succeed to get asn!"
					else:
						print "Fail to get asn!"		
					print "get cc city longtitude latitude and draw map......"
					if start_draw(a.output_file):
						print "Succeed to get geo_loc information and draw map!"
					else:
						print "Fail to get geo_loc information and draw map!"
					print "get os fingerprint......"
					#start to get os fingerprint
					get_os_fingerprint(a.output_file,MAX_THREAD_FOR_OS_DETECTION)
					#do alias resolution by iffinder
					iffinder_alias_resolution(a.output_file)			
					#remove the ipfile
					try:
						os.remove(a.output_file)
						print "succeed to remove the scanning result file!"
					except Exception as e:
						print "fail to remove the scanning result file!"
						print e
					#update or create statistics collection for database.
					temp=update_statistics_collection()
					temp.start()
	except Exception as e:
		print "$$$$$   ",e
		sys.exit()


if __name__ == "__main__":
	main()
