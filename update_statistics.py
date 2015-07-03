#! /usr/bin/env python

import pymongo
import datetime
from main  import PORT_LIST,  process_port


#There are four statistics collections: 	city_statistics_collection	asn_statistics_collection	fingerprint_statistics_collection		port_statistics_collection
#COLLECTION_LIST=[ ['city_statistics_collection', 'CITY'],  ['asn_statistics_collection', 'ASN'],   ['fingerprint_statistics_collection','OS_TYPE'] ]
#COLLECTION_LIST=[ ['fingerprint_statistics_collection','OS_TYPE'] ]
COLLECTION_LIST=[]
CORE_PORT_LIST=[22,23,80,161]



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



#Create or update the statistics information of  'bgp_router_collection' into collection.
#There are 3 statistics collections in COLLECTIOIN_LIST: 	city_statistics_collection	asn_statistics_collection	fingerprint_statistics_collection
class update_statistics_collection:
	def start(self):				
		#get longtitude and latitude from database.
		db_class = db_connect()
		if db_class.connect():
			for  collection_name_list  in  COLLECTION_LIST:	 #collection_name_list has two element: collection_name , attribute_name
				statistics_list=[]
				statistics_collection=db_class.db[ collection_name_list[0] ]		#This collection just stores statistics.
				data_collection = db_class.collection				#This collection stores all scanning data.
				for item in data_collection.find().batch_size(16):
					try:	
						if item[ collection_name_list[1] ]:
							sub_list = []
							flag= False
							#This item  has such attributes.  It should be put into statistics_list.
							for i in range(len(statistics_list)):
								if statistics_list[i][0] == item['CC'] and statistics_list[i][1] == item[ collection_name_list[1] ]:
									statistics_list[i][2] += 1
									flag = True
									break
							if not flag:
								sub_list.append(item['CC'])
								sub_list.append(item[ collection_name_list[1] ])
								sub_list.append(1)
								statistics_list.append(sub_list)
					except Exception as e:
						print e
						print "fail to process collection entry: ",item
						print "attribute name is: ",collection_name_list[1]
				#begin to create or update statistics collection.
				statistics_collection.remove()	#remove the old statistics information.
				for i in range( len(statistics_list) ):
					statistics_collection.update_one( { 'CC':statistics_list[i][0] , collection_name_list[1] : statistics_list[i][1]   },   {'$set' : {  'CC':statistics_list[i][0] ,    collection_name_list[1] : statistics_list[i][1] ,     'IP_NUM':  statistics_list[i][2]}},  True )


			###########################################
			#count the number of open port is not same as other attributes.  Here I produce a new method for count port numbers.
			#mapping_dict  is used for mapping  port to its location in list.	
			mapping_dict={}
			port_class=process_port()
			port_list=port_class.start(PORT_LIST)
			for i  in range (len(port_list)):
				mapping_dict[port_list[i]] = i

			statistics_dict = {}										#the element is  country_name:[port, ip_num]
			statistics_collection=db_class.db[ 'port_statistics_collection' ]		#This collection just stores statistics.
			data_collection = db_class.collection							#This collection stores all scanning data.
			#temp_num=0
			#starttime=datetime.datetime.now()
			for item in data_collection.find().batch_size(16):	#batch_size()	change the default batch size of pymongo query result.
				try:
					temp_num += 1
					if  item["CC"] :
						#print "country name is not none!"
						if  item["CC"]  in statistics_dict.keys():
							for port in item["PORT"]:
								try:
									statistics_dict[item["CC"]][mapping_dict[port]][1]  += 1
								except :
									print  "fail to count number of port: ",port
									#pass
						else:
							try:
								port_num_list = []
								for i in range(len(port_list)):
									port_num_list.append([port_list[i],  0 ])
								#print 'port_num_list is: ',port_num_list
								statistics_dict[item["CC"]] = port_num_list
							except Exception as e:
								print "fail to create port_num_list"
								print e
				except  Exception as e:
					#this item doesn't have "CC" attribute.
					print "Don't have any CC attribute."
					#print e
					print  item
				'''
				if temp_num > 10000:
					temp_num = 0
					endtime=datetime.datetime.now()
					print "Total time for 10000 items is: ",endtime-starttime
					starttime=datetime.datetime.now()
				'''

			#begin to create or update  port  statistics collection.
			for cc in statistics_dict.keys():
				for port in port_list:
					statistics_collection.update_one({'CC':cc , "PORT" : port},   {'$set' : { 'CC':cc, 'PORT' : port,     'IP_NUM':  statistics_dict[cc] [ mapping_dict[port] ] [1] }},  True )
			#finish updating all of statistics collections.  close the connection with database.
			db_class.close()
			print "Statistic is done!!!"
			return True
		else:
			print "Fail to connect database!"			
			return False



