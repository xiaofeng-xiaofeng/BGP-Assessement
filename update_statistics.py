#! /usr/bin/env python

import pymongo


#There are four statistics collections: 	city_statistics_collection	asn_statistics_collection	fingerprint_statistics_collection		port_statistics_collection
#COLLECTION_LIST=[ ['city_statistics_collection', 'CITY'],  ['asn_statistics_collection', 'ASN'],   ['fingerprint_statistics_collection','OS_TYPE'] ]
COLLECTION_LIST=[ ['fingerprint_statistics_collection','OS_TYPE'] ]
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
		temp = db_connect()
		if temp.connect():
			for  collection_name_list  in  COLLECTION_LIST:			#collection_name_list has two element: collection_name  , attribute_name
				statistics_list=[]
				statistics_collection=temp.db[ collection_name_list[0] ]		#This collection just stores statistics.
				data_collection = temp.collection				#This collection stores all scanning data.
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

			#try to get port statistics for given port in CORE_PORT_LIST.
			for port in CORE_PORT_LIST:
				statistics_list=[]
				statistics_collection=temp.db[ 'port_statistics_collection' ]		#This collection just stores statistics.
				data_collection = temp.collection							#This collection stores all scanning data.
				for item in data_collection.find().batch_size(16):				#batch_size()	change the default batch size of pymongo query result.
					try:	
						#if item[ 'PORT' ]:
						sub_list = []
						flag= False
						#This item  has such attributes.
						#It should be put into statistics_list if its city isn't None.
						for i in range(len(statistics_list)):
							if statistics_list[i][0] == item['CC'] and  port  in item["PORT"]:
								statistics_list[i][2] += 1
								flag = True
								break
						if not flag:								
							sub_list.append(item['CC'])
							sub_list.append(port)
							sub_list.append(1)
							statistics_list.append(sub_list)	
					except Exception as e:
						print "fail to process collection entry: ",item
						print "port is: ",port
						print e
				#begin to create or update  port  statistics collection.
				for i in range( len(statistics_list) ):
					statistics_collection.update_one( { 'CC':statistics_list[i][0] , "PORT" : statistics_list[i][1]   },   {'$set' : {  'CC':statistics_list[i][0] ,   'PORT' : statistics_list[i][1] ,     'IP_NUM':  statistics_list[i][2]}},  True )
			#finish updating all of statistics collections.  close the connection with database.
			temp.close()
			print "Statistic is done!!!"
			return True
		else:
			print "Fail to connect database!"			
			return False



