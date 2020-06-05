#!/usr/bin/python3
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from flask import Flask, jsonify, request
from datetime import date
import requests
import time
import json, re, sys
import threading
#set various scores for different fields
type = 15
user = 15
host = 15
pid = 15
lock = 0

username = ""
counter = 0

app = Flask(__name__)

tasks = [
    {
        'id': 1,
        'value': u'test'
    }
]

def get_username(username):
    #When function is called. Send signal that new score needs to be calculated.
    global type, user, host, pid, lock

    print("passed user: %s" %username)
    count = 0
 
    #these are the fields of preset values from osquery
    #they are hardcoded into the trust scoring 
    data_liu_type = ['user', 'boot_time', 'blah']
    data_liu_user = ['testosquery', 'reboot', 'runlevel']
    data_liu_host = [':1', '5.3.0-46-generic']
    data_liu_pid = ['0', '53', '2642']
    
    #this calls the trust engine for each field in the logged_in_users query
    trustengine(data_liu_type, 1, username)
    trustengine(data_liu_user, 2, username)
    trustengine(data_liu_host, 3, username)
    trustengine(data_liu_pid, 4, username)

    #this adds up the score from the trust engine function and 
    #sends the score to the Swissknife API
    pass_score(type + user + host + pid)
            #pass_score(10)

    #resets the scores to their base value
    type = 15
    user = 15
    host = 15
    pid = 15


#This grabs the scores calulated and adds them up to get a total score for a field
def field_score_add(category, cur_val):
    global type, user, host, pid
    if category == "type":
        type = type + cur_val
    if category == "user":
        user = user + cur_val
    if category == "host":
        host = host + cur_val
    if category == "pid":
        pid = pid + cur_val
    print("type: ", type)
    print("user: ", user)
    print("host: ", host)
    print("pid: ", pid)

#this is the main function
def trustengine(data_array, number, user):
    #this connects to the elasticsearch database
    client = Elasticsearch(['http://<username>:<password>@localhost:9200'])
    
    t = date.today()
    t = str(t).replace("-", ".")
    #sets the index name to "osquery-result-yyyy.mm.dd" with the time
    #this ensures the index is alway set to the current day
    INDEX_NAME = ("osquery-result-" + t)

    #this queries the elasticsearch database according to these parameters
    s = Search(using=client, index=INDEX_NAME) \
        #passes the user that it gets from the Swissknife API to the elasticsearch database for the query
        .filter("term", hostIdentifier=user) \
        #looks for the logged_in_user query
        .query("match", name="pack/testpack/logged_in_users") \
        #only grabs the data in the snapshot
        .source(includes=["snapshot"])

    #this sets how much data can be stored in the search results array
    s = s[0:100]
    
    #this executes the query
    response = s.execute()
    
    #goes through all of the data in the query and formats the data into a json acceptable format with replace
    #then loads that data into the variable json_data which is all of the data from the query that contains fields
    for hit in response:
       for hostIdentifier in hit:
           data = hit[hostIdentifier]
           json_acceptable_string = str(data).replace("'", "\"").replace("\"{", "{").replace("}\"", "}")
           json_data = json.loads(json_acceptable_string)

    SCORE = 0
    
    #creates an array of the fields from the query, when the number is passed to the trust engine function
    #the index of this array is the number that gets passed when the trust engine function is called above
    json_array_field = ['time', 'type', 'user','host', 'pid']
    #counts how many times a match is not found in the query
    miss_counter = 0
    #sets the length of the predefined array passed into the trust engine function
    max_length = len(data_array)
    for i in json_data:
        miss_counter = 0
        for x in data_array:
            print("----------------------------starting field-------------------------------")
            if x != i[json_array_field[number]]:
                print("json_data:",i[json_array_field[number]],"   data_liu_TYPE:", x, "       result:  not equal")
                miss_counter+=1
                if miss_counter == max_length:
                    miss_counter = 0
                    print("SCORE before loop: ", SCORE)
                    SCORE-=3
                    field_score_add(json_array_field[number], SCORE)
                    print("SCORE: ", SCORE)

            SCORE = 0
            print("----------------------------starting field-------------------------------")
            if x == i[json_array_field[number]]:
                print("json_data:",i[json_array_field[number]],"   data_liu_TYPE:", x, "       result:  equal")
                miss_counter = 0
                print("SCORE before loop: ", SCORE)
                SCORE+=3
                field_score_add(json_array_field[number], SCORE)
                print("SCORE: ", SCORE)

            if miss_counter == 0:
                break
            SCORE = 0
            print("----------------------------all done with field-------------------------------")

#Returns calculated score to handler
def pass_score(score):

    headers = {
        'Content-Type': 'application/json'
    }

    data = '{"value": "%s"}' %score

    return requests.put('http://192.168.1.103:5000/2', headers=headers, data=data)

print("lock:", lock)

#Listens for incomming GET and PUT 
@app.route('/<int:task_id>', methods=['GET', 'PUT'])
def update_task(task_id):
    global username, counter, lock

    if request.method == 'GET':

        return jsonify({'tasks': tasks})


    task = [task for task in tasks if task['id'] == task_id]
    if len(task) == 0:
        abort(404)
    if not request.json:
        abort(400)

    tasks[0]['value'] = request.json.get('value', tasks[0]['value'])
    if lock == 0:
        get_username((tasks[0]['value']))
        lock = 1
    return jsonify({'tasks': tasks[0]})



@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)

if __name__ == "__main__":
    app.run(host='192.168.1.101', port=5001, debug=True)
