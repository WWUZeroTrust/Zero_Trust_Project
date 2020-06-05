from flask import Flask, jsonify, request, abort
import requests
import json
import threading

user = ""
score = ""
resource = ""
lock = threading.Event()
counter = 0
flag = 0
error = 0

app = Flask(__name__)
#Need user, score, and resource for OPA query
tasks = [
    {
        'id': 1,
        'value': u'user'
    },
    {
        'id': 2,
        'value': u'score'
    },
    {
        'id': 3,
        'value': u'resource'
    }
]

# This posts the user to the TrustAPI. Returns the response from the query.
def trust_query( url, value ):

    headers = {
        'Content-Type': 'application/json'
    }

    try:
        return requests.put(url, headers=headers, data=value)
    except:
        return ""

#This gathers the needed variables and queries OPA. Returns OPA's response.
def opa_query ():
    headers = {
        'Content-Type': 'application/json'
    }
    url = 'http://localhost:8181/v1/data/rbac/authz/allow'
    null = ""
    data = '{"input":{"user": "%s", "action": "write", "object": "%s", "score": "%s"%s}%s}' %(user, resource, score, null, null)
    print(data)
    response = requests.post(url, headers=headers, data=data)
    try:
        return(response.text)
    except:
        return ""

def get_user(value):
    global user 
    user = value

def get_score(value):
    global score
    score = value

def get_resource(value):
    global resource
    resource = value

def run_once(code):
    if code == 0:
        return jsonify({'tasks': tasks})
    if code == 1:
        abort(502)
    if code == 2:
        abort(401)



@app.before_request
def before_request():
    global lock, counter, flag, error

    if str(request.remote_addr) == "192.168.1.100":
        #Passes username and resource from traifik initial get request to functions for storing. 
        get_user(request.headers['Remote-User'])
        get_resource(request.headers['X-Forwarded-Host'])
        counter += 1
        print("counter in before_request:", counter)

    if request.method == 'GET' and str(request.remote_addr) == "192.168.1.100" and counter == 6:
        counter = 0
        print("value of counter:", counter)
        #grabs the user from traifik get request
        user1 = '{"value": "%s"}' %request.headers['Remote-User']

        #Calls function trust_query() and stores value in query1.
        query1 = trust_query('http://192.168.1.101:5001/1', user1)

        #validates that there were no errors. If there is an error with TrustAPI, then the process is aborted.
        if str(query1) != '<Response [200]>':
            print("query1:%s" %query1)
            print("Unknown error. Expected value is <Response [200]>")
            error = 1
            return

        #Wait for lock to open. This waits for a new score to be pushed from TrustAPI
        lock.wait()

        #Calls function opa_query() and stores value in query2.
        query2 = opa_query()

        #Validates that there were no erros with OPA, or OPA responded with false. If so, the processs is aborted.
        if str(query2) != '{"result":true}':
            print("query2:%s" %query2)
            print("Unknown error. Either access was denied or there was a failed connection to Open Policy Agent")
            error = 2
            return
        error = 0

lock.clear()

#Listens for incoming GET requests.
@app.route('/<int:task_id>', methods=['GET'])
def Query_routine(task_id):
    global error
    return run_once(error)


#After the OPA has evaluated all fields, the lock is set to closed, and waits for a new updated score. 


#Listens for incoming PUT requests.
@app.route('/<int:task_id>', methods=['PUT'])
def update_task(task_id):
    #Assings task for ID entered
    task = [task for task in tasks if task['id'] == task_id]
    if len(task) == 0:
        abort(404)
    if not request.json:
        abort(400)

    #Upates value stored in API.
    tasks[0]['value'] = request.json.get('value', tasks[0]['value'])

    #This checks if the value pushed into the API is the score. If so, it passes to get_score.
    if task_id == 2:
        get_score(tasks[0]['value'])
        global lock
        #Opens the lock now that new new score is entered
        lock.set()
        print("Lock is set to open")

    return jsonify({'tasks': tasks[0]})

#runs the flask application
if __name__ == "__main__":
    app.run(host='192.168.1.103',port=5000, debug=True)

#Query Command
# curl -i -H "Content-Type: application/json" -X PUT -d "{\"JWT\":\"VALUE\"}" http://localhost:5000/1

# curl -i http://localhost:5000/1
