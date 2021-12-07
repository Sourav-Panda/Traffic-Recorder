#!/usr/bin/env python

# This is a simple web server for a traffic counting application.
# It's your job to extend it by adding the backend functionality to support
# recording the traffic in a SQL database. You will also need to support
# some predefined users and access/session control. You should only
# need to extend this file. The client side code (html, javascript and css)
# is complete and does not require editing or detailed understanding.

# import the various libraries needed
import http.cookies as Cookie # some cookie handling support
from http.server import BaseHTTPRequestHandler, HTTPServer # the heavy lifting of the web server
import urllib # some url parsing support
import json # support for json encoding
import sys # needed for agument handling
import random
import sqlite3
import string
import time

#magic generator----------------------------------------------------------------------------------------------------------------
def magicgen(n):
    a = ''
    for i in range(n):
        a+=(random.choice(string.ascii_lowercase+string.digits))
    return a
#Query function ---------------------------------------------------------------------------------------------------------------
def access_database_with_result(query):
    connect = sqlite3.connect('db/clean.db')
    cursor = connect.cursor()
    rows = cursor.execute(query).fetchall()
    connect.commit()
    connect.close()
    return rows

def access_database(query):
    connect = sqlite3.connect('db/clean.db')
    cursor = connect.cursor()
    cursor.execute(query)
    connect.commit()
    connect.close()





def build_response_refill(where, what):
    """This function builds a refill action that allows part of the
       currently loaded page to be replaced."""
    return {"type":"refill","where":where,"what":what}


def build_response_redirect(where):
    """This function builds the page redirection action
       It indicates which page the client should fetch.
       If this action is used, only one instance of it should
       contained in the response and there should be no refill action."""
    return {"type":"redirect", "where":where}


def handle_validate(iuser, imagic):
    """Decide if the combination of user and magic is valid"""
    #changes done 1
    
    user_in = access_database_with_result("Select count(sessionid) from session inner join users on session.userid = users.userid where username = '%s' and magic = '%s' and session.end=0" %(iuser,imagic))
    print (user_in,"-------user_in-----------")
    if user_in[0][0]>0:
        return True
    else:
        return False
def csv_data(iuser, imagic):
    response = []
    if handle_validate(iuser, imagic) != True:
                #Invalid sessions redirect to login
                response.append(build_response_redirect('/index.html'))
                return 0
    else:
        session_id = access_database_with_result("select session.sessionid from session inner join users on users.userid = session.userid where users.username = '%s' and session.magic = '%s'"%(iuser,imagic))
        summary = access_database_with_result("SELECT location,type,occupancy from traffic WHERE mode = 1 and sessionid = %d " %(session_id[0][0]))
        return summary

def handle_delete_session(iuser, imagic):
    """Remove the combination of user and magic from the data base, ending the login"""
    #changes done 2
    et = int(time.time())
    iuserid = access_database_with_result("select users.userid from users inner join session on users.userid where username='%s' and magic='%s' and session.end=0" %(iuser,imagic))
    print(iuserid,"-----------isuerid----------------")
    if len(iuserid) > 0:
        uid = iuserid[0][0]
    else:
        uid = 0
    access_database("update session set end = %d where userid = %d and magic = '%s'"%(et,uid,imagic))
    check_del = access_database_with_result("select * from session")
    print(check_del,"-------------check_del-----------------")
    return

def check_login(u,p):
    check_log = access_database_with_result("select count(userid) from users where username = '%s' and password = '%s'" %(u,p))
    print(u,p,check_log,"bvlfksn vdfl;bndf;lv nb dfkgnf klvb;mnfos;dlkbeho;l ; ;gn ek")
    print(len(check_log))
    if check_log[0][0]>0:
        print("hi")
        return True
    else:
        print('bye')
        return False
    
def handle_login_request(iuser, imagic, parameters):
    """A user has supplied a username (parameters['usernameinput'][0])
       and password (parameters['passwordinput'][0]) check if these are
       valid and if so, create a suitable session record in the database
       with a random magic identifier that is returned.
       Return the username, magic identifier and the response action set."""
    
    
    response = []
    user=""
    magic = ""
    if ('usernameinput' not in parameters.keys()) and ( 'passwordinput' not in parameters.keys()):
        response.append(build_response_refill('message', 'empty user name and password'))
        return [user, magic, response]
    elif 'passwordinput' not in parameters.keys():
        response.append(build_response_refill('message', 'empty password'))
        return [user, magic, response]
    elif('usernameinput' not in parameters.keys()):
        response.append(build_response_refill('message', 'empty username'))
        return [user, magic, response]
    
    if check_login(parameters['usernameinput'][0],parameters['passwordinput'][0]):
        print("---------------------asdvfb------------------------")
        check_magic = access_database_with_result("select magic from session inner join users on session.userid = users.userid where users.username = '%s' order by sessionid desc"%(parameters['usernameinput'][0]))
        
        if len(check_magic)>0:
            magicc = check_magic[0][0]
        else:
            magicc = 0
            
        if handle_validate(parameters['usernameinput'][0], magicc) == True:
            handle_delete_session(parameters['usernameinput'][0], magicc)
        else:
            pass
        # the user is already logged in, so end the existing session.
                               
        
        magic = magicgen(5)
        response.append(build_response_redirect('/page.html'))
        user = parameters['usernameinput'][0]
        st = int(time.time())
        print(user,'----user--------')
        print(parameters['usernameinput'][0],"userpram---------------")
        iuserid = access_database_with_result("select userid from users where username = '%s'" %(parameters['usernameinput'][0]))
        access_database("insert into session (userid,magic,start,end) values (%d,'%s',%d,%d)"%(iuserid[0][0],magic,st,0))
    else:
        print("invalid pass----------------------------")
        response.append(build_response_refill('message', 'Invalid user id or password'))
        user = '!'
        magic = ''
    return [user, magic, response]
            

    
    ## alter as required
    
    #ignore the lines of code below--------------------------------------------------
    if parameters['usernameinput'][0] == 'test': ## The user is valid
        response.append(build_response_redirect('/page.html'))
        user = 'test'
        magic = '1234567890'
    else: ## The user is not valid
        response.append(build_response_refill('message', 'Invalid password'))
        user = '!'
        magic = ''
    return [user, magic, response]


def handle_add_request(iuser, imagic, parameters):
    """The user has requested a vehicle be added to the count
       parameters['locationinput'][0] the location to be recorded
       parameters['occupancyinput'][0] the occupant count to be recorded
       parameters['typeinput'][0] the type to be recorded
       Return the username, magic identifier (these can be empty  strings) and the response action set."""
    response = []
    ## alter as required
    print(handle_validate(iuser, imagic))
    if handle_validate(iuser, imagic) != True:
        #Invalid sessions redirect to login
        response.append(build_response_redirect('/index.html'))
    else: 
        ## a valid session so process the addition of the entry.
        #check for location input
        if ('locationinput' not in parameters.keys()):
            response.append(build_response_refill('message', 'Empty location'))
        else:
        
            print(type(parameters['locationinput'][0]),"---------location------------",parameters['locationinput'][0])
            print(type(int(parameters['occupancyinput'][0])),"-----------occupancy----------",int(parameters['occupancyinput'][0]))
            print(type(parameters['typeinput'][0]),"---------------typeinput--------------",parameters['typeinput'][0])
            map_dict = {"car": 0, "van":1, "truck":2, "taxi":3, "other":4, "motorbike":5, "bicycle":6, "bus":7}
            at = int(time.time())
            session_id = access_database_with_result("select session.sessionid from session inner join users on users.userid = session.userid where users.username = '%s' and session.magic = '%s'"%(iuser,imagic))
            
            access_database("insert into traffic (sessionid,time,type,occupancy,location,mode) values (%d,'%d',%d,%d,'%s',%d)"%(session_id[0][0],at,map_dict[parameters['typeinput'][0]],int(parameters['occupancyinput'][0]),parameters['locationinput'][0],1))
            #row1 = access_database_with_result("select * from traffic")
            #print(row1)
            recorded = access_database_with_result("select count(recordid) from traffic where mode=1 and sessionid = %d"%(session_id[0][0]))
            if recorded is not None:
                nos_record = recorded[0][0]
            else:
                nos_record = 0
            #veh = map_dict[parameters['typeinput'][0]]
            #print("time :",type(at),"sessionid :",type(session_id[0][0]),"vehicle :",type(veh))
            response.append(build_response_refill('message', 'Entry added.'))
            response.append(build_response_refill('total', nos_record))
    user = ''
    magic = ''
    return [user, magic, response]


def handle_undo_request(iuser, imagic, parameters):
    #add session id
    """The user has requested a vehicle be removed from the count
       This is intended to allow counters to correct errors.
       parameters['locationinput'][0] the location to be recorded
       parameters['occupancyinput'][0] the occupant count to be recorded
       parameters['typeinput'][0] the type to be recorded
       Return the username, magic identifier (these can be empty  strings) and the response action set."""
    map_dict = {"car": 0, "van":1, "truck":2, "taxi":3, "other":4, "motorbike":5, "bicycle":6, "bus":7}
    response = []
    session_id = access_database_with_result("select session.sessionid from session inner join users on users.userid = session.userid where users.username = '%s' and session.magic = '%s'"%(iuser,imagic))
    recordid = access_database_with_result("select recordid from traffic where location = '%s' and type = %d  and occupancy = %d and mode = 1 and sessionid = %d order by recordid desc" %(parameters['locationinput'][0],map_dict[parameters['typeinput'][0]],int(parameters['occupancyinput'][0]),session_id[0][0]))
    ## alter as required
    ## if there are duplicate record it will undo all but we might want to do one only
    if handle_validate(iuser, imagic) != True:
        #Invalid sessions redirect to login
        response.append(build_response_redirect('/index.html'))
    else: ## a valid session so process the recording of the entry.
        access_database("update traffic set mode = 0 where location = '%s' and type = %d  and occupancy = %d and mode = 1 and sessionid = %d and recordid = %d" %(parameters['locationinput'][0],map_dict[parameters['typeinput'][0]],int(parameters['occupancyinput'][0]),session_id[0][0],recordid[0][0]))
        recorded = access_database_with_result("select count(recordid) from traffic where mode=1 and sessionid = %d"%(session_id[0][0]))
        if recorded is not None:
            nos_record = recorded[0][0] 
        else:
            nos_record = 0
            
        
        response.append(build_response_refill('message', 'Entry Un-done.'))
        response.append(build_response_refill('total', nos_record))
    user = ''
    magic = ''
    return [user, magic, response]


def handle_back_request(iuser, imagic, parameters):
    """This code handles the selection of the back button on the record form (page.html)
       You will only need to modify this code if you make changes elsewhere that break its behaviour"""
    response = []
    ## alter as required
    if handle_validate(iuser, imagic) != True:
        response.append(build_response_redirect('/index.html'))
    else:
        response.append(build_response_redirect('/summary.html'))
    user = ''
    magic = ''
    return [user, magic, response]


def handle_logout_request(iuser, imagic, parameters):
    """This code handles the selection of the logout button on the summary page (summary.html)
       You will need to ensure the end of the session is recorded in the database
       And that the session magic is revoked."""
    response = []
    ## alter as required
    et = int(time.time())
    iuserid = access_database_with_result("select users.userid from users inner join session on users.userid where username='%s' and magic='%s' and session.end=0" %(iuser,imagic))
    print(iuserid,"-----------isuerid----------------")
    if len(iuserid) > 0:
        uid = iuserid[0][0]
    else:
        uid = 0
    access_database("update session set end = %d where userid = %d and magic = '%s'"%(et,uid,imagic))
    check_del = access_database_with_result("select * from session")
    print(check_del,"-------------check_del-----------------")
    response.append(build_response_redirect('/index.html'))
    #response.append(build_response_refill('message', 'Logout successful'))
    user = '!'
    magic = ''
    return [user, magic, response]


def handle_summary_request(iuser, imagic, parameters):
    """This code handles a request for an update to the session summary values.
       You will need to extract this information from the database.
       You must return a value for all vehicle types, even when it's zero."""
    response = []
    if handle_validate(iuser, imagic) != True:
        #Invalid sessions redirect to login
        response.append(build_response_redirect('/index.html'))
    else:    
        session_id = access_database_with_result("select session.sessionid from session inner join users on users.userid = session.userid where users.username = '%s' and session.magic = '%s'"%(iuser,imagic))
        summary_count = access_database_with_result("select count(recordid),type from traffic where mode =1 and sessionid  = %d group by type"%(session_id[0][0]))
        ## alter as required
        print(summary_count,"summary count")
        
        recorded = access_database_with_result("select count(recordid) from traffic where mode=1 and sessionid  = %d" %(session_id[0][0]))
        if recorded is not None:
            nos_record = recorded[0][0] 
        else:
            nos_record = 0
        #[(6,), (1,), (1,), (1,), (1,), (1,), (1,), (2,)]
        map_dict = {"car": 0, "van":1, "truck":2, "taxi":3, "other":4, "motorbike":5, "bicycle":6, "bus":7}
        out_dict = {"car": 0, "van":0, "truck":0, "taxi":0, "other":0, "motorbike":0, "bicycle":0, "bus":0}
        
        for k,v in map_dict.items():
            for i,j in summary_count:
                if v==j:
                    out_dict[k] = i
                    
        print(out_dict,"out_dict----------------------------")
                    
                    
    
    
        if handle_validate(iuser, imagic) != True:
            response.append(build_response_redirect('/index.html'))
        else:
            response.append(build_response_refill('sum_car', out_dict['car']))
            response.append(build_response_refill('sum_taxi', out_dict['taxi']))
            response.append(build_response_refill('sum_bus', out_dict['bus']))
            response.append(build_response_refill('sum_motorbike', out_dict['motorbike']))
            response.append(build_response_refill('sum_bicycle', out_dict['bicycle']))
            response.append(build_response_refill('sum_van', out_dict['van']))
            response.append(build_response_refill('sum_truck', out_dict['truck']))
            response.append(build_response_refill('sum_other', out_dict['other']))
            
            
            response.append(build_response_refill('total',nos_record ))
    user = ''
    magic = ''
    return [user, magic, response]


# HTTPRequestHandler class
class myHTTPServer_RequestHandler(BaseHTTPRequestHandler):

    # GET This function responds to GET requests to the web server.
    def do_GET(self):

        # The set_cookies function adds/updates two cookies returned with a webpage.
        # These identify the user who is logged in. The first parameter identifies the user
        # and the second should be used to verify the login session.
        def set_cookies(x, user, magic):
            ucookie = Cookie.SimpleCookie()
            ucookie['u_cookie'] = user
            x.send_header("Set-Cookie", ucookie.output(header='', sep=''))
            mcookie = Cookie.SimpleCookie()
            mcookie['m_cookie'] = magic
            x.send_header("Set-Cookie", mcookie.output(header='', sep=''))

        # The get_cookies function returns the values of the user and magic cookies if they exist
        # it returns empty strings if they do not.
        def get_cookies(source):
            rcookies = Cookie.SimpleCookie(source.headers.get('Cookie'))
            user = ''
            magic = ''
            for keyc, valuec in rcookies.items():
                if keyc == 'u_cookie':
                    user = valuec.value
                if keyc == 'm_cookie':
                    magic = valuec.value
            return [user, magic]

        # Fetch the cookies that arrived with the GET request
        # The identify the user session.
        user_magic = get_cookies(self)

        print(user_magic)

        # Parse the GET request to identify the file requested and the parameters
        parsed_path = urllib.parse.urlparse(self.path)

        # Decided what to do based on the file requested.

        # Return a CSS (Cascading Style Sheet) file.
        # These tell the web client how the page should appear.
        if self.path.startswith('/css'):
            self.send_response(200)
            self.send_header('Content-type', 'text/css')
            self.end_headers()
            with open('.'+self.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # Return a Javascript file.
        # These tell contain code that the web client can execute.
        elif self.path.startswith('/js'):
            self.send_response(200)
            self.send_header('Content-type', 'text/js')
            self.end_headers()
            with open('.'+self.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # A special case of '/' means return the index.html (homepage)
        # of a website
        elif parsed_path.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('./index.html', 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # Return html pages.
        elif parsed_path.path.endswith('.html'):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('.'+parsed_path.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # The special file 'action' is not a real file, it indicates an action
        # we wish the server to execute.
        elif parsed_path.path == '/action':
            self.send_response(200) #respond that this is a valid page request
            # extract the parameters from the GET request.
            # These are passed to the handlers.
            parameters = urllib.parse.parse_qs(parsed_path.query)

            if 'command' in parameters:
                # check if one of the parameters was 'command'
                # If it is, identify which command and call the appropriate handler function.
                if parameters['command'][0] == 'login':
                    [user, magic, response] = handle_login_request(user_magic[0], user_magic[1], parameters)
                    #The result of a login attempt will be to set the cookies to identify the session.
                    set_cookies(self, user, magic)
                elif parameters['command'][0] == 'add':
                    [user, magic, response] = handle_add_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'undo':
                    [user, magic, response] = handle_undo_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'back':
                    [user, magic, response] = handle_back_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'summary':
                    [user, magic, response] = handle_summary_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'logout':
                    [user, magic, response] = handle_logout_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                else:
                    # The command was not recognised, report that to the user.
                    response = []
                    response.append(build_response_refill('message', 'Internal Error: Command not recognised.'))

            else:
                # There was no command present, report that to the user.
                response = []
                response.append(build_response_refill('message', 'Internal Error: Command not found.'))

            text = json.dumps(response)
            print(text)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(bytes(text, 'utf-8'))
            

        elif self.path.endswith('/statistics/hours.csv'):
            ## if we get here, the user is looking for a statistics file
            ## this is where requests for /statistics/hours.csv should be handled.
            ## you should check a valid user is logged in. You are encouraged to wrap this behavour in a function.
            text = "Username,Day,Week,Month\n"
            text += "test1,0.0,0.0,0.0\n" # not real data
            text += "test2,0.0,0.0,0.0\n"
            text += "test3,0.0,0.0,0.0\n"
            text += "test4,0.0,0.0,0.0\n"
            text += "test5,0.0,0.0,0.0\n"
            text += "test6,0.0,0.0,0.0\n"
            text += "test7,0.0,0.0,0.0\n"
            text += "test8,0.0,0.0,0.0\n"
            text += "test9,0.0,0.0,0.0\n"
            text += "test10,0.0,0.0,0.0\n"       
            encoded = bytes(text, 'utf-8')
            self.send_response(200)
            self.send_header('Content-type', 'text/csv')
            self.send_header("Content-Disposition", 'attachment; filename="{}"'.format('hours.csv'))
            self.send_header("Content-Length", len(encoded))
            self.end_headers()
            self.wfile.write(encoded)

        elif self.path.endswith('/statistics/traffic.csv'):
            
            ## if we get here, the user is looking for a statistics file
            ## this is where requests for  /statistics/traffic.csv should be handled.
            ## you should check a valid user is checked in. You are encouraged to wrap this behavour in a function.
            #text = "This should be the content of the csv file."
            #ofline summary
            
            
            data = csv_data(user_magic[0],user_magic[1])
            ref_dict = {0:"car", 1:"van", 2:"truck", 3:"taxi", 4:"other", 5:"motorbike", 6:"bicycle", 7:"bus"}
            if data !=0:
                text = "Location,Type,Occupancy1,Occupancy2,Occupancy3,Occupancy4\n"
                for i in data:
                    occupancy1 = 0
                    occupancy2 = 0
                    occupancy3 = 0
                    occupancy4 = 0
                    if i[2]==1:
                        occupancy1 = 1
                    elif i[2]==2:
                        occupancy2 = 1
                    elif i[2]==3:
                        occupancy3 = 1
                    elif i[2]==4:
                        occupancy4 = 1
                        
                        
                        
                    s = str(i[0])+','+ref_dict[i[1]]+','+str(occupancy1)+','+str(occupancy2)+','+str(occupancy3)+','+str(occupancy4)+'\n'
                    text+=s
                    encoded = bytes(text, 'utf-8')
                    print(s)
                    #text += f"{{str(i[0])},{ref_dict[i[1]]},{str(occupancy1)},{str(occupancy2)},{str(occupancy3)},{str(occupancy4)}}"
                    
            #text = "Location,Type,Occupancy1,Occupancy2,Occupancy3,Occupancy4\n"
            text += '"Main Road",car,0,0,0,0\n' # not real data 
            encoded = bytes(text, 'utf-8')
            self.send_response(200)
            self.send_header('Content-type', 'text/csv')
            self.send_header("Content-Disposition", 'attachment; filename="{}"'.format('traffic.csv'))
            self.send_header("Content-Length", len(encoded))
            self.end_headers()
            self.wfile.write(encoded)

        else:
            # A file that does n't fit one of the patterns above was requested.
            self.send_response(404)
            self.end_headers()
        return

def run():
    """This is the entry point function to this code."""
    print('starting server...')
    ## You can add any extra start up code here
    # Server settings
    # Choose port 8081 over port 80, which is normally used for a http server
    if(len(sys.argv)<2): # Check we were given both the script name and a port number
        print("Port argument not provided.")
        return
    server_address = ('127.0.0.1', int(sys.argv[1]))
    httpd = HTTPServer(server_address, myHTTPServer_RequestHandler)
    print('running server on port =',sys.argv[1],'...')
    summary = access_database_with_result("SELECT location,type,occupancy from traffic WHERE mode = 1 order by location")
    print(summary,"__________________________________ssssssssssSSSSSS____________________")
    #row = access_database_with_result("Select * from users where username = '%s'" %('test1'))
    #print(row)
    httpd.serve_forever() # This function will not return till the server is aborted.

run()
