#!/usr/bin/env python

# This is a simple web server for a traffic counting application.
# It's your job to extend it by adding the backend functionality to support
# recording the traffic in a SQL database. You will also need to support
# some predefined users and access/session control. You should only
# need to extend this file. The client side code (html, javascript and css)
# is complete and does not require editing or detailed understanding.

# import the various libraries needed
import http.cookies as Cookie  # some cookie handling support
from http.server import BaseHTTPRequestHandler, HTTPServer  # the heavy lifting of the web server
import urllib  # some url parsing support
import json  # support for json encoding
import sys  # needed for agument handling
import random
import sqlite3
import string
import time


def magicgen(nos1):
    """used to generate string of length nos1 for magic"""
    a = ''
    for i in range(nos1):
        a += random.choice(string.ascii_lowercase + string.digits)
    return a


def access_database_with_result(query, *args):
    """returns the query output in the form of list of tupple"""
    connect = sqlite3.connect('traffic.db')
    cursor = connect.cursor()
    rows = cursor.execute(query, args).fetchall()
    connect.commit()
    connect.close()
    return rows


def access_database(query, *args):
    """takes in the sql querry  and arguments and update or insert in the database"""
    connect = sqlite3.connect('traffic.db')
    cursor = connect.cursor()
    cursor.execute(query, args)
    connect.commit()
    connect.close()


def day_data(iuser, imagic):
    """Returns the week month and day data required for hour summary in dictonary format"""
    a = access_database_with_result("select date(end, 'unixepoch', 'localtime')"
                                    "from session where end!=0 order by sessionid "
                                    "desc limit 1")

    d = access_database_with_result("select date(datetime(`start`,'unixepoch'))"
                                    ",userid,end,start,"
                                    "round(sum(((end-start)/cast((60*60)as float))),1)"
                                    "from session "
                                    "where date(datetime(`end`,'unixepoch')) = ? "
                                    "and end!=0 and sessionid != 0 "
                                    "group by userid", a[0][0])
    w = access_database_with_result("select date(datetime(`start`,'unixepoch')),"
                                    "userid,end,start, "
                                    "round(sum(((end-start)/cast((60*60)as float))),1) "
                                    "from session where date(end, 'unixepoch', 'localtime') > "
                                    "date(?, '-7 day') and end != 0 "
                                    "and sessionid !=0 "
                                    "group by userid", a[0][0])
    m = access_database_with_result("select date(datetime(`start`,'unixepoch')),"
                                    "userid,end,start,round(sum(((end-start)/cast((60*60)as float))),1) "
                                    "from session where date(end, 'unixepoch', 'localtime') > "
                                    "date(?, '-1 month') and end != 0 and sessionid !=0 "
                                    "group by userid", a[0][0])

    dict_d = {1: 0, 2: 0, 3: 0,
              4: 0, 5: 0, 6: 0,
              7: 0, 8: 0, 9: 0,
              10: 0}
    dict_w = {1: 0, 2: 0, 3: 0,
              4: 0, 5: 0, 6: 0,
              7: 0, 8: 0, 9: 0,
              10: 0}
    dict_m = {1: 0, 2: 0, 3: 0,
              4: 0, 5: 0, 6: 0,
              7: 0, 8: 0, 9: 0,
              10: 0}
    for i in d:
        dict_d[i[1]] = i[4]
    for j in w:
        dict_w[j[1]] = j[4]
    for k in m:
        dict_m[k[1]] = k[4]

    return dict_d, dict_w, dict_m


def build_response_refill(where, what):
    """response built for message"""
    return {"type": "refill", "where": where, "what": what}


def build_response_redirect(where):
    """response built for redirect"""
    return {"type": "redirect", "where": where}


def handle_validate(iuser, imagic):
    """Decide if the combination of user and magic is valid"""
    user_in = access_database_with_result("select count(sessionid) "
                                          "from session "
                                          "inner join users on session.userid = users.userid "
                                          "where username = ? and magic = ? and "
                                          "session.end=0", iuser, imagic)

    if user_in[0][0] > 0:
        return True
    else:
        return False


def csv_data(iuser, imagic):
    """Returns the traffic data required for traffic.csv summary file in string format"""
    response = []
    if not handle_validate(iuser, imagic):
        response.append(build_response_redirect('/index.html'))
        return 'not logged in'
    else:
        lst = access_database_with_result("select time "
                                          "from traffic where mode = ? "
                                          "order by recordid desc limit 1", 1)

        typeloc = access_database_with_result("select type, location "
                                              "from traffic where mode = 1 "
                                              "and occupancy > 0 "
                                              "and date(time, 'unixepoch', 'localtime') = "
                                              "date(?, 'unixepoch', 'localtime') "
                                              "group by location, type", lst[0][0])
        ref_dict = {0: "car", 1: "van", 2: "truck",
                    3: "taxi", 4: "other", 5: "motorbike",
                    6: "bicycle", 7: "bus"}
        if len(typeloc) > 0:
            s = "Location,Type,Occupancy1,Occupancy2,Occupancy3,Occupancy4\n"

            for i in typeloc:
                out_csv = access_database_with_result("select occupancy, count(occupancy) "
                                                      "from traffic "
                                                      "where mode = 1 "
                                                      "and date(time, 'unixepoch', 'localtime') = "
                                                      "(select date(time, 'unixepoch', 'localtime') "
                                                      "from traffic "
                                                      "order by recordid desc limit 1) and "
                                                      "location = ? and type = ? "
                                                      "group by occupancy", i[1], i[0])
                occupancy1 = 0
                occupancy2 = 0
                occupancy3 = 0
                occupancy4 = 0
                for a in out_csv:

                    if a[0] == 1:
                        occupancy1 = a[1]
                    elif a[0] == 2:
                        occupancy2 = a[1]
                    elif a[0] == 3:
                        occupancy3 = a[1]
                    elif a[0] == 4:
                        occupancy4 = a[1]

                s += i[1] + ',' + ref_dict[i[0]] + ',' + str(occupancy1) + ',' \
                     + str(occupancy2) + ',' \
                     + str(occupancy3) + ',' + str(occupancy4) + '\n'
            return s


def handle_delete_session(iuser, imagic):
    """Deletes the current session"""

    et = int(time.time())
    iuserid = access_database_with_result("select users.userid, session.sessionid "
                                          "from users "
                                          "inner join session "
                                          "on users.userid = session.userid "
                                          "where username='%s' "
                                          "and magic='%s' "
                                          "and session.end=0" % (iuser, imagic))

    if len(iuserid) > 0:
        uid = iuserid[0][0]
        sid = iuserid[0][1]
    else:
        uid = 0
        sid = 0
    access_database("update session set end = ? "
                    "where userid = ? and magic = ? "
                    "and sessionid = ?", et, uid, imagic, sid)
    return


def check_login(u, p):
    """validate user id password"""

    check_log = access_database_with_result("select count(userid) "
                                            "from users "
                                            "where username = ? and password = ?", u, p)

    if check_log[0][0] > 0:
        return True
    return False


def handle_login_request(iuser, imagic, parameters):
    """Handle's the login request from the web page"""

    response = []
    user = ""
    magic = ""
    if ('usernameinput' not in parameters.keys()) and ('passwordinput' not in parameters.keys()):
        response.append(build_response_refill('message', 'empty user name and password'))
        return [user, magic, response]
    elif 'passwordinput' not in parameters.keys():
        response.append(build_response_refill('message', 'empty password'))
        return [user, magic, response]
    elif 'usernameinput' not in parameters.keys():
        response.append(build_response_refill('message', 'empty username'))
        return [user, magic, response]

    if check_login(parameters['usernameinput'][0], parameters['passwordinput'][0]):

        check_magic = access_database_with_result("select magic "
                                                  "from session "
                                                  "inner join users "
                                                  "on session.userid = users.userid "
                                                  "where users.username = ? "
                                                  "order by sessionid desc", parameters['usernameinput'][0])

        if len(check_magic) > 0:
            magicc = check_magic[0][0]
        else:
            magicc = 0
        if handle_validate(parameters['usernameinput'][0], magicc):
            handle_delete_session(parameters['usernameinput'][0], magicc)

        magic = magicgen(5)
        response.append(build_response_redirect('/page.html'))
        user = parameters['usernameinput'][0]
        st = int(time.time())
        iuserid = access_database_with_result("select userid from users where username = ?",
                                              parameters['usernameinput'][0])
        access_database("insert into session (userid,magic,start,end) "
                        "values (?,?,?,?)", iuserid[0][0], magic, st, 0)
    else:
        response.append(build_response_refill('message', 'Invalid user id or password'))
    return [user, magic, response]


def handle_add_request(iuser, imagic, parameters):
    """Handle's the add request"""
    response = []
    user = ''
    magic = ''

    if not handle_validate(iuser, imagic):
        response.append(build_response_redirect('/index.html'))
    else:
        session_id = access_database_with_result("select session.sessionid "
                                                 "from session "
                                                 "inner join users on users.userid = session.userid "
                                                 "where users.username = ? and session.magic = ?", iuser, imagic)

        map_dict = {"car": 0, "van": 1, "truck": 2,
                    "taxi": 3, "other": 4, "motorbike": 5,
                    "bicycle": 6, "bus": 7}
        if 'locationinput' not in parameters.keys():
            response.append(build_response_refill('message', 'Empty location'))
            return [user, magic, response]

        for i in parameters['locationinput'][0]:
            if i in string.punctuation:
                response.append(build_response_refill('message', 'invalid '
                                                                 'location has special char'))
                return [user, magic, response]

        if ('occupancyinput' not in parameters.keys()) or (
                parameters['occupancyinput'][0] not in ['0', '1', '2', '3', '4']):
            response.append(build_response_refill('message', 'empty occupancyinput'))
            return [user, magic, response]

        if ('typeinput' not in parameters.keys()) or (parameters['typeinput'][0] not in map_dict.keys()):
            response.append(build_response_refill('message', 'empty typeinput'))
            return [user, magic, response]

        at = int(time.time())

        access_database("insert into traffic "
                        "(sessionid,time,type,occupancy,location,mode) "
                        "values (?,?,?,?,?,?)", session_id[0][0],
                        at, map_dict[parameters['typeinput'][0]],
                        (parameters['occupancyinput'][0]),
                        parameters['locationinput'][0].lower(), 1)
        recorded = access_database_with_result("select count(recordid) "
                                               "from traffic "
                                               "where mode=1 and sessionid = ?", session_id[0][0])

        if recorded is not None:
            nos_record = str(recorded[0][0])
        else:
            nos_record = str(0)

        response.append(build_response_refill('message', 'Entry added.'))
        response.append(build_response_refill('total', nos_record))
    user = ''
    magic = ''
    return [user, magic, response]


def handle_undo_request(iuser, imagic, parameters):
    # add session id
    """undo request"""
    response = []
    user = ''
    magic = ''
    if not handle_validate(iuser, imagic):
        # Invalid sessions redirect to login
        response.append(build_response_redirect('/index.html'))
        return [user, magic, response]
    if 'locationinput' not in parameters.keys():
        response.append(build_response_refill('message', 'Empty location'))
        # response.append(build_response_redirect('/index.html'))
        # return 'invalid input'
        return [user, magic, response]

    for i in parameters['locationinput'][0]:
        if i in string.punctuation:
            response.append(build_response_refill('message', 'invalid location has special char'))
            # return 'invalid input'
            return [user, magic, response]

    if not (not ('occupancyinput' not in parameters.keys()) and not (parameters['occupancyinput'][0] not in ['0', '1', '2', '3', '4'])):
        response.append(build_response_refill('message', 'empty occupancyinput'))
        return [user, magic, response]
    map_dict = {"car": 0, "van": 1, "truck": 2, "taxi": 3, "other": 4, "motorbike": 5, "bicycle": 6, "bus": 7}

    if ('typeinput' not in parameters.keys()) or (parameters['typeinput'][0] not in map_dict.keys()):
        response.append(build_response_refill('message', 'empty typeinput'))
        return [user, magic, response]
    qt = int(time.time())
    session_id = access_database_with_result("select session.sessionid "
                                             "from session inner join users "
                                             "on users.userid = session.userid "
                                             "where users.username = ? and session.magic = ?",iuser, imagic)
    session_id_1 = 0
    if len(session_id)>0:
        session_id_1 = session_id[0][0]
    
    recordid = access_database_with_result("select recordid from traffic "
                                           "where location = ? and type = ? "
                                           "and occupancy = ? "
                                           "and mode = 1 "
                                           "and sessionid = ? "
                                           "order by recordid desc",parameters['locationinput'][0], map_dict[parameters['typeinput'][0]], int(parameters['occupancyinput'][0]), session_id_1)

    recordid_1 = 0
    if len(recordid)>0:
        recordid_1 = recordid[0][0]
        
    if not handle_validate(iuser, imagic):

        response.append(build_response_redirect('/index.html'))

    else:
        access_database("update traffic set mode = 2 "
                        "where location = ? and type = ?  "
                        "and occupancy = ? and mode = 1 "
                        "and sessionid = ? "
                        "and recordid = ?", parameters['locationinput'][0].lower(), map_dict[parameters['typeinput'][0]], int(parameters['occupancyinput'][0]), session_id_1, recordid_1)
        access_database("insert into traffic (sessionid,time,type,occupancy,location,mode) "
                        "values (?,?,?,?,?,?) ",session_id_1, qt, map_dict[parameters['typeinput'][0]], int(parameters['occupancyinput'][0]), parameters['locationinput'][0].lower(), 0)
        recorded = access_database_with_result("select count(recordid) "
                                               "from traffic where mode=1 and sessionid = ?", session_id_1)
        if recorded is not None:
            nos_record = str(recorded[0][0])
        else:
            nos_record = str(0)

        response.append(build_response_refill('message', 'Entry Un-done.'))
        response.append(build_response_refill('total', nos_record))

    return [user, magic, response]


def handle_back_request(iuser, imagic, parameters):
    """Back request"""
    response = []

    if not handle_validate(iuser, imagic):
        response.append(build_response_redirect('/index.html'))
    else:
        response.append(build_response_redirect('/summary.html'))
    user = ''
    magic = ''
    return [user, magic, response]


def handle_logout_request(iuser, imagic, parameters):
    """log out"""
    response = []

    et = int(time.time())
    iuserid = access_database_with_result("select users.userid, session.sessionid "
                                          "from users inner join session on users.userid "
                                          "where username=? and magic=? and session.end=0 "
                                          "order by session.sessionid desc limit 1", iuser, imagic)

    if len(iuserid) > 0:
        uid = iuserid[0][0]
        sid = iuserid[0][1]
    else:
        uid = 0
        sid = 0
    access_database("update session set end = ? "
                    "where userid = ? and magic = ? "
                    "and sessionid = ?", et, uid, imagic, sid)

    response.append(build_response_redirect('/index.html'))

    user = '!'
    magic = ''
    return [user, magic, response]


def handle_summary_request(iuser, imagic, parameters):
    """handle summary"""
    response = []
    if not handle_validate(iuser, imagic):
        # Invalid sessions redirect to login
        response.append(build_response_redirect('/index.html'))
    else:
        session_id = access_database_with_result("select session.sessionid "
                                                 "from session "
                                                 "inner join users "
                                                 "on users.userid = session.userid "
                                                 "where users.username = ? and session.magic = ?",iuser, imagic)
        if len(session_id)>0:
            
        
            summary_count = access_database_with_result("select count(recordid),type "
                                                        "from traffic where mode =1 and sessionid  =? "
                                                        "group by type", session_id[0][0])
            if len(summary_count)<1:
                summary_count=[(0,0)]
                
        
                
    
            recorded = access_database_with_result("select count(recordid) "
                                                   "from traffic "
                                                   "where mode=1 and sessionid  = ?",session_id[0][0])
            #print(summary_count,"odfhvodfklbjgofbedfol;beuhp;ensfvm;glbnefduih;ndfnfbdou")
            
            if recorded is not None:
                nos_record = recorded[0][0]
            else:
                nos_record = 0
    
            map_dict = {"car": 0, "van": 1, "truck": 2,
                        "taxi": 3, "other": 4, "motorbike": 5,
                        "bicycle": 6, "bus": 7}
            out_dict = {"car": 0, "van": 0, "truck": 0,
                        "taxi": 0, "other": 0, "motorbike": 0,
                        "bicycle": 0, "bus": 0}
    
            for k, v in map_dict.items():
                for i, j in summary_count:
                    
                    if v == j:
                        out_dict[k] = str(i)
    
            if not handle_validate(iuser, imagic):
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
    
                response.append(build_response_refill('total', nos_record))
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
            with open('.' + self.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # Return a Javascript file.
        # These tell contain code that the web client can execute.
        elif self.path.startswith('/js'):
            self.send_response(200)
            self.send_header('Content-type', 'text/js')
            self.end_headers()
            with open('.' + self.path, 'rb') as file:
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
            with open('.' + parsed_path.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()


        elif parsed_path.path == '/action':
            self.send_response(200)  # respond that this is a valid page request
            # extract the parameters from the GET request.
            # These are passed to the handlers.
            parameters = urllib.parse.parse_qs(parsed_path.query)

            if 'command' in parameters:
                # check if one of the parameters was 'command'
                # If it is, identify which command and call the appropriate handler function.
                if parameters['command'][0] == 'login':
                    [user, magic, response] = handle_login_request(user_magic[0], user_magic[1], parameters)
                    # The result of a login attempt will be to set the cookies to identify the session.
                    set_cookies(self, user, magic)
                elif parameters['command'][0] == 'add':
                    [user, magic, response] = handle_add_request(user_magic[0], user_magic[1], parameters)
                    if user == '!':  # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'undo':
                    [user, magic, response] = handle_undo_request(user_magic[0], user_magic[1], parameters)
                    if user == '!':  # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'back':
                    [user, magic, response] = handle_back_request(user_magic[0], user_magic[1], parameters)
                    if user == '!':  # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'summary':
                    [user, magic, response] = handle_summary_request(user_magic[0], user_magic[1], parameters)
                    if user == '!':  # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'logout':
                    [user, magic, response] = handle_logout_request(user_magic[0], user_magic[1], parameters)
                    if user == '!':  # Check if we've been tasked with discarding the cookies.
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

            dict_d, dict_w, dict_m = day_data(user_magic[0], user_magic[1])

            text = "Username,Day,Week,Month\n"

            for key in dict_d.keys():
                text += 'test' + str(key) + ',' + str(dict_d[key]) + ',' + str(dict_w[key]) + ',' + str(
                    dict_m[key]) + '\n'

            encoded = bytes(text, 'utf-8')
            self.send_response(200)
            self.send_header('Content-type', 'text/csv')
            self.send_header("Content-Disposition", 'attachment; filename="{}"'.format('hours.csv'))
            self.send_header("Content-Length", len(encoded))
            self.end_headers()
            self.wfile.write(encoded)

        elif self.path.endswith('/statistics/traffic.csv'):

            text = csv_data(user_magic[0], user_magic[1])

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

    if len(sys.argv) < 2:
        print("Port argument not provided.")
        return
    server_address = ('127.0.0.1', int(sys.argv[1]))
    httpd = HTTPServer(server_address, myHTTPServer_RequestHandler)
    print("running server on port =", sys.argv[1], '...')
    httpd.serve_forever()


run()
