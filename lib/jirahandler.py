from attackcti import attack_client
import requests
import sys, traceback, json, re
import urllib3
import urllib.parse
import logging

# Configure logging to output to both stdout and a file.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),  # Logs to stdout
        logging.FileHandler("attack2jira.log")  # Logs to a file
    ]
)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class JiraHandler:

    username=""
    apitoken=""
    url=""

    def __init__(self, url, username, password):

        self.login(url, username, password)

    def login(self, url, username, apitoken):

        headers = {'Content-Type': 'application/json'}

        try:
            print("[*] Authenticating to " + url + "...")
            r = requests.get(url + '/rest/api/2/issue/createmeta', headers=headers,auth=(username,apitoken), verify=False)

            if r.status_code == 200:
                self.username=username
                self.apitoken=apitoken
                self.url=url
                print("[!] Success!")

            elif r.status_code == 401:
                print('[!] Wrong username or password :( .')
                sys.exit(1)

        except Exception as ex:
            print('[!] Error when trying to authenticate.')
            traceback.print_exc(file=sys.stdout)
            sys.exit(1)

    def create_project(self, project, key):

        #https://developer.atlassian.com/cloud/jira/platform/rest/v3/#api-rest-api-3-project-post -> this did not work for me.
        #found this endpoint using chrome dev tools.
        print("[*] Creating the Att&ck project...")
        headers = {'Content-Type': 'application/json'}

        project_dict = {
            'key': key,
            'name': project,
            'templateKey': "com.pyxis.greenhopper.jira:gh-simplified-basic",
        }
        try:
            r = requests.post(self.url + '/rest/simplified/latest/project', json=project_dict, headers=headers, auth=(self.username, self.apitoken), verify=False)
            if r.status_code == 200:
                print("[!] Success!")

            elif r.status_code == 401:
                print('[!] Unauthorized. Probably not enough permissions :(')
                sys.exit(1)

            else:
                print('[!] Error creating Jira project. Does it already exist ?')
                sys.exit(1)

        except Exception as ex:
            print ("[!] Error creating Jira project")
            traceback.print_exc(file=sys.stdout)
            sys.exit(1)

    def create_custom_fields(self):

        # avoid creating the custom fields more than once
        if not self.do_custom_fields_exist():
            print("[*] Creating custom fields ...")
            headers = {'Content-Type': 'application/json'}
            try:

                custom_fields=[]
                custom_field1_dict = {
                    "searcherKey": "com.atlassian.jira.plugin.system.customfieldtypes:multiselectsearcher",
                    "name": "Tactic",
                    "description": "Attack Tactic",
                    "type": "com.atlassian.jira.plugin.system.customfieldtypes:select"
                }
                custom_fields.append(custom_field1_dict)

                custom_field2_dict = {
                    "searcherKey": "com.atlassian.jira.plugin.system.customfieldtypes:multiselectsearcher",
                    "name": "Maturity",
                    "description": "Detection Maturity",
                    "type": "com.atlassian.jira.plugin.system.customfieldtypes:select"
                }
                custom_fields.append(custom_field2_dict)

                custom_field3_dict = {
                    "searcherKey": "com.atlassian.jira.plugin.system.customfieldtypes:exacttextsearcher",
                    "name": "Url",
                    "description": "Attack Technique Url",
                    "type": "com.atlassian.jira.plugin.system.customfieldtypes:url"
                }
                custom_fields.append(custom_field3_dict)

                custom_field4_dict = {
                    "searcherKey": "com.atlassian.jira.plugin.system.customfieldtypes:multiselectsearcher",
                    "name": "Datasources",
                    "description": "Data Sources",
                    "type": "com.atlassian.jira.plugin.system.customfieldtypes:multiselect"
                }
                custom_fields.append(custom_field4_dict)

                custom_field5_dict = {
                    "searcherKey": "com.atlassian.jira.plugin.system.customfieldtypes:textsearcher",
                    "name": "Id",
                    "description": "Technique Id",
                    "type": "com.atlassian.jira.plugin.system.customfieldtypes:textfield"
                }
                custom_fields.append(custom_field5_dict)

                custom_field6_dict = {
                    "searcherKey": "com.atlassian.jira.plugin.system.customfieldtypes:textsearcher",
                    "name": "Sub-Technique of",
                    "description": "Parent Technique Id",
                    "type": "com.atlassian.jira.plugin.system.customfieldtypes:textfield"
                }
                custom_fields.append(custom_field6_dict)

                for custom_field in custom_fields:
                    r = requests.post(self.url + '/rest/api/3/field', json=custom_field, headers=headers, auth=(self.username, self.apitoken), verify=False)

                    if r.status_code == 201:
                        print("\t [!] Successfully created \'"+custom_field['name']+"\' custom field.")

                    elif r.status_code == 401:
                        print('[!] Unauthorized. Probably not enough permissions :(')
                        sys.exit(1)

                    else:
                        print ("[!] Error creating custom fields")
                        sys.exit(1)


            except Exception as ex:
                traceback.print_exc(file=sys.stdout)
                sys.exit(1)

        else:
            print('[!] Found custom fields')

    def add_custom_field_options(self):

        custom_fields = self.get_custom_fields()
        headers = {'Content-Type': 'application/json'}
        try:

            # maturity field options
            payload=[{"name":"Not Tracked"},{"name":"Initial"},{"name":"Defined"},{"name":"Resilient"},{"name":"Optimized"}]
            r=requests.post(self.url + '/rest/globalconfig/1/customfieldoptions/'+custom_fields['Maturity'], headers=headers, json= payload, auth=(self.username, self.apitoken),verify=False)
            if r.status_code != 204:
                print("[!] Error creating options for the maturity custom field.")
                sys.exit()

            # tactic field options
            payload = self.get_attack_tactics()
            r = requests.post(self.url + '/rest/globalconfig/1/customfieldoptions/' + custom_fields['Tactic'], headers=headers, json=payload, auth=(self.username, self.apitoken), verify=False)
            if r.status_code != 204:
                print("[!] Error creating options for the tactic custom field.")
                sys.exit()

            # data source field options
            payload = self.get_attack_datasources()
            r = requests.post(self.url + '/rest/globalconfig/1/customfieldoptions/' + custom_fields['Datasources'], headers=headers, json=payload, auth=(self.username, self.apitoken), verify=False)
            if r.status_code != 204:
                print("[!] Error creating options for the datasources custom field.")
                sys.exit()


        except Exception as ex:
            traceback.print_exc(file=sys.stdout)
            sys.exit()

    def get_custom_fields(self):

        #print("[*] Getting custom field ids ...")
        custom_fields=['Tactic','Maturity','Url','Datasources','Id','Sub-Technique of']
        headers = {'Content-Type': 'application/json'}
        resp = {}

        try:
            r = requests.get(self.url + '/rest/api/3/field', headers=headers, auth=(self.username, self.apitoken), verify=False)
            if r.status_code == 200:
                results = r.json()
                for r in results:
                    if r['name'] in custom_fields:
                        resp.update({r['name']:r['id']})

            else:
                print("[!] Error getting custom fields")
                sys.exit(1)

            #logging.info(f"Custom fields: {custom_fields}")

            return resp


        except Exception as ex:
            traceback.print_exc(file=sys.stdout)
            sys.exit(1)

    def hide_unwanted_fields_old(self,key):
    # Deprecated, keeping in just in case.
        print("[*] Hiding unnecessary fields from ATTACK's issue layout...")
        screen_tab_ids = self.get_screen_tabs(key)
        headers = {'Content-Type': 'application/json'}

        #json_string = u'{"contextItemsCategories":{"primary":[{"id":"assignee","type":"FIELD"},{"id":"labels","type":"FIELD"}],"secondary":[{"id":"priority","type":"FIELD"}],"alwaysHidden":[{"id":"reporter","type":"FIELD"},{"id":"devSummary","type":"DEV_SUMMARY"},{"id":"releases","type":"RELEASES_PANEL"},{"id":"customfield_10041","type":"FIELD"},{"id":"timeoriginalestimate","type":"FIELD"},{"id":"customfield_10014","type":"FIELD"},{"id":"components","type":"FIELD"},{"id":"fixVersions","type":"FIELD"},{"id":"duedate","type":"FIELD"},{"id":"customfield_10011","type":"FIELD"},{"id":"timetracking","type":"FIELD"}]},"contentItemsCategories":{"visible":[{"id":"description","type":"FIELD"}],"alwaysHidden":[]}}'
        #json_string = u'{"contextItemsCategories":{"primary":[{"id":"assignee","type":"FIELD"}],"secondary":[{"id":"priority","type":"FIELD"},{"id":"labels","type":"FIELD"}],"alwaysHidden":[{"id":"reporter","type":"FIELD"},{"id":"devSummary","type":"DEV_SUMMARY"},{"id":"releases","type":"RELEASES_PANEL"},{"id":"customfield_10041","type":"FIELD"},{"id":"timeoriginalestimate","type":"FIELD"},{"id":"customfield_10014","type":"FIELD"},{"id":"components","type":"FIELD"},{"id":"fixVersions","type":"FIELD"},{"id":"duedate","type":"FIELD"},{"id":"customfield_10011","type":"FIELD"},{"id":"timetracking","type":"FIELD"}]},"contentItemsCategories":{"visible":[{"id":"description","type":"FIELD"}],"alwaysHidden":[]}}'
        json_string = u'{"contextItemsCategories":{"primary":[{"id":"assignee","type":"FIELD"}],"secondary":[{"id":"labels","type":"FIELD"}],"alwaysHidden":[{"id":"priority","type":"FIELD"},{"id":"reporter","type":"FIELD"},{"id":"devSummary","type":"DEV_SUMMARY"},{"id":"releases","type":"RELEASES_PANEL"},{"id":"customfield_10041","type":"FIELD"},{"id":"timeoriginalestimate","type":"FIELD"},{"id":"customfield_10014","type":"FIELD"},{"id":"components","type":"FIELD"},{"id":"fixVersions","type":"FIELD"},{"id":"duedate","type":"FIELD"},{"id":"customfield_10011","type":"FIELD"},{"id":"timetracking","type":"FIELD"}]},"contentItemsCategories":{"visible":[{"id":"description","type":"FIELD"}],"alwaysHidden":[]}}'

        try:
            for screen_tab_id in screen_tab_ids:
                r = requests.put(self.url + '/rest/api/2/project/'+key+'/properties/viewScreenId-'+str(screen_tab_id[0]), data=json_string, headers=headers, auth=(self.username, self.apitoken), verify=False)
            print("[!] Done.")

        except Exception as ex:
            print (ex)
            traceback.print_exc(file=sys.stdout)
            sys.exit(1)
    
    def hide_unwanted_fields(self,key):

        #https://support.atlassian.com/jira-core-cloud/docs/configure-field-layout-in-the-issue-view/
        #https://jira.atlassian.com/browse/JRACLOUD-74697?error=login_required&error_description=Login+required&state=0c1a9f1d-8614-4158-b02e-f06e8706f5d4


        print("[*] Hiding unnecessary fields from ATTACK's issue layout...")
        #screen_tab_ids = self.get_screen_tabs(key)
        project_id=self.get_project_id(key)
        screen_ids = self.get_screen_ids(project_id)
        custom_Fields = self.get_custom_fields()

        headers = {'Content-Type': 'application/json'}

        #json_string = u'{"context":{"primary":[{"id":"assignee","type":"FIELD"},{"id":"reporter","type":"FIELD"},{"id":"devSummary","type":"DEV_SUMMARY"},{"id":"customfield_10094","type":"FIELD"},{"id":"customfield_10092","type":"FIELD"},{"id":"customfield_10090","type":"FIELD"},{"id":"customfield_10093","type":"FIELD"},{"id":"customfield_10091","type":"FIELD"},{"id":"labels","type":"FIELD"}],"secondary":[{"id":"priority","type":"FIELD"}],"alwaysHidden":[{"id":"timeoriginalestimate","type":"FIELD"},{"id":"timetracking","type":"FIELD"},{"id":"components","type":"FIELD"},{"id":"fixVersions","type":"FIELD"},{"id":"customfield_10014","type":"FIELD"},{"id":"duedate","type":"FIELD"},{"id":"customfield_10011","type":"FIELD"},{"id":"customfield_10026","type":"FIELD"}]},"content":{"visible":[{"id":"description","type":"FIELD"}],"alwaysHidden":[]}}'
        json_string = u'{"context":{"primary":[{"id":"assignee","type":"FIELD"},{"id":"reporter","type":"FIELD"},{"id":"labels","type":"FIELD"},{"id":"MATURITY_CUSTOMFIELD","type":"FIELD"},{"id":"DATASOURCE_CUSTOMFIELD","type":"FIELD"}],"secondary":[{"id":"priority","type":"FIELD"}],"alwaysHidden":[{"id":"timeoriginalestimate","type":"FIELD"},{"id":"timetracking","type":"FIELD"},{"id":"components","type":"FIELD"},{"id":"fixVersions","type":"FIELD"},{"id":"customfield_10014","type":"FIELD"},{"id":"duedate","type":"FIELD"},{"id":"customfield_10011","type":"FIELD"},{"id":"customfield_10026","type":"FIELD"},{"id":"devSummary","type":"DEV_SUMMARY"}]},"content":{"visible":[{"id":"TACTIC_CUSTOMFIELD","type":"FIELD"},{"id":"ID_CUSTOMFIELD","type":"FIELD"},{"id":"URL_CUSTOMFIELD","type":"FIELD"},{"id":"SUBTECHNIQUE_CUSTOMFIELD","type":"FIELD"},{"id":"description","type":"FIELD"}],"alwaysHidden":[]}}'        
        
        json_string = json_string.replace("DATASOURCE_CUSTOMFIELD", custom_Fields['Datasources'])
        json_string = json_string.replace("ID_CUSTOMFIELD", custom_Fields['Id'])
        json_string = json_string.replace("TACTIC_CUSTOMFIELD", custom_Fields['Tactic'])
        json_string = json_string.replace("MATURITY_CUSTOMFIELD", custom_Fields['Maturity'])
        json_string = json_string.replace("URL_CUSTOMFIELD", custom_Fields['Url'])
        json_string = json_string.replace("SUBTECHNIQUE_CUSTOMFIELD", custom_Fields['Sub-Technique of'])

        try:
            for screen_id in screen_ids:
                r = requests.put(self.url + '/rest/issuedetailslayout/config/classic/screen?projectIdOrKey='+key+'&screenId='+str(screen_id), data=json_string, headers=headers, auth=(self.username, self.apitoken), verify=False)
            print("[!] Done.")

        except Exception as ex:
            print (ex)
            traceback.print_exc(file=sys.stdout)
            sys.exit(1)


    def do_custom_fields_exist(self):

        custom_fields = self.get_custom_fields()

        ## TODO: Need to perform better checks but this works for now.
        if len(custom_fields.keys()) == 6:
            return True
        else:
            return False


    def create_issue(self, issue_dict, id):

        # good examples https://developer.atlassian.com/server/jira/platform/jira-rest-api-examples/#creating-an-issue-examples
        headers = {'Content-Type': 'application/json'}
        try:
            r = requests.post(self.url + '/rest/api/2/issue', json=issue_dict, headers=headers, auth=(self.username, self.apitoken), verify=False)

            if r.status_code == 201:
                print ("\t[!] Successfully created Jira issue for "+id)
                return json.loads(r.text)
            else:
                print ("\t[!] Error creating Jira issue for "+id)
                print (r.text)
                sys.exit()

        except Exception as ex:

            print(ex)
            traceback.print_exc(file=sys.stdout)
            sys.exit()


    def get_attack_screens(self, key):

        headers = {'Content-Type': 'application/json'}
        screen_ids=[]
        try:
            r = requests.get(self.url + '/rest/api/3/screens', headers=headers, auth=(self.username, self.apitoken), verify=False)

            if r.status_code == 200:
                results = r.json()['values']
                for r in results:
                    if key in r['name'] and "Default Issue Screen" in r['name']:
                        screen_ids.append(r['id'])
            else:
                print("[!] Error obtaining screens")
                sys.exit(1)

            return screen_ids

        except Exception as ex:
            traceback.print_exc(file=sys.stdout)
            sys.exit()

    def get_screen_tabs(self, key):

        # deprecated, keeping it in codebase just in case.
        headers = {'Content-Type': 'application/json'}
        screen_ids = self.get_attack_screens(key)
        screen_tab_ids=[]
        try:
            for screen_id in screen_ids:

                r = requests.get(self.url + '/rest/api/3/screens/'+str(screen_id)+'/tabs', headers=headers, auth=(self.username, self.apitoken), verify=False)
                if r.status_code == 200:
                    for result in r.json():
                        screen_tab_ids.append([screen_id, result['id']])
                else:
                    print("[!] Error obtaining screen tabs")
                    sys.exit(1)

            return screen_tab_ids

        except Exception as ex:
            traceback.print_exc(file=sys.stdout)
            sys.exit()


    def add_custom_field_to_screen_tab_old(self, key):
        # deprecated. keeping it in codebase just in case

        print("[*] Adding custom fields to ATTACK's default screen tab ...")
        headers = {'Content-Type': 'application/json'}
        screen_tab_ids = self.get_screen_tabs(key)
        custom_fields = self.get_custom_fields()

        try:
            for key in custom_fields.keys():
                for screen_tab_id in screen_tab_ids:
                    custom_field_dict = {'fieldId': custom_fields[key]}
                    #print (self.url + '/rest/api/2/screens/'+str(screen_tab_id[0])+'/tabs/'+str(screen_tab_id[1])+'/fields')
                    r = requests.post(self.url + '/rest/api/3/screens/'+str(screen_tab_id[0])+'/tabs/'+str(screen_tab_id[1])+'/fields', json = custom_field_dict, headers=headers, auth=(self.username, self.apitoken), verify=False)

            print("[!] Done!.")

        except Exception as ex:
            traceback.print_exc(file=sys.stdout)
            sys.exit()

    def get_technique_maturity(self):

        print("[*] Getting issues from the ATTACK project...")
        custom_fields = self.get_custom_fields()
        headers = {'Content-Type': 'application/json'}
        read_issues=0
        startAt=0
        res_dict=dict()

        try:

            while(True):
                #print("Entering while loop. startAt is "+str(startAt))
                r = requests.get(self.url + '/rest/api/3/search?jql=project%20%3D%20ATTACK&startAt='+str(startAt), headers=headers, auth=(self.username, self.apitoken), verify=False)
                resp_dict = r.json()
                for issue in resp_dict['issues']:
                    technique_id = issue['fields'][custom_fields['Id']]
                    #print (issue['fields']['summary']," ",issue['fields'][custom_fields['maturity']] )
                    #print(technique_id, " ", issue['fields'][custom_fields['maturity']])
                    res_dict.update({technique_id:issue['fields'][custom_fields['Maturity']]})
                read_issues+=50
                startAt+=50
                if (read_issues>=r.json()['total']):
                    break

            return res_dict

        except Exception as ex:
            traceback.print_exc(file=sys.stdout)
            sys.exit()


    def get_attack_datasources(self):
    
        try:
            datasource_payload=[]
            client = attack_client()

            #the datasources obtained via the line below do not correspond with the data sources being present in get_attack_techniques()
            #datasources = client.get_data_sources()

            #this is likely a temporary workaround
            data_sources_legacy = []
            techniques = client.get_techniques()
            for technique in techniques:
                try:
                    data_sources_field = technique['x_mitre_data_sources']
                except:
                    pass
                for ds in data_sources_field:
                    data_sources_legacy.append(str(ds).title())
            #making data_sources_legacy records unique
            data_sources_legacy = list(set(data_sources_legacy))
            # end of the workaround
            for datasource in data_sources_legacy:
                d = {'name': datasource}
                datasource_payload.append(d)
            return datasource_payload

        except:
            traceback.print_exc(file=sys.stdout)
            print ("[!] Error connecting obtaining datasources from Att&ck's API !")
            sys.exit()

    def get_attack_tactics(self):

        try:
            tactics_payload=[]
            client = attack_client()
            enterprise_tactics = client.get_enterprise()
            tactics = [tactic['name'].lower().replace(" ", "-") for tactic in enterprise_tactics['tactics']]
            for tactic in tactics:
                tactics_payload.append({"name": tactic})
            return tactics_payload

        except:
            traceback.print_exc(file=sys.stdout)
            print ("[!] Error connecting obtaining tactics from Att&ck's API !")
            sys.exit()

    def add_custom_fields_to_screen(self, key):

        print("[*] Adding custom fields to ATTACK's default screen tab ...")
        headers = {'Content-Type': 'application/json'}
        project_id=self.get_project_id(key)
        screen_tab_ids = self.get_screen_tab_ids(project_id)
        screen_ids = self.get_screen_ids(project_id)
        custom_fields = self.get_custom_fields()

        try:
            for key in custom_fields.keys():
                for i in range(1):
                    custom_field_dict = {'fieldId': custom_fields[key]}
                    #print (self.url + '/rest/api/2/screens/'+str(screen_tab_id[0])+'/tabs/'+str(screen_tab_id[1])+'/fields')
                    r = requests.post(self.url + '/rest/api/3/screens/'+str(screen_ids[i])+'/tabs/'+str(screen_tab_ids[i])+'/fields', json = custom_field_dict, headers=headers, auth=(self.username, self.apitoken), verify=False)

            print("[!] Done!.")

        except Exception as ex:
            traceback.print_exc(file=sys.stdout)
            sys.exit()

    def get_project_id(self,key):
        headers = {'Content-Type': 'application/json'}
        try:
            r = requests.get(self.url + '/rest/api/3/project/search', headers=headers, auth=(self.username, self.apitoken), verify=False)
            resp_dict = r.json()
            for project in resp_dict['values']:
                if project['key'] == key:
                    return project['id']
            return 0
                
        except:
            traceback.print_exc(file=sys.stdout)
            print ("[!] Error obtaining project id!")
            sys.exit()

    def get_screen_ids(self, project_id):
        headers = {'Content-Type': 'application/json'}
        screen_scheme_ids = self.get_screen_scheme_ids(project_id)
        screen_ids = []
        try:
            for item in screen_scheme_ids:
                r = requests.get(self.url +'/rest/api/2/screenscheme?id='+item, headers=headers, auth=(self.username, self.apitoken),verify=False)
                r_dict = r.json()
                screen_ids.append(list(r_dict['values'][0]['screens'].values())[0])
            return screen_ids

        except:
            traceback.print_exc(file=sys.stdout)
            print ("[!] Error obtaining screen ids!")
            sys.exit()


    def get_screen_scheme_ids(self, project_id):
        headers = {'Content-Type': 'application/json'}
        issue_type_screen_scheme_ids = self.get_project_issue_type_screen_scheme_ids(project_id)
        request_items=[]
        screen_scheme_ids=[]
        try:
            for item in issue_type_screen_scheme_ids:
                r = requests.get(self.url +'/rest/api/2/issuetypescreenscheme/mapping?issueTypeScreenSchemeId=' + item, headers=headers, auth=(self.username, self.apitoken), verify=False)
                r_dict=r.json()
                request_items.append(r_dict)
            for item in request_items:
                for subitem in item['values']:
                    screen_scheme_ids.append(subitem['screenSchemeId'])
            return  screen_scheme_ids
        
        except:
            traceback.print_exc(file=sys.stdout)
            print ("[!] Error obtaining screen scheme ids!")
            sys.exit()

    
    def get_project_issue_type_screen_scheme_ids(self, project_id):
        headers = {'Content-Type': 'application/json'}
        query={'projectId': project_id}
        issue_type_screen_scheme_ids=[]
        try:
            r = requests.get(self.url +'/rest/api/3/issuetypescreenscheme/project/', headers=headers, params=query, auth=(self.username, self.apitoken), verify=False) 
            resp_dict = r.json()
            for item in resp_dict['values']:
                issue_type_screen_scheme_ids.append(item['issueTypeScreenScheme']['id'])

            return issue_type_screen_scheme_ids

        except:
            traceback.print_exc(file=sys.stdout)
            print ("[!] Error obtaining issue type screen scheme ids!")
            sys.exit()
    
    
    def get_screen_tab_ids(self, project_id):
        screen_ids = self.get_screen_ids(project_id)
        screen_tab_ids = []
        try:
            for item in screen_ids:
                screen_tab_id = self.get_screen_tab_id(item)
                screen_tab_ids.append(screen_tab_id)
            return screen_tab_ids

        except:
            traceback.print_exc(file=sys.stdout)
            print ("[!] Error obtaining screen tab ids!")
            sys.exit()


    def get_screen_tab_id(self, screen_id):
        headers = {'Content-Type': 'application/json'}
        try:
            r = requests.get(self.url +'/rest/api/3/screens/'+str(screen_id)+'/tabs', headers=headers, auth=(self.username, self.apitoken), verify=False) 
            resp_dict = r.json()
            return resp_dict[0]['id']

        except:
            traceback.print_exc(file=sys.stdout)
            print ("[!] Error obtaining screen/tab ids!")
            sys.exit()
            
            
    def get_project_screen_tab_ids(self, project_id):
    #legacy - not used in the current version
        headers = {'Content-Type': 'application/json'}
        screen_tab_ids=[]
        try:
            r = requests.get(self.url +'/rest/api/3/issuetypescreenscheme/mapping?issueTypeScreenSchemeId='+project_id,headers=headers, auth=(self.username, self.apitoken), verify=False) 
            resp_dict = r.json()
            for screen in resp_dict['values']:
                screen_tab_ids.append([screen['screenSchemeId'], self.get_screen_tab_id(screen['screenSchemeId'])])

            return screen_tab_ids

        except:
            traceback.print_exc(file=sys.stdout)
            print ("[!] Error obtaining screen/tab ids!")
            sys.exit()

    def issue_exists(self, ttp_id, project_key):
        try:
            print(f"Called issue_exists for {ttp_id}")  # Debug print
            # Build a JQL query that looks for the technique id in the custom field "Id"
            jql = f'project = {project_key} AND "Id[Short text]" ~ "{ttp_id}"'
            #logging.info(f"Executing JQL: {jql}")
            headers = {'Content-Type': 'application/json'}
            # URL-encode the JQL string
            jql_encoded = urllib.parse.quote(jql)
            url = f"{self.url}/rest/api/3/search?jql={jql_encoded}"
            r = requests.get(url, headers=headers, auth=(self.username, self.apitoken), verify=False)
            if r.status_code == 200:
                data = r.json()
                logging.info(f"Search result: {data.get('total', 0)} issues found for {ttp_id}")
                return data.get('total', 0) > 0
            else:
                print(f"[!] Error searching for existing issues: {r.text}")
                # Optionally, decide if you want to fail here or assume no issue exists
                return False
        except:
            traceback.print_exc(file=sys.stdout)
            print ("[!] Error checking for existing TTPs!")
            sys.exit()

    def get_issue_by_ttp(self, ttp_id, project_key):
        """
        Returns the parent issue for a given TTP ID.
        If the fuzzy search returns several issues (e.g., T1234, T1234.001, T1234.002),
        this method filters out sub-techniques (those with a dot in their Id field)
        and returns the issue that exactly matches the parent's TTP ID.
        """
        # Build JQL with fuzzy operator since exact match isn't accepted.
        jql = f'project = {project_key} AND "Id[Short text]" ~ "{ttp_id}"'
        logging.info(f"Executing JQL to get issue: {jql}")
        
        headers = {'Content-Type': 'application/json'}
        jql_encoded = urllib.parse.quote(jql)
        url = f"{self.url}/rest/api/3/search?jql={jql_encoded}"
        
        r = requests.get(url, headers=headers, auth=(self.username, self.apitoken), verify=False)
        if r.status_code == 200:
            data = r.json()
            issues = data.get('issues', [])
            if issues:
                custom_fields = self.get_custom_fields()
                id_field = custom_fields.get('Id')
                # Filter issues: only return the one that has no dot in the Id (i.e., the parent)
                for issue in issues:
                    issue_id_value = issue['fields'].get(id_field, "")
                    # Only consider issues where the custom field exactly equals ttp_id and has no dot.
                    if '.' not in issue_id_value and issue_id_value == ttp_id:
                        logging.info(f"Found parent issue for {ttp_id}: {issue['key']}")
                        return issue
                logging.info(f"No parent issue found for {ttp_id} among returned issues.")
        else:
            logging.error(f"[!] Error searching for issue by TTP: {r.text}")
        return None


