from attackcti import attack_client
import json, sys, argparse, traceback
from getpass import getpass
from lib.jirahandler import JiraHandler
from argparse import RawTextHelpFormatter
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

class Attack2Jira:

    jirahandler = None

    def __init__(self, url, username, password):

        jirahandler = JiraHandler(url, username, password)
        self.jirahandler = jirahandler

    def get_attack_techniques(self):
    # Deprecated, keeping just in case

        try:
            print ("[*] Obtaining ATT&CK's techniques...")
            client = attack_client()
            all_enterprise = client.get_enterprise()
            techniques = []
            for technique in all_enterprise['techniques']:
                tech= json.loads(technique.serialize())
                # avoid bringing in the revoked techniques
                if not 'revoked' in tech.keys():
                    techniques.append(tech)
            print ("[!] Done!")
            return techniques

        except:
            traceback.print_exc(file=sys.stdout)
            print ("[!] Error connecting to Att&ck's API !")
            return


    def create_attack_techniques(self, key):

        techniques = self.get_attack_techniques()
        jiraclient = self.jirahandler

        print ("[*] Creating Jira issues for ATT&CK's techniques...")
        for technique in techniques:
            try:

                custom_fields=self.jirahandler.get_custom_fields()

                name = technique['name']
                id = technique['external_references'][0]['external_id']
                url = technique['external_references'][0]['url']
                tactic = technique['kill_chain_phases'][0]['phase_name']
                description = technique['description']

                # some techniques dont have the field populated
                if 'x_mitre_data_sources' in technique.keys(): datasources = technique['x_mitre_data_sources']
                else: datasources = []

                ds_payload=[]
                for ds in datasources: ds_payload.append({'value':ds.title()})

                issue_dict = {
                    "fields": {
                        "project": {"key": key},
                        "summary":  name + " (" + id + ")",
                        #"summary": name,
                        "description": description,
                        "issuetype": {"name": "Task"},
                        custom_fields['id']: id,
                        custom_fields['tactic']: {'value': tactic},
                        custom_fields['maturity']: {'value':'Not Tracked'},
                        custom_fields['url']: url,
                        custom_fields['datasources']: ds_payload,
                        # "customfield_11050": "Value that we're putting into a Free Text Field."
                    }
                }
                jiraclient.create_issue(issue_dict,id)


            except Exception as ex:
                print ("\t[*] Could not create ticket for " + id)
                print(ex)
                traceback.print_exc(file=sys.stdout)
                pass
                #print(ex)
                #sys.exit()

        print ("[*] Done!")

    def create_attack_techniques_and_subtechniques(self, key):
        jiraclient = self.jirahandler
        techniques = self.get_attack_techniques()
        sorted_techniques = sorted(techniques, key=lambda k: k['external_references'][0]['external_id'])
        print("[*] Creating Jira issues for ATT&CK's techniques...")
        for technique in sorted_techniques:
            try:
                custom_fields = self.jirahandler.get_custom_fields()
                name = technique['name']
                ttp_id = technique['external_references'][0]['external_id']
                url = technique['external_references'][0]['url']
                tactic = technique['kill_chain_phases'][0]['phase_name']
                description = technique['description']
                datasources = technique.get('x_mitre_data_sources', [])
                ds_payload = [{'value': ds.title()} for ds in datasources]

                if self.jirahandler.issue_exists(ttp_id, key):
                    logging.info(f"Skipping technique {ttp_id} as it already exists.")
                    continue
                else:
                    # Branch between techniques and sub-techniques
                    if not technique['x_mitre_is_subtechnique']:
                        issue_dict = {
                            "fields": {
                                "project": {"key": key},
                                "summary": name,
                                "description": description,
                                "issuetype": {"name": "Task"},
                                custom_fields['Id']: ttp_id,
                                custom_fields['Tactic']: {'value': tactic},
                                custom_fields['Maturity']: {'value': 'Not Tracked'},
                                custom_fields['Url']: url,
                                custom_fields['Datasources']: ds_payload,
                            }
                        }
                        parent_id = jiraclient.create_issue(issue_dict, ttp_id)
                        # Optionally store parent_id mapping if needed for sub-techniques
                    else:
                        # For sub-techniques, you may also want to check existence or
                        # associate with an already existing parent
                        parent_ttp_id = ttp_id.split('.')[0]
                        logging.info(f"Derived parent TTP id: {parent_ttp_id} for sub-technique {ttp_id}")
                        parent_issue = self.jirahandler.get_issue_by_ttp(parent_ttp_id, key)
                        if not parent_issue:
                            logging.error(f"Parent issue for TTP {parent_ttp_id} not found. Skipping sub-technique {ttp_id}.")
                            continue
                        parent_issue_key = parent_issue['key']
                        logging.info(f"Found parent issue: {parent_issue_key} for sub-technique {ttp_id}")
                        issue_dict = {
                            "fields": {
                                #"parent": {"id": parent_id['id']},
                                "parent": {"id": parent_issue['id']},
                                "project": {"key": key},
                                "summary": name,
                                "description": description,
                                "issuetype": {"name": "Sub-task"},
                                custom_fields['Id']: ttp_id,
                                custom_fields['Tactic']: {'value': tactic},
                                custom_fields['Maturity']: {'value': 'Not Tracked'},
                                custom_fields['Url']: url,
                                custom_fields['Datasources']: ds_payload,
                                #custom_fields['Sub-Technique of']: jiraclient.url + "/browse/" + parent_id['key'],
                                custom_fields['Sub-Technique of']: jiraclient.url + "/browse/" + parent_issue_key,
                            }
                        }
                        ret_id = jiraclient.create_issue(issue_dict, ttp_id)
                        if ret_id:
                            logging.info(f"Successfully created Jira issue for sub-technique {ttp_id}")
                        else:
                            logging.error(f"Failed to create Jira issue for sub-technique {ttp_id}")
            except Exception as ex:
                logging.error(f"Error creating Jira issue for {ttp_id}: {str(ex)}", exc_info=True)
                print(ex)
                traceback.print_exc(file=sys.stdout)
                pass
        print("[*] Done!")


    def generate_json_layer(self, hideDisabled):
        VERSION = "2.2"
        NAME = "Attack2Jira"
        DESCRIPTION = "Attack2Jira"
        DOMAIN = "mitre-enterprise"
        GRADIENT = {
                "colors": [
                    "#DCDCDC",
                    "#03ad03"],
            }

        layer_json = {
            "domain": DOMAIN,
            "name": NAME,
            "description": DESCRIPTION,
            "gradient": GRADIENT,
            "version": VERSION,
            "hideDisabled": hideDisabled,
            "techniques": [ ]
        }

        # Define your colors here
        not_tracked_color = "#DCDCDC"
        shade_0_color = "#e1fce1" # lightest green
        shade_1_color = "#81fc81" # lighter green
        shade_2_color = "#49fc49" # green 
        shade_3_color = "#03ad03" # darker green


        res_dict=self.jirahandler.get_technique_maturity()
        for key in res_dict.keys():
            enabled = True
            #print (key +" "+ res_dict[key]['value'])
            if res_dict[key]['value'] == "Not Tracked":
                enabled=False
                color = not_tracked_color
            elif res_dict[key]['value'] == "Initial":
                color = shade_0_color 
            elif res_dict[key]['value'] == "Defined":
                color = shade_1_color 
            elif res_dict[key]['value'] == "Resilient":
                color = shade_2_color 
            elif res_dict[key]['value'] == "Optimized":
                color = shade_3_color 
            
            technique = {
            "techniqueID": key,
            "enabled": enabled,
            "color": color
            }
            layer_json["techniques"].append(technique)

        print ("[*] Outputting JSON layer attack2jira.json")
        with open('attack2jira.json', 'w', encoding='utf-8') as f:
            json.dump(layer_json, f, ensure_ascii=False, indent=4)
        

    def set_up_jira_automated(self, project, key):

        self.jirahandler.create_project(project, key)
        self.jirahandler.create_custom_fields()
        self.jirahandler.add_custom_field_options()
        self.jirahandler.add_custom_fields_to_screen(key)
        self.jirahandler.hide_unwanted_fields(key)
        self.create_attack_techniques_and_subtechniques(key)


def main():

    parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter)
    parser.add_argument('-url', dest = 'url', type=str, help= 'Url of Jira instance', default="")
    parser.add_argument('-u', dest = 'user', type=str, help='Username', default="")
    parser.add_argument('-a', dest='action', type=str, default="", help='action to execute\nTwo supported:\n\'initialize\' will create the JIRA entities. \n\'export\' will export the JSON layer.')
    parser.add_argument('-p', dest = 'project', type=str, help='Name of the Jira project to create.', default="Mitre Attack Framework")
    parser.add_argument('-k', dest = 'key', type=str, help='Project Key.(default=\'ATTACK\')', default="ATTACK")
    parser.add_argument('-hide', help='If set, \'Not Tracked\' techniques will be hidden',action='store_true')
    parser.add_argument('-update', dest = 'update', action='store_true', help='Skip project creation and only update with new TTPs.')
    results = parser.parse_args()

    url= results.url
    user= results.user
    action = results.action
    hideDisabled = results.hide
    project = results.project
    key = results.key

    if (url and user and action):
        pswd = getpass('Jira API Token for '+user+":")

        if (action == "initialize"):
            attack2jira = Attack2Jira(url, user, pswd)
            if results.update:
                # Skip project creation; update with new TTPs only
                logging.info("Update mode enabled: Skipping project creation.")
                attack2jira.create_attack_techniques_and_subtechniques(key)
            else:
                attack2jira.set_up_jira_automated(project, key)

        if (action == "export"):
            attack2jira = Attack2Jira(url, user, pswd)
            attack2jira.generate_json_layer(hideDisabled)
    else:
        parser.print_help()

if __name__ == '__main__':

    try:
       main()


    except KeyboardInterrupt:
        print("\n")
        print ("[!] Exiting attack2jira")
        sys.exit()