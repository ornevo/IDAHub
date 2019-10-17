from idaapi import Form, warning
import idc
import ida_nalt
import ida_pro
import requests
import json
import jwt
import shared
import constants
class ProjectSelector(Form):
	def __init__(self, project_list):
		self.invert = False
		project_list += ["Select public project"]
		self._project_list = project_list
		Form.__init__(self, r"""STARTITEM {id:iProject}
BUTTON CANCEL Cancel
Project selector form
{FormChangeCb}
<##Select your working project:{iProject}>
""", {
			'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
			'iProject': Form.DropdownListControl(project_list)
		})
	def OnFormChange(self, fid):
		if fid == -2: # click on ok
			print self._project_list[self.GetControlValue(self.iProject)]
			if self._project_list[self.GetControlValue(self.iProject)] == "Select public project":
				project_id = idc.AskStr("", "Project id:")
				try:
					headers = {"Authorization" : "Bearer {0}".format(shared.USER_TOKEN)}
					data = json.loads(requests.get("{0}/{1}".format(shared.BASE_URL, constants.GET_PROJECT_HEADER.format(project_id)), headers = headers).content)
					hash_of_program = data["body"]["hash"]
					warning("{0} {1}".format(ida_nalt.retrieve_input_file_sha256().lower(), hash_of_program))
					if ida_nalt.retrieve_input_file_sha256().lower() != hash_of_program:
						pass
						#warning("Wrong hash of program, exiting now")
						#ida_pro.qexit(1)
					contributors = data["body"]["contributors"]
					shared.MASTER_PAUSE_HOOK = True
					for cont in contributors:
						if cont["id"] == shared.USERID:
							shared.MASTER_PAUSE_HOOK = False
							shared.PAUSE_HOOK = True
							break
					shared.PROJECT_ID = data["body"]["id"]
				except Exception as e:
					warning("Cant get project information: " + str(e))
					return 0
			else:
				headers = {"Authorization" : "Bearer {0}".format(shared.USER_TOKEN)}
				data = json.loads(requests.get("{0}/{1}".format(shared.BASE_URL, constants.GET_PROJECT_HEADER.format(self._project_list[self.GetControlValue(self.iProject)].split(" ")[0])), headers = headers).content)
				warning(str(data))
				hash_of_program = data["body"]["hash"]
				warning("{0}----{1}".format(ida_nalt.retrieve_input_file_sha256().lower(), hash_of_program))
				if ida_nalt.retrieve_input_file_sha256().lower() != hash_of_program:
					pass
					#warning("Wrong hash of program, exiting now")
					#ida_pro.qexit(1)
				shared.PROJECT_ID = self._project_list[self.GetControlValue(self.iProject)].split(" ")[0]
			return 1
		else:
			return 1
