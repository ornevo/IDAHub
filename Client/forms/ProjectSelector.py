from idaapi import Form, warning
import idc
import requests
import json
import jwt
import shared
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
					data = json.loads(requests.get("{0}/{1}".format(shared.BASE_URL, shared.GET_PROJECT_HEADER), headers = headers).content)
					contributors = data["contributors"]
					shared.MASTER_PAUSE_HOOK = True
					for cont in contributors:
						if cont["id"] == shared.USERID:
							shared.MASTER_PAUSE_HOOK = False
							shared.PAUSE_HOOK = True
							break
					shared.PROJECT_ID = data["id"]
				except Exception:
					warning("Cant get project information")
					return 0
			else:
				shared.PROJECT_ID = self._project_list[self.GetControlValue(self.iProject)].split(" ")[0]
			return 1
		else:
			return 1
