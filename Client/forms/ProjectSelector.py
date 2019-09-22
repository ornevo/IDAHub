from idaapi import Form, warning
import requests
import jwt
import shared
class ProjectSelector(Form):
	def __init__(self, project_list):
		self.invert = False
		project_list += ["-1 : Draft"]
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
			shared.PROJECT_ID = self._project_list[self.GetControlValue(self.iProject)].split(" ")[0]
			return 1
		else:
			return 1
