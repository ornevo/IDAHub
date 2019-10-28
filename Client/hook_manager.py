import constants
import time
import idaapi
import struct
import subprocess
import ida_enum
from all_events import *
import idc
import ida_bytes
from ida_idp import IDB_Hooks, IDP_Hooks
from ida_kernwin import UI_Hooks, View_Hooks
import ida_hexrays
import ida_typeinf
import ida_nalt
import ida_auto
import ida_struct
import shared
last_ea = None
def log(data):
	if shared.LOG:
		print("[IReal] " + data)
	else:
		pass

class CursorChangeHook(ida_kernwin.View_Hooks):
	def view_loc_changed(self, view, now, was):
		if now.plce.toea() != was.plce.toea():
			pass_to_manager(IDACursorEvent(now.plce.toea(), shared.USERNAME))

class ClosingHook(idaapi.UI_Hooks):
	def __init__(self):
		idaapi.UI_Hooks.__init__(self)

	def term(self):
		shared.PAUSE_HOOK = True
		log("Exit IDB")
		pass_to_manager(ExitIDBEvent())
		return idaapi.UI_Hooks.term(self)
	
	def ready_to_run(self):
		shared.PAINTER.ready_to_run()

	def get_ea_hint(self, ea):
		return shared.PAINTER.get_ea_hint(ea)

	def widget_visible(self, widget):
		shared.PAINTER.widget_visible(widget)

class LiveHookIDP(ida_idp.IDP_Hooks):
	def ev_undefine(self, ea):
		if not shared.PAUSE_HOOK:
			pass_to_manager(UndefineDataEvent(ea))
		return ida_idp.IDP_Hooks.ev_undefine(self, ea)

	def	ev_newfile(self, fname):	
		log("START")
		pass_to_manager(StartIDAEvent())
		if not shared.MASTER_PAUSE_HOOK:
			shared.PAUSE_HOOK = not ida_auto.auto_is_ok()
		return ida_idp.IDP_Hooks.ev_newfile(self, fname)

	def ev_oldfile(self, fname):
		log("START")
		pass_to_manager(StartIDAEvent())
		if not shared.MASTER_PAUSE_HOOK:
			shared.PAUSE_HOOK = not ida_auto.auto_is_ok()
		return ida_idp.IDP_Hooks.ev_oldfile(self, fname)

	def ev_get_bg_color(self, color,ea):
		value = shared.PAINTER.get_bg_color(ea)
		if value is not None:
			ctypes.c_uint.from_address(long(color)).value = value
			return 1
		return 0
class LiveHook(ida_idp.IDB_Hooks):
	def closebase(self):
		log("Exit IDB")
		pass_to_manager(ExitIDBEvent())
		shared.PAUSE_HOOK = True
		
	def renamed(self, ea, new_name, is_local_name):		
		if not shared.PAUSE_HOOK and (not new_name.startswith("loc_") and not new_name.startswith("sub_") and not new_name.startswith("unk_") and 
									not new_name.startswith("dword_") and not new_name.startswith("word_") and not new_name.startswith("qword_") and not new_name.startswith("byte_")) :
			log("Name changed: {0}  = {1} | {2}".format(hex(ea),new_name, is_local_name))
			flags_of_address = idc.GetFlags(ea)
			if idaapi.isFunc(flags_of_address):
				pass_to_manager(ChangeFunctionNameEvent(ea, new_name))
			elif flags_of_address != 0:
				if is_local_name:
					pass_to_manager(ChangeLabelNameEvent(ea, new_name))
				else:
					pass_to_manager(ChangeGlobalVariableNameEvent(ea, new_name,not is_local_name))
		return ida_idp.IDB_Hooks.renamed(self,ea,new_name,is_local_name)

	def changing_cmt(self, ea, repeatable_cmt, newcmt):
		if not shared.PAUSE_HOOK:
			log("New comment: {0} {1}".format(hex(ea), newcmt))
			pass_to_manager(ChangeCommentEvent(ea, newcmt, "repetable" if repeatable_cmt else "regular", 0))
		return ida_idp.IDB_Hooks.changing_cmt(self,ea,repeatable_cmt, newcmt)

	def func_added(self,pfn):
		if not shared.PAUSE_HOOK:
			log("New function")
			pass_to_manager(NewFunctionEvent(int(pfn.start_ea), int(pfn.end_ea)))
		return ida_idp.IDB_Hooks.func_added(self, pfn)

	def set_func_start(self, pfn, new_start):
		if not shared.PAUSE_HOOK:
			log("New start: {0}".format(new_start))
			pass_to_manager(ChangeFunctionStartEvent(pfn.start_ea, new_start))
		return ida_idp.IDB_Hooks.set_func_start(self, pfn, int(new_start))

	def set_func_end(self, pfn, new_end):
		if not shared.PAUSE_HOOK:
			log("New end: {0}".format(new_end))
			pass_to_manager(ChangeFunctionEndEvent(pfn.start_ea, new_end))
		return ida_idp.IDB_Hooks.set_func_end(self, pfn, new_end)

	def struc_created(self, struc_id):
		if not shared.PAUSE_HOOK:
			log("New struct")
			pass_to_manager(CreateStructEvent(ida_struct.get_struc_name(struc_id), struc_id))
		return ida_idp.IDB_Hooks.struc_created(self, struc_id)

	def renaming_struc(self, sid, oldname, newname):
		if not shared.PAUSE_HOOK:
			log("Rename struct")
			pass_to_manager(ChangeStructNameEvent(oldname, newname))
		return ida_idp.IDB_Hooks.renaming_struc(self, sid, oldname, newname)
	
	def struc_member_created(self, sptr, mptr):
		if not shared.PAUSE_HOOK:
			tinfo = ida_typeinf.tinfo_t()
			ida_hexrays.get_member_type(mptr, tinfo)
			member_type = "unkown"
			if tinfo.get_size() == 1:
				member_type = 'db'
			elif tinfo.get_size() == 2:
				member_type = 'dw'
			elif tinfo.get_size() == 4:
				member_type = 'dd'
			elif tinfo.get_size() == 8:
				member_type = 'dq'
			else:
				pass
			pass_to_manager(CreateStructVariableEvent(ida_struct.get_struc_name(sptr.id), mptr.get_soff(), member_type, ida_struct.get_member_name(mptr.id)))
		return ida_idp.IDB_Hooks.struc_member_created(self, sptr, mptr)
		
	def renaming_struc_member(self, sptr, mptr, newname):
		if not shared.PAUSE_HOOK:
			log("Rename struct member")
			pass_to_manager(ChangeStructItemEvent(ida_struct.get_struc_name(sptr.id), mptr.get_soff(), newname))
		return ida_idp.IDB_Hooks.renaming_struc_member(self, sptr, mptr, newname)

	def struc_member_deleted(self, sptr, member_id, offset):
		if not shared.PAUSE_HOOK:
			log("Remove struct memeber")
			pass_to_manager(DeleteStructVariableEvent(ida_struct.get_struc_name(sptr.id), offset))
		return ida_idp.IDB_Hooks.struc_member_deleted(self, sptr, member_id, offset)
		
	def struc_deleted(self, struc_id):
		if not shared.PAUSE_HOOK:
			log("Remove struct")
			pass_to_manager(DeleteStructEvent(struc_id))
		return 0

	def changing_struc_member(self, sptr, mptr, flag, ti, nbytes):
		if not shared.PAUSE_HOOK:
			log("Changing struc member: {0} {1} {2} {3} {4}".format(sptr, mptr, flag, ti, nbytes))
			data_type = None
			if flag & ida_bytes.FF_BYTE:
				data_type = "db"
			elif flag & ida_bytes.FF_WORD:
				data_type = "dw"
			elif flag & ida_bytes.FF_DWORD:
				data_type = "dd"
			elif flag & ida_bytes.FF_QWORD:
				data_type = "dq"
			elif flag & ida_bytes.FF_STRUCT:
				data_type = ti.tid
			if data_type:
				pass_to_manager(ChangeStructItemTypeEvent(ida_struct.get_struc_name(sptr.id), mptr.get_soff(), data_type))
		return 0

	def changing_range_cmt(self, kind, a, cmt, repeatable):
		if not shared.PAUSE_HOOK:
			if kind == 1:
				log("Change range comment {0} {1} {2} {3}".format(kind, a.start_ea, cmt, repeatable))
				function_address = a.start_ea
				pass_to_manager(ChangeCommentEvent(function_address, cmt, "function", 0))
		return ida_idp.IDB_Hooks.changing_range_cmt(self, kind, a, cmt, repeatable)	

	def enum_created(self, id):
		if not shared.PAUSE_HOOK:
			log("Enum created: {0}".format(id))
			pass_to_manager(CreateEnumEvent(ida_enum.get_enum_name(id), id))
		return ida_idp.IDB_Hooks.enum_created(self, id)

	def renaming_enum(self, eid, is_enum, newname):
		if not shared.PAUSE_HOOK:
			log("Enum name changed {0} {1} {2}".format(eid, is_enum, newname))
			old_name = ida_enum.get_enum_name(eid)
			if is_enum:
				pass_to_manager(ChangeEnumNameEvent(old_name, newname))
			else:
				pass_to_manager(ChangeEnumMemberName(old_name, newname))
		return ida_idp.IDB_Hooks.renaming_enum(self, eid, is_enum, newname)

	def enum_member_created(self, id, cid):
		if not shared.PAUSE_HOOK:
			log("Enum memeber created: {0} {1}".format(id, cid))
			name = ida_enum.get_enum_name(id)
			enum_item_name = ida_enum.get_enum_member_name(cid)
			value = ida_enum.get_enum_member_value(cid)
			pass_to_manager(CreateEnumItemEvent(name, enum_item_name , value))
		return ida_idp.IDB_Hooks.enum_member_created(self, id, cid)

	def deleting_enum_member(self, id_of_struct, cid):
		if not shared.PAUSE_HOOK:
			log("Enum member deleted {0} {1}".format(id_of_struct, cid))
			name = ida_enum.get_enum_name(id_of_struct)
			value = ida_enum.get_enum_member_value(cid)
			serial = ida_enum.get_enum_member_serial(cid)
			bmask = ida_enum.get_enum_member_bmask(cid)
			pass_to_manager(DeleteEnumMemberEvent(name , value, serial, bmask))
		return ida_idp.IDB_Hooks.deleting_enum_member(self, id_of_struct, cid)

	def deleting_enum(self, id):
		if not shared.PAUSE_HOOK:
			log("Enum deleted")
			pass_to_manager(DeleteEnumEvent(ida_enum.get_enum_name(id)))
		return ida_idp.IDB_Hooks.enum_deleted(self, id)		

	def extra_cmt_changed(self, ea, line_idx, cmt):
		if not shared.PAUSE_HOOK:
			log("{0} {1}".format(line_idx, cmt))
			if line_idx / 1000 == 1:
				pass_to_manager(ChangeCommentEvent(ea, cmt, "anterior", line_idx))
			else:
				pass_to_manager(ChangeCommentEvent(ea, cmt, "posterior", line_idx))
		return ida_idp.IDB_Hooks.extra_cmt_changed(self, ea, line_idx, cmt)

	def ti_changed(self, ea, type, fnames):
		if not shared.PAUSE_HOOK:
			log("Ti changed: {0} {1} {2}".format(str(ea), str(type), str(fnames)))
			pass_to_manager(ChangeTypeEvent(ea, ida_typeinf.idc_get_type_raw(ea),is_make_data = False))
		return ida_idp.IDB_Hooks.ti_changed(self, ea, type, fnames)

	def make_data(self, ea, flags, tid, len):
		if not shared.PAUSE_HOOK:
			log("Make data: {0} {1} {2} {3}".format(ea, flags, tid, len))
			pass_to_manager(ChangeTypeEvent(ea, flags, tid, len, is_make_data= True))
		return ida_idp.IDB_Hooks.make_data(self, ea, flags, tid, len)
		
	def auto_empty_finally(self):
		log("auto finished")
		if not shared.MASTER_PAUSE_HOOK:
			shared.PAUSE_HOOK = False
		return 0
	
def pass_to_manager(ev):
	log("Pass to manager: " + str(ev))
	try:
		constants.send_data_to_window(shared.COMMUNICATION_MANAGER_WINDOW_ID, constants.SEND_DATA_TO_SERVER, ev.encode_to_json())
	except Exception as e:
		pass

class hook_manager(idaapi.UI_Hooks, idaapi.plugin_t):
	flags = idaapi.PLUGIN_HIDE | idaapi.PLUGIN_FIX
	comment = " "
	help = " "
	wanted_name = "Hooker"
	wanted_hotkey = ""
	def run(self, arg):
		pass

	def attach_to_menu(self):
		pass

	def register_actions(self):
		pass
		
	def init(self):
		msg("[IReal]: Init done\n")
		msg("[IReal]: Waiting for auto analysing\n")
		constants.create_general_config_file()
		constants.create_config_file()
		shared.BASE_URL = constants.get_data_from_config_file("server")
		shared.LOG = constants.get_data_from_config_file("log")
		
		if idc.GetIdbPath() and ida_auto.auto_is_ok():
			log("Start")
			if not shared.MASTER_PAUSE_HOOK:
				shared.PAUSE_HOOK = False
			
		else:
			shared.PAUSE_HOOK = True
	
		if shared.USERID != -1 and shared.IS_COMMUNICATION_MANAGER_STARTED: #started.
			if not shared.PAUSE_HOOK:
				pass_to_manager(StartIDAEvent())
			constants.send_data_to_window(shared.COMMUNICATION_MANAGER_WINDOW_ID, constants.CHANGE_PROJECT_ID, json.dumps({"project-id": shared.PROJECT_ID,"need-to-pull": shared.MASTER_PAUSE_HOOK}))
			constants.send_data_to_window(shared.COMMUNICATION_MANAGER_WINDOW_ID, constants.CHANGE_USER, json.dumps({"username":shared.USERNAME, "id": shared.USERID, "token": shared.USER_TOKEN}))
			constants.send_data_to_window(shared.COMMUNICATION_MANAGER_WINDOW_ID, constants.CHANGE_BASE_URL, json.dumps({"url": shared.BASE_URL}))
			
		self.idb_hook = LiveHook()
		self.ui_hook = ClosingHook()
		self.idp_hook = LiveHookIDP()
		self.view_hook = CursorChangeHook()
		self.idb_hook.hook()
		self.ui_hook.hook()
		self.idp_hook.hook()
		self.view_hook.hook()
		self.hook()
		
		return idaapi.PLUGIN_KEEP

	def term(self):
		try:
			constants.send_data_to_window(shared.COMMUNICATION_MANAGER_WINDOW_ID, constants.KILL_COMMUNICATION_MANAGER_MESSAGE_ID, None)
			time.sleep(1)
		except Exception as e:
			pass
		
		if self.idb_hook:
			self.idb_hook.unhook()
		if self.ui_hook:
			self.ui_hook.unhook()
		if self.idb_hook:
			self.idp_hook.unhook()
		self.unhook()
		
		

def PLUGIN_ENTRY():
	return hook_manager()
