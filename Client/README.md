# IReal  
IReal is the real time client plugin for IDAHub, to install IReal, you need to drug all the files to the 'plugins' directory in the IDA folder.  
you need to install the requirments for this to work.

## How to use
Add the server public key, to the key.pub file.
Run this script install_key.py to install the public key of the server
You need to install all the dependencies, you can do that by installing the 'requirements' file, the second step is to drag the plugin files into the 'plugin' directory at IDA installationg path.  
When you will do this 2 steps, you will need to open IDA, when you will open IDA you will need to insert server address, after you will insert the server address, you will be asked with username and password.  
Great now you are logged in, now just start working on a new project.
Also you need to install python and make sure that it is in the PATH.
## Documentation

So how it is all works together?, We can split the client into parts, we have the hook manager, authenticator, integrator, and the communication manager, we will address each part and how it works in this document.

### Hook manager

The hook manager, is responsible to hook all the client events, like changing comment or creating a new function, the hook manager is creating the event and storing its data, than it is sending the event to the communication manager, the hook manager is using the `idapython` hook, like `ida_kernwin.IDB_HOOK`.

### Authenticator

The authenticator is responsible to log into the `IDAHub` and choose the project you want to work on, it is responsible to create all the authentication forms and the project selection forms.

### Integrator

The integrator is getting all the new data from the server, and integrate it into the client.

### Communication manager

The communicator manager is responsible for the most of the communication between the `IDAHub` and the client, it is requesting the new data, and sending new data.

The communication manager send and receive data, using windows messages, the communication manager is creating an hidden window, and register message callback for it, the message we are using is the copy data message, named: `WM_COPYDATA`. 

Each window has its own id, we have to pass the window id of the integrator, to the communication manager, we do that by passing the integrator window id by argument when creating the communication manager process, than we send back windows message with the communication manager id to the integrator window.