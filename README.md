# IDAHub
This project is a platform for community-driven, collaborative reverse engineering using the IDA Pro tool.

The projects has three components:
- The client, which is an IDA plugin written in python in `./Client`.
- The server, which is a node/express/mongo stack server in `./Server/src`.
- The web-client, which presents users with project and account managment interface in `./Server/src/views/web-client`. 

Created by [Orr Shachaff](https://github.com/lolblat), Jonathan Suzy and [Or Nevo](https://github.com/ornevo). 

© and stuff.

## Dev Notes
### Merging to updated-server branch
The `updated-server` branch is the branch containing the code to run on the server directly. This branch should be updated against `master` regulary, whenever master is progressing, except for a exceptions:

1. `Server/bin/www` file should (usually) be kept as in the `updated-server` branch.
2. `Client/key.pub` contains the server's public key, should not change.
3. `Server/package.json`, which contains some slightly different scripts for production.
4. `Server/src/views/web-client/src/shared/API.js`. This **should** change as master does, but always remember to keep the `const URL = ...` at the beginning pointing to the remote `https://idahub.live` domain in the `updated-server` branch, since it is `https://localhost` in the `master` branch.

So, to merge master into it, do the following:
```bash
git pull
git checkout updated-server
git merge --no-ff --no-commit master
git reset HEAD Server/bin/www
git checkout -- Server/bin/www
git reset HEAD Client/key.pub
git checkout -- Client/key.pub
git reset HEAD Server/package.json
git checkout -- Server/package.json
git reset HEAD Server/src/views/web-client/src/shared/API.js
git checkout -- Server/src/views/web-client/src/shared/API.js
git commit -m "Merged master into updated-server"
```

### Updating the server
After merging master into the server as described above, connect to the server via ssh and run:
```bash
cd ~/IDAHub/Server
git pull
sudo npm run stop
sudo npm run build-client
sudo npm run build
sudo npm run start
```