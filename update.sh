# stop server
screen -X -S pycraft-server quit
echo "stopped server"

# update server
git pull

# stop clients
pm2 stop pycraft-client-2 -s
pm2 stop pycraft-client-4 -s
echo "stopped clients"

# update clients
npm run update --prefix /home/networkexception/projects/minecraft/pycraft-client-2
npm run update --prefix /home/networkexception/projects/minecraft/pycraft-client-4

# start server
/home/networkexception/projects/minecraft/pycraft-server/run.sh

# start clients
pm2 start pycraft-client-2 -s
pm2 start pycraft-client-4 -s
echo "started clients"

