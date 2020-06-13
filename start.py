from __future__ import print_function

import asyncio
import json

from autobahn.asyncio.websocket import WebSocketServerProtocol, WebSocketServerFactory

from minecraft import authentication
from minecraft.networking.connection import Connection
from minecraft.networking.packets import Packet, serverbound, ChatMessagePacket, PlayerListItemPacket
from minecraft.networking.packets.clientbound.play import PlayerListHeaderAndFooterPacket

connections = dict()


class WebSocketServer(WebSocketServerProtocol):
    username: str = ""

    def onConnect(self, request):
        print("Client connecting: {0}".format(request.peer))

    def onOpen(self):
        print("WebSocket connection open.")

    def sendPacket(self, packet: Packet):
        if type(packet) is ChatMessagePacket:
            data = {"type": "ChatMessagePacket", "packet": packet.json_data}

            self.sendMessage(json.dumps(data, ensure_ascii=False).encode('utf8'), isBinary=False)

        if type(packet) is PlayerListHeaderAndFooterPacket:
            data = {"type": "PlayerListHeaderAndFooterPacket", "packet":
                {"header": packet.header, "footer": packet.footer}}

            self.sendMessage(json.dumps(data, ensure_ascii=False).encode('utf8'), isBinary=False)

        if type(packet) is PlayerListItemPacket:
            for action in packet.actions:
                if type(action) is PlayerListItemPacket.AddPlayerAction:
                    data = {"type": "AddPlayerAction", "packet": {
                        "uuid": action.uuid,
                        "name": action.name,
                        "gamemode": action.gamemode,
                        "ping": action.ping,
                        "displayName": action.display_name
                    }}

                    self.sendMessage(json.dumps(data, ensure_ascii=False).encode('utf8'), isBinary=False)

                if type(action) is PlayerListItemPacket.RemovePlayerAction:
                    data = {"type": "RemovePlayerAction", "packet": {
                        "uuid": action.uuid
                    }}

                    self.sendMessage(json.dumps(data, ensure_ascii=False).encode('utf8'), isBinary=False)

                if type(action) is PlayerListItemPacket.UpdateDisplayNameAction:
                    data = {"type": "UpdateDisplayNameAction", "packet": {
                        "uuid": action.uuid,
                        "displayName": action.display_name
                    }}

                    self.sendMessage(json.dumps(data, ensure_ascii=False).encode('utf8'), isBinary=False)

                if type(action) is PlayerListItemPacket.UpdateLatencyAction:
                    data = {"type": "UpdateLatencyAction", "packet": {
                        "uuid": action.uuid,
                        "ping": action.ping
                    }}

                    self.sendMessage(json.dumps(data, ensure_ascii=False).encode('utf8'), isBinary=False)

    def onMessage(self, payload, isBinary):
        if not isBinary:
            message = json.loads(payload.decode('utf8'))

            if message["type"] == "login":
                try:
                    if message["username"] in connections and message["password"] == connections[message["username"]]["password"]:
                        connections[message["username"]]["connection"].register_packet_listener(self.sendPacket, Packet, early=True)

                        self.username = message["username"]

                        print("Resuming session as " + connections[message["username"]]["auth_token"].username + " on " + message["host"])
                        return

                    print("Trying to log in as " + message["username"] + " on " + message["host"] + ":" + message["port"])

                    auth_token = authentication.AuthenticationToken()
                    auth_token.authenticate(message["username"], message["password"])

                    connection = Connection(message["host"], int(message["port"]), auth_token=auth_token)
                    connection.register_packet_listener(self.sendPacket, Packet, early=True)
                    connection.connect()

                    connections[message["username"]] = {
                        "password": message["password"],
                        "host": message["host"],
                        "port": message["port"],
                        "auth_token": auth_token,
                        "connection": connection
                    }

                    self.username = message["username"]

                    print("Started new session as " + auth_token.username + " on " + message["host"])

                except Exception as e:
                    print("Error while logging in: " + repr(e))
                    self.sendMessage(("Error while logging in: " + repr(e)).encode('utf8'), False)
                    self._closeConnection()

            elif message["type"] == "respawn":
                packet = serverbound.play.ClientStatusPacket()
                packet.action_id = serverbound.play.ClientStatusPacket.RESPAWN
                connections[self.username]["connection"].write_packet(packet)

            elif message["type"] == "chat":
                packet = serverbound.play.ChatPacket()
                packet.message = message["message"]
                connections[self.username]["connection"].write_packet(packet)

            elif message["type"] == "disconnect":
                connections[self.username]["connection"].disconnect()
                connections.pop(self.username)
                self._closeConnection()

    def onClose(self, wasClean, code, reason):
        connections[self.username]["connection"].early_packet_listeners.clear()

        print("Cleared registered listeners")

        print("WebSocket connection closed: {0}".format(reason))


if __name__ == '__main__':
    factory = WebSocketServerFactory("ws://127.0.0.1:9000")
    factory.protocol = WebSocketServer

    loop = asyncio.get_event_loop()
    coro = loop.create_server(factory, '0.0.0.0', 9000)
    server = loop.run_until_complete(coro)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        loop.close()
