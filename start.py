from __future__ import print_function

import asyncio
import json

from autobahn.asyncio.websocket import WebSocketServerProtocol, WebSocketServerFactory

from minecraft import authentication
from minecraft.authentication import AuthenticationToken
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
            self.sendMessage(packet.json_data.encode('utf8'), False)

        if type(Packet) is PlayerListHeaderAndFooterPacket:
            data = {"header": packet.header, "footer": packet.footer}

            self.sendMessage(json.dumps(data).encode("utf8"), True)

        if type(Packet) is PlayerListItemPacket:
            self.sendMessage(("%s" % packet).encode("utf8"), True)

    def onMessage(self, payload, isBinary):
        if not isBinary:
            message = json.loads(payload.decode('utf8'))

            if message["type"] == "login":
                try:
                    if message["username"] in connections and message["password"] == connections[message["username"]]["password"]:
                        connections[message["username"]]["connection"].register_packet_listener(self.sendPacket, Packet, early=True)

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
        connections[self.username]["connection"].packet_listeners.clear()
        connections[self.username]["connection"].outgoing_packet_listeners.clear()
        connections[self.username]["connection"].early_packet_listeners.clear()
        connections[self.username]["connection"].early_outgoing_packet_listeners.clear()

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
