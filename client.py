from playground.network.packet import PacketType
import playground, time
import getpass, os, asyncio
import sys

from escape_room_packets import *




def game_next_input(transport):
    input = sys.stdin.readline().strip()
    command_packet = create_game_command(input)
    transport.write(command_packet.__serialize__())
    flush_output(">> ", end='')

def flush_output(*args, **kargs):
    print(*args, **kargs)
    sys.stdout.flush()

class EchoClientProtocol(asyncio.Protocol):
    def __init__(self, loop):
        self.flag = 0
        self.loop = asyncio.get_event_loop()
        self.deserializer = PacketType.Deserializer()

    def connection_made(self, transport):
        print("Connected to {}".format(transport.get_extra_info("peername")))
        self.transport = transport

        self.loop.add_reader(sys.stdin, game_next_input, transport)
        packet = create_game_init_packet("tfeng7")
        self.transport.write(packet.__serialize__())

    def data_received(self, data):
        self.deserializer.update(data)
        for clientPacket in self.deserializer.nextPackets():
            if isinstance(clientPacket, GameRequirePayPacket):
                unique_id, account, amount = process_game_require_pay_packet(clientPacket)
                print(unique_id)
                print(account)
                print(amount)
                self.loop.create_task(self.CreatePayment(account, amount, unique_id))

            if isinstance(clientPacket, GameResponsePacket):
                res_temp = clientPacket.response
                print("Response:\n", clientPacket.response, "\n")


    async def CreatePayment(self, account, amount, unique_id):
        result = await paymentInit("tfeng7_account", account, amount, unique_id)
        print(result)
        receipt, receipt_sig = result
        game_packet = create_game_pay_packet(receipt, receipt_sig)
        self.transport.write(game_packet.__serialize__())

    def connection_lost(self, exc):
        print('The server closed the connection')
        print('Stop the event loop')
        self.loop.stop()


if __name__ == "__main__":
    ip_addr, port = sys.argv[1:2]
    loop = asyncio.get_event_loop()
    loop.set_debug(enabled=True)
    from playground.common.logging import EnablePresetLogging, PRESET_DEBUG
    #
    EnablePresetLogging(PRESET_DEBUG)
    coro = playground.create_connection(lambda: EchoClientProtocol(loop), ip_addr, port)
    # coro = loop.create_connection(lambda: EchoClientProtocol(loop), 'localhost', 1024)
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()
