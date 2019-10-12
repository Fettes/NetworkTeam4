import asyncio
import playground
from playground.network.packet import PacketType

import sys
from Game_Bank.payProcedure import *
from Game_Bank.packet import *


class EchoClient(asyncio.Protocol):
    def __init__(self):
        pass

    def connection_made(self, transport):
        self.loop = asyncio.get_event_loop()
        self.loop.add_reader(sys.stdin, self.game_next_input)
        self.transport = transport

        self.command_packet = create_game_init_packet("tfeng7")
        self.transport.write(self.command_packet.__serialize__())

    def data_received(self, data):
        d = PacketType.Deserializer()
        d.update(data)
        for gamePacket in d.nextPackets():
            if isinstance(gamePacket, GameRequirePayPacket):
                print(gamePacket.amount)
                unique_id, account, amount = process_game_require_pay_packet(gamePacket)
                print(unique_id)
                print(account)
                print(amount)
                self.loop.create_task(self.Create_Payment(account, amount, unique_id))
            elif isinstance(gamePacket, GameResponsePacket):
                print(gamePacket.response)
                self.flush_output(">> ", end='')



    async def Create_Payment(self, account, amount, unique_id):
        result = await paymentInit("tfeng7_account", account, amount, unique_id)
        print(result)

        receipt, receipt_sig = result
        game_packet = create_game_pay_packet(receipt, receipt_sig)
        self.transport.write(game_packet.__serialize__())

    def flush_output(self, *args, **kargs):
        print(*args, **kargs)
        sys.stdout.flush()

    def game_next_input(self):
        input = sys.stdin.readline().strip()
        self.command_packet = create_game_command(input)
        self.transport.write(self.command_packet.__serialize__())


if __name__ == "__main__":
    loop = asyncio.get_event_loop()

    coro = playground.create_connection(EchoClient, '20194.0.1.1', 8666)

    # loop.set_debug(enabled=True)
    # from playground.common.logging import EnablePresetLogging, PRESET_DEBUG
    # EnablePresetLogging(PRESET_DEBUG)
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()
