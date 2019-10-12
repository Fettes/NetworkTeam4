import sys
from playground.network.packet import PacketType

def createFile():
    logFile = open('log.txt', 'w')
    logFile.write('Log File\n')


def saveInFile(packetData):
    sourceip = packetData.source
    sourceport = str(packetData.sourcePort)
    destinationip = packetData.destination
    destinationport = str(packetData.destinationPort)
    packet = packetData.data
    addcontent(packet)
    with open('log.txt', 'a') as f:
        f.write("------------------------------\n")
        f.write(sourceip + "\n")
        f.write(sourceport + "\n")
        f.write(destinationip + "\n")
        f.write(destinationport + "\n")



def addcontent(packet):
    deserializer = PacketType.Deserializer()
    deserializer.update(packet)
    for packet in deserializer.nextPackets():
        print(packet)
        with open('log.txt', 'a') as f:
            f.write(str(packet))




