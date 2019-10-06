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
    with open('log.txt', 'a') as f:
        f.write("------------------------------\n")
        f.write(sourceip + "\n")
        f.write(sourceport + "\n")
        f.write(destinationip + "\n")
        f.write(destinationport + "\n")
    addcontent(packet)


def addcontent(packet):
    deserializer = PacketType.Deserializer()
    deserializer.updata(packet)
    for pkt in deserializer.nextPackets():
        with open('log.txt', 'a') as f:
            f.write(pkt)




