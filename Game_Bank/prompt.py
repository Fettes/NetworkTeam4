import random
import sys
import time

CURSOR_UP_ONE = '\x1b[1A'
ERASE_LINE = '\x1b[2K'

escape_room_ascii = """\
 ___ _____                          ______       ______                    ___ 
|  _|  ___|                         |  _  \      | ___ \                  |_  |
| | | |__ ___  ___ __ _ _ __   ___  | | | |__ _  | |_/ /___  _ __ ___   ___ | |
| | |  __/ __|/ __/ _` | '_ \ / _ \ | | | / _` | |    // _ \| '_ ` _ \ / _ \| |
| | | |__\__ \ (_| (_| | |_) |  __/ | |/ / (_| | | |\ \ (_) | | | | | |  __/| |
| |_\____/___/\___\__,_| .__/ \___| |___/ \__,_| \_| \_\___/|_| |_| |_|\___|| |
|___|                  | |                                                |___|
                       |_|                                                     
"""

a_group_four_game_ascii = """\
     _____                           ___ 
    |  __ \                         /   |
    | |  \/_ __ ___  _   _ _ __    / /| |
    | | __| '__/ _ \| | | | '_ \  / /_| |
A   | |_\ \ | | (_) | |_| | |_) | \___  |  GAME
     \____/_|  \___/ \__,_| .__/      |_/
                          | |            
                          |_|                   
"""

iron_head_ascii = """\
 ___________ _____ _   _   _   _  _____  ___ ______ 
|_   _| ___ \  _  | \ | | | | | ||  ___|/ _ \|  _  \\
  | | | |_/ / | | |  \| | | |_| || |__ / /_\ \ | | |
  | | |    /| | | | . ` | |  _  ||  __||  _  | | | |
 _| |_| |\ \\\\ \_/ / |\\  | | | | || |___| | | | |/ / 
 \___/\_| \_|\___/\_| \_/ \_| |_/\____/\_| |_/___/   PRESENTS
                                                             
                                                             
"""


def ascii_art_clear():
    for i in range(9):
        sys.stdout.write(CURSOR_UP_ONE)
        sys.stdout.write(ERASE_LINE)


def ascii_art_print(ascii_art, level, output, rev=False):
    tmp_ascii_art = list(ascii_art)
    if level is not 15:
        for i in range(len(tmp_ascii_art)):
            if tmp_ascii_art[i] != '\n' and random.random() > level / 15.0:
                rand = random.random()
                if rand > 0.4:
                    tmp_ascii_art[i] = ' '
                elif rand > 0.2:
                    tmp_ascii_art[i] = '.'
                else:
                    tmp_ascii_art[i] = '\''
    output(''.join(tmp_ascii_art))


def run_start(output):
    time_slice = 0.08

    for i in range(16):
        ascii_art_print(iron_head_ascii, i, output=output)
        time.sleep(time_slice)
        if i is not 15:
            ascii_art_clear()

    time.sleep(2)

    for i in reversed(range(16)):
        ascii_art_clear()
        ascii_art_print(iron_head_ascii, i,output=output)
        time.sleep(time_slice)

    for i in range(16):
        ascii_art_clear()
        ascii_art_print(a_group_four_game_ascii, i,output=output)
        time.sleep(time_slice)

    time.sleep(2)

    for i in reversed(range(16)):
        ascii_art_clear()
        ascii_art_print(a_group_four_game_ascii, i,output=output)
        time.sleep(time_slice)

    for i in range(16):
        ascii_art_clear()
        ascii_art_print(escape_room_ascii, i, output=output)
        time.sleep(time_slice)
