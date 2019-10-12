"""
Escape Room Core
"""
import asyncio
from Game_Bank.prompt import *
import pygame

file = "playmusic.mp3"
pygame.mixer.init()
track = pygame.mixer.music.load(file)
pygame.mixer.music.play()


def create_container_contents(*escape_room_objects):
    return {obj.name: obj for obj in escape_room_objects}


def listFormat(object_list):
    l = ["a " + object.name for object in object_list if object["visible"]]


class EscapeRoomObject:
    def __init__(self, name, **attributes):
        self.name = name
        self.attributes = attributes
        self.triggers = []

    def do_trigger(self, *trigger_args):
        return [event for trigger in self.triggers for event in [trigger(self, *trigger_args)] if event]

    def __getitem__(self, object_attribute):
        return self.attributes.get(object_attribute, False)

    def __setitem__(self, object_attribute, value):
        self.attributes[object_attribute] = value

    def __repr__(self):
        return self.name


class EscapeRoomCommandHandler:
    def __init__(self, room, player, output=print):
        self.room = room
        self.player = player
        self.output = output

    def _run_triggers(self, object, *trigger_args):
        for event in object.do_trigger(*trigger_args):
            self.output(event)

    def _cmd_look(self, look_args):
        look_result = None
        if len(look_args) == 0:
            object = self.room
        else:
            object = self.room["container"].get(look_args[-1], self.player["container"].get(look_args[-1], None))

        if not object or not object["visible"]:
            look_result = "You don't see that here."
        elif object["container"] != False and look_args and "in" == look_args[0]:
            if not object["open"]:
                look_result = "You can't do that! It's closed!"
            else:
                look_result = "Inside the {} you see: {}".format(object.name, listFormat(object["container"].values()))
        else:
            self._run_triggers(object, "look")
            look_result = object.attributes.get("description", "You see nothing special")
        self.output(look_result)

    def _cmd_unlock(self, unlock_args):
        unlock_result = None
        if len(unlock_args) == 0:
            unlock_result = "Unlock what?!"
        elif len(unlock_args) == 1:
            unlock_result = "Unlock {} with what?".format(unlock_args[0])

        else:
            object = self.room["container"].get(unlock_args[0], None)
            unlock = False

            if not object or not object["visible"]:
                unlock_result = "You don't see that here."
            elif not object["keyed"] and not object["keypad"]:
                unlock_result = "You can't unlock that!"
            elif not object["locked"]:
                unlock_result = "It's already unlocked"

            elif object["keyed"]:
                unlocker = self.player["container"].get(unlock_args[-1], None)
                if not unlocker:
                    unlock_result = "You don't have a {}".format(unlock_args[-1])
                elif unlocker not in object["unlockers"]:
                    unlock_result = "It doesn't unlock."
                else:
                    unlock = True

            elif object["keypad"]:
                # TODO: For later Exercise
                pass

            if unlock:
                unlock_result = "You hear a click! It worked!"
                object["locked"] = False
                self._run_triggers(object, "unlock", unlocker)
        self.output(unlock_result)

    def _cmd_open(self, open_args):
        """
        Let's demonstrate using some ands instead of ifs"
        """
        if len(open_args) == 0:
            return self.output("Open what?")
        object = self.room["container"].get(open_args[-1], None)

        success_result = "You open the {}.".format(open_args[-1])
        open_result = (
                ((not object or not object["visible"]) and "You don't see that.") or
                ((object["open"]) and "It's already open!") or
                ((object["locked"]) and "It's locked") or
                ((not object["openable"]) and "You can't open that!") or
                success_result)
        if open_result == success_result:
            object["open"] = True
            self._run_triggers(object, "open")
        self.output(open_result)

    def _cmd_get(self, get_args):
        if len(get_args) == 0:
            get_result = "Get what?"
        elif self.player["container"].get(get_args[0], None) != None:
            get_result = "You already have that"
        else:
            if len(get_args) > 1:
                container = self.room["container"].get(get_args[-1], None)
            else:
                container = self.room
            object = container["container"] and container["container"].get(get_args[0], None) or None

            success_result = "You got it"
            get_result = (
                    ((not container or container["container"] == False) and "You can't get something out of that!") or
                    ((container["openable"] and not container["open"]) and "It's not open.") or
                    ((not object or not object["visible"]) and "You don't see that") or
                    ((not object["gettable"]) and "You can't get that.") or
                    success_result)

            if get_result == success_result:
                container["container"].__delitem__(object.name)
                self.player["container"][object.name] = object
                self._run_triggers(object, "get", container)
        self.output(get_result)

    def _cmd_hit(self, hit_args):
        if not hit_args:
            return self.output("What do you want to hit?")
        target_name = hit_args[0]
        if target_name == "myself":
            if self.player.name == "player":
                target_name = "player"
            if self.player.name == "player2":
                target_name = "player2"
            if self.player.name == "player3":
                target_name = "player3"
        with_what_name = None
        if len(hit_args) != 1:
            with_what_name = hit_args[-1]

        target = self.room["container"].get(target_name, None)
        if not target or not target["visible"]:
            return self.output("You don't see a {} here.".format(target_name))
        if with_what_name:
            with_what = self.player["container"].get(with_what_name, None)
            if not with_what:
                return self.output("You don't have a {}".format(with_what_name))
        else:
            return self.output("With what?")

        if not target["hittable"]:
            return self.output("You can't hit that!")
        else:
            self.output("You hit the {} with the {}".format(target_name, with_what_name))
            if target_name == "flyingkey":
                self._run_triggers(target, "hit", with_what)
            elif target_name == "beast":
                self._run_triggers(target, "hitbeast", with_what)
            elif target_name == "lock":
                self._run_triggers(target, "hitlock", with_what)
            elif target_name == "player":
                self._run_triggers(target, "hitmyself", with_what)
            elif target_name == "player2":
                self._run_triggers(target, "hitmyself", with_what)
            elif target_name == "player3":
                self._run_triggers(target, "hitmyself", with_what)
            elif target_name == "gyroscope":
                self._run_triggers(target, "hitgyroscope", with_what)
            elif target_name == "steelchain":
                self._run_triggers(target, "hitsteelchain", with_what)

    def _cmd_inventory(self, inventory_args):
        """
        Use return statements to end function early
        """
        if len(inventory_args) != 0:
            self.output("What?!")
            return

        items = ", ".join(["a " + item for item in self.player["container"]])
        self._run_triggers(object, "inventory")
        self.output("You are carrying {}".format(items))

    # --------------------------------------------------tsts

    def _cmd_stand(self, stand_args):
        if not stand_args:
            return self.output("Stand on what?")
        target_name = stand_args[-1]

        target = self.room["container"].get(target_name, None)
        if not target or not target["standable"]:
            return self.output("You cannot stand on {}.".format(target_name))
        else:
            object1 = self.player["container"].get("axe", None)
            if not object1:
                self.output("you stand on {}, then you can get the axe!!".format(target_name))
                object = self.room["container"].get("axe", None)
                object["gettable"] = True
            else:
                self.output("You stand on {}. Nothing you can do. So you jump down.".format(target_name))

    def command(self, command_string):
        # no command
        if command_string.strip == "":
            return self.output("")

        command_args = command_string.split(" ")
        function = "_cmd_" + command_args[0]

        # unknown command
        if not hasattr(self, function):
            return self.output("You don't know how to do that.")

        # execute command dynamically
        getattr(self, function)(command_args[1:])
        self._run_triggers(self.room, "_post_command_", *command_args)


def create_room_description(room):
    room_data = {
        "mirror": room["container"]["mirror"].name,
        "clock_time": room["container"]["clock"]["time"],
        "interesting": ""
    }
    for item in room["container"].values():
        if item["interesting"]:
            room_data["interesting"] += "\n\t" + short_description(item)
    if room_data["interesting"]:
        room_data["interesting"] = "\nIn the room you see:" + room_data["interesting"]
    return """You are in a locked room. There is only one door
and it is locked. Above the door is a clock that reads {clock_time}.
Across from the door is a large {mirror}. Below the mirror is an old chest.

The room is old and musty and the floor is creaky and warped. This is not a simple game,
try to win this in another way? Like Inception {interesting}""".format(**room_data)


def create_door_description(door):
    description = "The door is strong and highly secured."
    if door["locked"]: description += " The door is locked."
    return description


def create_mirror_description(mirror, room):
    description = "You look in the mirror and see yourself."
    if "hairpin" in room["container"]:
        description += ".. wait, there's a hairpin in your hair. Where did that come from?"
    return description


def create_chest_description(chest):
    description = "An old chest. It looks worn, but it's still sturdy."
    if chest["locked"]:
        description += " And it appears to be locked."
    elif chest["open"]:
        description += " The chest is open."
    return description


def create_flyingkey_description(flyingkey):
    description = "A golden flying key with silver wings shimmering in the light"
    description += " is currently resting on the " + flyingkey["location"]
    return description


def create_flyingkey_short_description(flyingkey):
    return "A flying key on the " + flyingkey["location"]


def advance_time(room, clock):
    event = None
    clock["time"] = clock["time"] - 1
    if clock["time"] == 0:
        for object in room["container"].values():
            if object["alive"]:
                object["alive"] = False
        event = "Oh no! The clock reaches 0 and a deadly gas fills the room!"
    room["description"] = create_room_description(room)
    return event


def flyingkey_hit_trigger(room, flyingkey, key, output):
    if flyingkey["location"] == "ceiling":
        output("You can't reach it up there!")
    elif flyingkey["location"] == "floor":
        output("It's too low to hit.")
    else:
        flyingkey["flying"] = False
        del room["container"][flyingkey.name]
        room["container"][key.name] = key
        output(
            "The flying key falls off the wall. When it hits the ground, it's wings break off and you now see an ordinary key.")


# -------------------------------------------tsts
def beast_hit_trigger(beast, key, output):
    if beast["alive"] == True:
        beast["alive"] = False
        key["gettable"] = True
        output("You kill the beast and you find a shinning key in its hand. ")
    else:
        output("It is already dead. ")


def lock_hit_trigger(lock, beast, output):
    lock["locked"] = False
    output("The lock destroyed and the cage open. The beast comes out!!!")
    beast["locked"] = False
    beast["hittable"] = True
    output("You are defending the beast with axe, try to hit it.")

def player_hit_trigger(player, roomswitch, output):
    if roomswitch == 1:
        player["alive"] = False
        output("You dead!")
    if roomswitch == 2:
        output("You dead!")
        output("However, you find yourself awake suddenly. Seems like you come back to the first room!!")
        asyncio.ensure_future(gameswitch(switch=1))
    if roomswitch == 3:
        output("You dead!")
        output("However, you find yourself awake suddenly. Seems like you come back to the first room!!")
        asyncio.ensure_future(gameswitch(switch=2))


def player_open_trigger(door, roomswitch, output):
    #player["alive"] = False
    output("You open the door!!!")
    time.sleep(1)
    if roomswitch == 1:
        asyncio.ensure_future(gameswitch(switch=2))
        output("You feel a exdrodinary headache. Suddenly, you find that you are now in SECOND room!!")
    if roomswitch == 2:
        asyncio.ensure_future(gameswitch(switch=3))
        output("You feel a exdrodinary headache. Suddenly, you are now in THIRD room!!")
    if roomswitch == 3:
        asyncio.ensure_future(gameswitch(switch=3))
        output("You feel a exdrodinary headache. Suddenly, you are now in THIRD room!!")
    

# -----------------------------------------haolin
def steelchain_hit_trigger(player, steelchain, output):
    player["bleeding"] = True
    steelchain["broken"] = True
    output("Although you break the steelchain successfully. However, you hurt your legs accidentally!")


def short_description(object):
    if not object["short_description"]: return "a " + object.name
    return object["short_description"]


# --------------------------------------------------------------tsts
def create_room2_description(room):
    room_data = {
        "mirror": room["container"]["mirror"].name,
        "clock_time": room["container"]["clock"]["time"],
        "interesting": ""
    }
    for item in room["container"].values():
        if item["interesting"]:
            room_data["interesting"] += "\n\t" + short_description(item)
    if room_data["interesting"]:
        room_data["interesting"] = "\nIn the room you see:" + room_data["interesting"]
    return """You are in a locked room. It seems like it is a different room. But still, there is only one door
            and it is locked. Above the door is a clock that reads {clock_time}.
            Across from the door is a large {mirror}. Beside the mirror is an old cage.
            There ia a beast in the old cage trying to break out and the cage has a lock seems to be destroyed in a few seconds.
            You could also see an axe sticking on the celling above the cage.
            The key and hammer in your hand disappear but you still have hairpin. Perhaps you need to find another key and take a look at the beast.

            The room is old and musty and the floor is creaky and warped.{interesting}""".format(**room_data)


def create_cage_description(cage):
    description = "An old cage. It looks worn, and it's not sturdy."
    if cage["locked"]:
        description += " And it appears to be locked. You can see a beast in it and it will destory the cage soon. Will you try to stand on it?"
    elif cage["open"]:
        description += " The beast run out and nothing in the cage"
    return description


def create_beast_description(beast):
    description = """It is a bloody and giant beast, and it really wants to eat you as its dinner.
                        In its hand, you can see a shinning key. How can you get the key?"""
    if beast["locked"]:
        description += " It is in the cage."
    if not beast["locked"] and beast["alive"]:
        description += "It is approaching. Try too kill it or it will eat you!!!!!!"
    if not beast["alive"]:
        description += "Beast is dead."
    return description


def create_lock_description(lock):
    description = "It is a lock, and seems that you can hit it. It can be easily destroyed."
    if lock["locked"]:
        description += "It will be destroyed soon by the beast."
    if not lock["locked"]:
        description += "It is broken."
    return description


def create_axe_description(axe):
    description = "A nice axe with the sign of god of thunder."
    if not axe["gettable"]:
        description += "It is too high. Try to stand on something!"
    return description


def create_gyroscope_description(gyroscope):
    description = "This gyroscope is wired because it spins forever."
    if not gyroscope["hitted"]:
        description += "Try to hit it?"
    if gyroscope["hitted"]:
        description += "It is still spinning. Nothing happens"
    return description


# ---------------------------------------------------------------------------------------------haolin
def create_gun_description(gun):
    description = "A shotgun, you can use it to kill anyone, or, yourself."
    return description


def create_saw_description(saw):
    description = "A saw. People sometimes use it to do something cruel."
    return description


def create_bullet_description(bullet):
    description = "You see a bullet inside the magazine. Only one. So make up your mind before using it."
    return description


def create_steelchain_description(steelchain):
    description = "A steelchain is on your leg and you are chained up."
    if steelchain["broken"]:
        description = "A broken steelchain. You just broke it."
    return description


def create_room3_description(room3):
    return """You are in a dark room. There is no mirror or clock. You are lucky since the door is unlocked but you can't move around because you are chained up with a steelchain. 
    You see a gun and a saw in front of you. You might have seen that movie and you'd better know what I'm talking about. If you dont, you have
    to figure it out yourself. Good luck. """


class EscapeRoomGame:
    def __init__(self, command_handler_class=EscapeRoomCommandHandler, output=print):
        self.room, self.player = None, None
        self.output = output
        self.command_handler_class = command_handler_class
        self.command_handler = None
        self.agents = []
        self.status = "void"

    def create_game(self, roomswitch, cheat=False):
        clock = EscapeRoomObject("clock", visible=True, time=100, hittable=False)
        mirror = EscapeRoomObject("mirror", visible=True, standable=False, hittable=False)
        hairpin = EscapeRoomObject("hairpin", visible=False, gettable=True, standable=False, hittable=False)
        key = EscapeRoomObject("key", visible=True, gettable=True, interesting=True, standable=False, hittable=False)
        door = EscapeRoomObject("door", visible=True, openable=True, open=False, keyed=True, locked=True,
                                unlockers=[key], standable=False, hittable=False)
        chest = EscapeRoomObject("chest", visible=True, openable=True, open=False, keyed=True, locked=True,
                                 unlockers=[hairpin], standable=False)
        room = EscapeRoomObject("room", visible=True)
        hammer = EscapeRoomObject("hammer", visible=True, gettable=True)
        player = EscapeRoomObject("player", visible=True, alive=True, hittable = True, smashers=[hammer])
        flyingkey = EscapeRoomObject("flyingkey", visible=True, flying=True, hittable=False, smashers=[hammer],
                                     interesting=True, location="ceiling")

        # --------------------------------------------------------------------tsts
        room2 = EscapeRoomObject("room2", visible=True)
        axe = EscapeRoomObject("axe", visible=True, gettable=False, standable=False)
        cage = EscapeRoomObject("cage", visible=True, gettable=False, locked=True, open=False, standable=True)
        player2 = EscapeRoomObject("player2", visible=True, alive=True, hittable=True, smashers=[axe])
        lock = EscapeRoomObject("lock", visible=True, gettable=False, hittable=True, smashers=[axe], locked=True,
                                standable=False)
        beast = EscapeRoomObject("beast", visible=True, gettable=False, hittable=False, locked=True, smashers=[axe],
                                 standable=False, alive=True)
        gyroscope = EscapeRoomObject("gyroscope", visible=True, gettable=False, hittable=True, smashers=[axe],
                                     hitted=False, standable=False)

        # ---------------------------------------------------------------------------haolin
        room3 = EscapeRoomObject("room3", visible=True)
        gun = EscapeRoomObject("gun", visible=True, gettable=True, hittable=False, locked=False, standable=False)
        bullet = EscapeRoomObject("bullet", visible=False, gettable=False, hittable=False, locked=False,
                                  standable=False)
        saw = EscapeRoomObject("saw", visible=True, gettable=True, hittable=False, locked=False, standable=False)
        steelchain = EscapeRoomObject("steelchain", visible=True, gettable=False, hittable=True, smashers=[saw],
                                      broken=False)
        player3 = EscapeRoomObject("player3", visible=True, alive=True, hittable=True, smashers=[gun, saw], bleeding=False)


        # setup containers
        player["container"] = {}
        chest["container"] = create_container_contents(hammer)
        room["container"] = create_container_contents(player, door, clock, mirror, hairpin, flyingkey, chest)
        room2["container"] = create_container_contents(player2, door, clock, mirror, cage, lock, beast, axe, gyroscope,
                                                       hairpin)
        room3["container"] = create_container_contents(player3, door, gun, saw, steelchain, gyroscope)
        beast["container"] = create_container_contents(key)

        # -------------------------------------------------------------haolin
        gun["container"] = create_container_contents(bullet)

        # set initial descriptions (functions)
        player2["container"] = {"hairpin": hairpin}
        door["description"] = create_door_description(door)
        mirror["description"] = create_mirror_description(mirror, room)
        chest["description"] = create_chest_description(chest)
        flyingkey["description"] = create_flyingkey_description(flyingkey)
        flyingkey["short_description"] = create_flyingkey_short_description(flyingkey)
        key["description"] = "a golden key, cruelly broken from its wings."

        # --------------------------------------------------------tsts
        axe["description"] = create_axe_description(axe)
        cage["description"] = create_cage_description(cage)
        gyroscope["description"] = create_gyroscope_description(gyroscope)
        beast["description"] = create_beast_description(beast)
        lock["description"] = create_lock_description(lock)

        # ------------------------------------------------------------haolin
        player3["container"] = {}
        gun["description"] = create_gun_description(gun)
        saw["description"] = create_saw_description(saw)
        steelchain["description"] = create_steelchain_description(steelchain)
        bullet["description"] = create_bullet_description(bullet)

        # the room's description depends on other objects. so do it last
        room["description"] = create_room_description(room)
        room2["description"] = create_room2_description(room2)
        room3["description"] = create_room3_description(room3)

        mirror.triggers.append(lambda obj, cmd, *args: (cmd == "look") and hairpin.__setitem__("visible", True))
        mirror.triggers.append(lambda obj, cmd, *args: (cmd == "look") and mirror.__setitem__("description",
                                                                                              create_mirror_description(
                                                                                                  mirror, room)))
        door.triggers.append(lambda obj, cmd, *args: (cmd == "unlock") and door.__setitem__("description",
                                                                                            create_door_description(
                                                                                                door)))
        door.triggers.append(lambda obj, cmd, *args: (cmd == "open") and player_open_trigger(door, roomswitch, self.output))        
        room.triggers.append(lambda obj, cmd, *args: (cmd == "_post_command_") and advance_time(room, clock))
        flyingkey.triggers.append((lambda obj, cmd, *args: (cmd == "hit" and args[0] in obj[
            "smashers"]) and flyingkey_hit_trigger(room, flyingkey, key, self.output)))
        # TODO, the chest needs some triggers. This is for a later exercise
        # --------------------------------------tsts
        beast.triggers.append(lambda obj, cmd, *args: (cmd == "smashcage") and beast.__setitem__("locked", False))
        beast.triggers.append(lambda obj, cmd, *args: (cmd == "smashcage") and beast.__setitem__("hittable", True))
        lock.triggers.append(lambda obj, cmd, *args: (cmd == "smashlock") and lock.__setitem__("locked", False))
        lock.triggers.append((lambda obj, cmd, *args: (cmd == "hitlock" and args[0] in obj["smashers"]) and lock_hit_trigger(lock, beast, self.output)))
        beast.triggers.append((lambda obj, cmd, *args: (cmd == "hitbeast" and args[0] in obj["smashers"]) and beast_hit_trigger(beast, key, self.output)))
        player2.triggers.append((lambda obj, cmd, *args: (cmd == "hitmyself" and args[0] in obj["smashers"]) and player_hit_trigger(player2, roomswitch, self.output)))
        player3.triggers.append((lambda obj, cmd, *args: (cmd == "hitmyself" and args[0] in obj["smashers"]) and player_hit_trigger(player3, roomswitch, self.output)))
        player.triggers.append((lambda obj, cmd, *args: (cmd == "hitmyself" and args[0] in obj["smashers"]) and player_hit_trigger(player, roomswitch, self.output)))

        # ----------------------------------------haolin
        steelchain.triggers.append((lambda obj, cmd, *args: (cmd == "hitsteelchain" and args[0] in obj[
            "smashers"]) and steelchain_hit_trigger(player3, steelchain, self.output)))

        if roomswitch == 1:
            self.room, self.player = room, player
            self.command_handler = self.command_handler_class(room, player, self.output)
            self.agents.append(self.flyingkey_agent(flyingkey))
        if roomswitch == 2:
            self.room, self.player = room2, player2
            self.command_handler = self.command_handler_class(room2, player2, self.output)
            self.agents.append(self.beast_agent(beast, lock))
        if roomswitch == 3:
            self.room, self.player = room3, player3
            self.command_handler = self.command_handler_class(room3, player3, self.output)
            self.agents.append(self.blood_agent(player3,steelchain))

        self.status = "created"

    async def flyingkey_agent(self, flyingkey):
        random.seed(0)  # this should make everyone's random behave the same.
        await asyncio.sleep(5)  # sleep before starting the while loop
        while self.status == "playing" and flyingkey["flying"]:
            locations = ["ceiling", "floor", "wall"]
            locations.remove(flyingkey["location"])
            random.shuffle(locations)
            next_location = locations.pop(0)
            old_location = flyingkey["location"]
            flyingkey["location"] = next_location
            flyingkey["description"] = create_flyingkey_description(flyingkey)
            flyingkey["short_description"] = create_flyingkey_short_description(flyingkey)
            flyingkey["hittable"] = next_location == "wall"
            self.output("The {} flies from the {} to the {}".format(flyingkey.name, old_location, next_location))
            for event in self.room.do_trigger("_post_command_"):
                self.output(event)
            await asyncio.sleep(5)

    # -----------------------------------------tsts
    async def beast_agent(self, beast, lock):
        await asyncio.sleep(8)  # sleep before starting the while loop
        flag = 10
        while self.status == "playing" and beast["locked"]:
            self.output("The beast is destroying the lock which seems to break out soon. {} seconds left".format(flag))
            flag = flag - 2
            if flag == 0:               
                beast.do_trigger("smashcage")
                lock.do_trigger("smashlock")
                self.output("The beast breaks out, you are under attack!!!")
                object = self.player["container"].get("axe", None)
                if object:
                    self.output("You are defending the beast with axe, try to hit it.")
                else:
                    self.output("You do not have weapon. You become its dinner.")
                    await asyncio.sleep(3)
                    self.output(
                        "However, you find yourself awake suddenly. Seems like you come back to the first room!!")
                    self.status = "dead"
                    asyncio.ensure_future(gameswitch(switch=1))
            await asyncio.sleep(5)

    # -----------------------------------------haolin
    async def blood_agent(self, player, steelchain):
        while self.status == "playing":
            await asyncio.sleep(3)
            if steelchain["broken"]:
                await asyncio.sleep(3)  # sleep before starting the while loop
                flag = 100
                while self.status == "playing" and player["bleeding"]:
                    self.output("You are now bleeding. After {} seconds, you will die.".format(flag))
                    flag = flag - 5
                    if flag == 0:
                        self.output("You are dead!!") 
                        await asyncio.sleep(3)
                        self.output("However, you find yourself awake suddenly. Seems like you come back to the second room!!")
                        self.status = "dead"
                        asyncio.ensure_future(gameswitch(switch=2))
                    await asyncio.sleep(10)


    def start(self):
        self.status = "playing"
        self.output("Where are you? You don't know how you got here... Were you kidnapped? Better take a look around")

    def command(self, command_string):
        if self.status == "void":
            self.output("The world doesn't exist yet!")
        elif self.status == "created":
            self.output("The game hasn't started yet!")
        elif self.status == "dead":
            self.output("You already died! Sorry!")
        elif self.status == "escaped":
            self.output("You already escaped! The game is over!")
        else:
            self.command_handler.command(command_string)
            if not self.player["alive"]:
                self.status = "escaped"
                self.output("VICTORY! You escaped!")


def game_next_input(game):
    input = sys.stdin.readline().strip()
    game.command(input)
    if game.status != 'playing':
        asyncio.get_event_loop().stop()
    else:
        flush_output(">> ", end='')


def flush_output(*args, **kargs):
    print(*args, **kargs)
    sys.stdout.flush()


async def gameswitch(switch):
    loop = asyncio.get_event_loop()
    game = EscapeRoomGame(output=flush_output)
    if switch == 1:
        game.create_game(roomswitch=switch)
        game.start()
        flush_output(">> ", end='')
        loop.add_reader(sys.stdin, game_next_input, game)
        await asyncio.wait([asyncio.ensure_future(a) for a in game.agents])
    if switch == 2:
        game.create_game(roomswitch=switch)
        game.start()
        flush_output(">> ", end='')
        loop.add_reader(sys.stdin, game_next_input, game)
        await asyncio.wait([asyncio.ensure_future(a) for a in game.agents])
    if switch == 3:
        game.create_game(roomswitch=switch)
        game.start()
        flush_output(">> ", end='')
        loop.add_reader(sys.stdin, game_next_input, game)
        await asyncio.wait([asyncio.ensure_future(a) for a in game.agents])


if __name__ == "__main__":
    run_start()
    asyncio.ensure_future(gameswitch(switch=3))
    asyncio.get_event_loop().run_forever()

