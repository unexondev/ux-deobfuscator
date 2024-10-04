from miasm.analysis.machine import Machine
from miasm.analysis.binary import Container
from miasm.core.locationdb import LocationDB
from miasm.core.asmblock import AsmBlock
from miasm.arch.x86.arch import instruction_x86
from miasm.expression.expression import ExprLoc, ExprInt, ExprId
from miasm.core.asmblock import asm_resolve_final

input_path = "/home/unex/Dev/FiveM-Data/adhesive-v2.dll"
output_path = "/home/unex/Dev/FiveM-Data/adhesive-v3.dll"

file_bin = open(input_path, "rb")

container = Container.from_stream(file_bin, LocationDB())

machine = Machine(container.arch)

mdis = machine.dis_engine(container.bin_stream, loc_db=container.loc_db)

def print_block(offset):

    entry = mdis.dis_block(offset)

    for line in entry.lines:
        print("\n")
        print("Name:", line.name)
        print("Args:", line.args)
        print("Length:", line.l)
        print("\n")


class a:
    el = False

if __name__ == "__main__":

    text = "allahuekberallahuekbervakittamamgelvakittamamgel"

    letter_data = {}

    for letter in text:

        if letter not in letter_data:

            letter_data[letter] = 0

        letter_data[letter] += 1

    print(letter_data)

    exit(0)

    offset = 0x181ff4050 # entry point

    cfg = mdis.dis_multiblock(offset)

    cfg.graphviz().render("entry-2")

    entry : AsmBlock = list(cfg.blocks)[0]

    # instr = entry.lines[0]

    # instr.name = "MOV"
    # instr.args = [ ExprId("RCX", 64), ExprInt(0x1234, 64) ]

    entry.lines.pop(1)
    entry.lines.pop(1)

    instr = machine.mn.dis(machine.mn.asm(instruction_x86(name="MOV", args=[ ExprId("RCX", 64), ExprId("RDX", 64) ], mode=64), loc_db=cfg.loc_db)[0], 64)

    entry.lines.append(instr)

    print(cfg.getby_offset(entry.get_range()[1] - 1))

    cfg.graphviz().render("entry-2-up")

    #instr.name = "JLE"
    #instr.args = [ ExprLoc(cfg.loc_db.get_or_create_offset_location(0x181ff4063), 64) ]

    bl = cfg.getby_offset(0x181ff406f)
    bl.lines.insert(0, bl.lines[0])

    for block in list(cfg.blocks):

        preds = cfg.predecessors(block.loc_key)

        for pred in preds:

            if len(preds) == 2:

                print(cfg.edges2constraint[(pred, block.loc_key)])

            if cfg.edges2constraint[(pred, block.loc_key)] == "c_next":

                cfg.loc_db.unset_location_offset(block.loc_key)

                break

    res = asm_resolve_final(machine.mn, cfg)

    bytes_file = bytearray(open("/home/unex/Dev/FiveM-Data/adhesive-v2.dll", "rb").read())

    for k, v in res.items():

        addr = container.bin_stream.bin.virt2off(k)

        list_bytes = list(v)

        for i in range(len(list_bytes)):

           bytes_file[addr + i] = list_bytes[i]

    open(output_path, "wb").write(bytes_file)

    # View it again

    file_bin = open(output_path, "rb")
    container = Container.from_stream(file_bin, LocationDB())
    machine = Machine(container.arch)
    mdis = machine.dis_engine(container.bin_stream, loc_db=container.loc_db)

    cfg = mdis.dis_multiblock(offset)

    entry : AsmBlock = list(cfg.blocks)[0]

    cfg.graphviz().render("entry-3")