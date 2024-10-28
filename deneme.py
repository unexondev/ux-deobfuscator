from miasm.analysis.machine import Machine
from miasm.analysis.binary import Container
from miasm.core.locationdb import LocationDB
from miasm.core.asmblock import AsmBlock
from miasm.arch.x86.arch import instruction_x86
from miasm.expression.expression import ExprLoc, ExprInt, ExprId
from miasm.core.asmblock import asm_resolve_final
from miasm.core import parse_asm

input_path = "/home/unex/Dev/ux-deobfuscator/binaries/miasm-tests.exe"
# output_path = "/home/unex/Dev/FiveM-Data/adhesive-v3.dll"

file_bin = open(input_path, "rb")

container = Container.from_stream(file_bin, LocationDB())

machine = Machine(container.arch)

mdis = machine.dis_engine(container.bin_stream, loc_db=container.loc_db)

if __name__ == "__main__":

    offset = 0x1400117c8

    cfg = mdis.dis_multiblock(offset)

    print(cfg.heads())

    cfg.graphviz().render("cfg-test")

    for block in list(cfg.blocks):

        preds = cfg.predecessors(block.loc_key)

        c_next = any(cfg.edges2constraint[(pred, block.loc_key)] == "c_next" for pred in preds)

        if c_next:

            cfg.loc_db.unset_location_offset(block.loc_key)

            print("Unset: 0x%X" % block.get_offsets()[0])

    asm_resolve_final(mdis.arch, cfg)