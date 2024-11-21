from miasm.analysis.machine import Machine
from miasm.analysis.binary import Container
from miasm.core.locationdb import LocationDB
from miasm.core.asmblock import AsmBlock
from miasm.arch.x86.arch import instruction_x86
from miasm.expression.expression import ExprLoc, ExprInt, ExprId, ExprOp, ExprMem
from miasm.core.asmblock import asm_resolve_final
from miasm.core import parse_asm

input_path = "/home/unex/Dev/ux-deobfuscator/binaries/miasm-tests.exe"
# output_path = "/home/unex/Dev/FiveM-Data/adhesive-v3.dll"

file_bin = open(input_path, "rb")

container = Container.from_stream(file_bin, LocationDB())

machine = Machine(container.arch)

mdis = machine.dis_engine(container.bin_stream, loc_db=container.loc_db)

if __name__ == "__main__":

    # offset = 0x140011780

    # cfg = mdis.dis_multiblock(offset)

    # cfg.graphviz().render("cfg-test")

    instr = instruction_x86(name="LEA", mode=64, args=[ ExprId("RCX", 64), ExprMem(ExprOp("+", ExprId("RIP", 64), ExprInt(0x10000000, 64)), 64) ])
    print(machine.mn.dis(machine.mn.asm(instr)[0], 64, 0))