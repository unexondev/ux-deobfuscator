from miasm.core.asmblock import AsmBlock, AsmCFG
from miasm.analysis.machine import Machine
from miasm.analysis.binary import Container
from miasm.core.locationdb import LocationDB
from miasm.ir.ir import AssignBlock, IRBlock, IRCFG
from miasm.expression.expression import ExprInt, ExprCond

# Create location DB
db_loc = LocationDB()

# Fetch the binary stream
file_bin = open("/home/unex/Dev/FiveM-Data/adhesive-v2-new.dll", "rb") # i personally hate adhesive

# Read binary file and determine the target machine
container = Container.from_stream(file_bin, db_loc)
machine = Machine(container.arch)

mdis = machine.dis_engine(container.bin_stream, loc_db=container.loc_db)

class DefUseOptions(object):

    allow_use_no_def = False

    def __init__(self): pass

class DefUse(object):

    def __init__(self, ircfg : IRCFG, irblock : IRBlock, options : DefUseOptions):

        self.ircfg = ircfg
        self.irblock = irblock
        self.options = options

    def is_defined_on(self, assignblk : AssignBlock, expr):

        # Omit ints and conditions because they are constant values

        if isinstance(expr, (ExprInt, ExprCond)):

            raise TypeError("Expression must be stored in memory, so not to be a constant value. (Expr: %r)" % str(expr))

        return expr in assignblk.keys()

    def is_used_on(self, assignblk : AssignBlock, expr):

        # Omit ints and conditions because they are constant values

        if isinstance(expr, (ExprInt, ExprCond)):

            raise TypeError("Expression must be stored in memory, so not to be a constant value. (Expr: %r)" % str(expr))

        return any([ (str(expr) in str(val)) for val in assignblk.values() ])

    def get_chain(self, expr):

        chain = {}

        def_cur = None
        for assignblk in self.irblock:

            if self.is_used_on(assignblk, expr):

                if not def_cur:

                    if not self.options.allow_use_no_def:

                        raise ValueError("A use of expression has found before definition. (Instr: %r)" % str(assignblk.instr))

                else:

                    chain[def_cur].append(assignblk.instr)

            if self.is_defined_on(assignblk, expr):

                def_cur = assignblk.instr

                chain[def_cur] = []

        return chain


if __name__ == "__main__":

    offset = 0x182489c60

    asmcfg = mdis.dis_multiblock(offset)

    lifter = machine.lifter_model_call(mdis.loc_db)
    ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)

    first_irblock = ircfg.get_block(offset)

    reg = first_irblock.assignblks[14].instr.args[0]

    options = DefUseOptions()
    options.allow_use_no_def = True
    defuse = DefUse(ircfg, first_irblock, options)
    
    chain = defuse.get_chain(reg)

    for _def in chain.keys():

        print("[---------------------------------------]")

        print("Definition: %r\n" % str(_def))

        print("Uses:\n")

        for use in chain[_def]:

            print(use)

        print("[---------------------------------------]")
