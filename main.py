from miasm.core.locationdb import LocationDB
from miasm.analysis.machine import Machine
from miasm.analysis.binary import Container
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.expression.simplifications import expr_simp
from miasm.expression.expression import *
from miasm.core.asmblock import asm_resolve_final
from miasm.expression.expression import ExprId
from miasm.core.asmblock import AsmBlock
from miasm.core.asmblock import AsmCFG
from miasm.core.asmblock import assemble_block
from miasm.ir.ir import IRCFG
from miasm.arch.x86.arch import instruction_x86


def LOG_MESSAGE(*msg):

    print("\u001b[36m", *msg, "\u001b[0m", sep="")

def LOG_WARN(*msg):
    
    print("\u001b[33m", *msg, "\u001b[0m", sep="")

def LOG_ERROR(*msg):

    print("\u001b[31m", *msg, "\u001b[0m", sep="")

def LOG_SUCCESS(*msg):

    print("\u001b[32m", *msg, "\u001b[0m", sep="")


# Create location DB
db_loc = LocationDB()

# Fetch the binary stream
file_bin = open("/home/unex/Dev/FiveM-Data/adhesive-v2-new.dll", "rb") # i personally hate adhesive

# Read binary file and determine the target machine
container = Container.from_stream(file_bin, db_loc)
machine = Machine(container.arch)

mdis = machine.dis_engine(container.bin_stream, loc_db=container.loc_db)
# mdis.follow_call = False
# mdis.dontdis_retcall = False

class Symbexec(SymbolicExecutionEngine):

    print_steps = False

    def __init__(self, dis_engine):
        
        self.mdis = dis_engine

        self.lifter = machine.lifter_model_call(dis_engine.loc_db)

        super().__init__(self.lifter)

    def set_cfg(self, cfg_asm):

        self.cfg = cfg_asm

        self.ircfg = self.lifter.new_ircfg_from_asmcfg(self.cfg)

    def execute(self, address):

        return self.run_block_at(self.ircfg, address, self.print_steps)

# Combines the splitted blocks by call routines
# returning the loc_key of head block and lines after collapsing
def combine_calls(asmcfg: AsmCFG, block: AsmBlock):

    lines = block.lines.copy()

    block_cur = block.loc_key
    while True: # insert all the blocks which are splitted because of a CALL
                # we need to assume those blocks are combined
        
        preds = asmcfg.predecessors(block_cur)

        for i in range(len(preds)):

            pred: AsmBlock = asmcfg.loc_key_to_block(preds[i])

            terminator: instruction_x86 = pred.lines[-1]

            if terminator.name == "CALL":

                lines_pred = pred.lines.copy()

                lines = lines_pred + lines

                block_cur = pred.loc_key

                break

            if i != (len(preds) - 1):
                continue

        else:

            break   

    return [ block_cur, lines ]

# Gets branch registers which store jump addresses
def get_branch_regs(lines):

    instr_jmp: instruction_x86 = lines[-1]

    if instr_jmp.name != "JMP": # branch instruction should be a jump
        return None

    reg_jmp = instr_jmp.args[0]

    if not isinstance(reg_jmp, ExprId):
        return None
    
    for i in range(len(lines) - 2, -1, -1):
        
        instr: instruction_x86 = lines[i]

        if instr.args[0] == reg_jmp: # first operand is destination on arithmetic operations
            
            if instr.name.startswith("CMOV"):

                return [ instr.args[1], reg_jmp ] # [ on_true, on_false ]
            
            else:

                return [ reg_jmp ]

    return None


def get_cfg(offset):

    return mdis.dis_multiblock(offset)    

def find_single_path(asmcfg: AsmCFG, loc_dst):

    path = [ loc_dst ]

    while True:

        preds = asmcfg.predecessors(path[0])

        if not preds:

            break

        pred = preds[0]

        path.insert(0, pred)

        if pred == asmcfg.heads()[0]:

            return path

    return []

def get_successors(asmcfg, block, state=None):

    addr_bl = block.get_offsets()[0]

    # Get the indirect jump register

    loc_block_head, lines = combine_calls(asmcfg, block)

    # is_call_node = len(lines) != len(block.lines) --> not needed for now

    jmp_regs = get_branch_regs(lines)

    is_conditional = (len(jmp_regs) == 2)

    if jmp_regs is None:

        LOG_WARN("[%r]: Couldn't find an indirect jump register on block %r" % (__name__, hex(addr_bl)))

        return None

    symbexec = Symbexec(mdis)

    loc_bl_ir_dest = None

    # First execute the parent path (which belongs to main CFG)

    symbexec.set_cfg(asmcfg)

    parent_path = find_single_path(asmcfg, loc_block_head)

    if parent_path: parent_path.pop()

    for bl_path_parent in parent_path:
        symbexec.execute(bl_path_parent)

    symbexec.set_cfg(get_cfg(asmcfg.loc_db.get_location_offset(loc_block_head)))

    for i in range(len(symbexec.ircfg.blocks)): # ? to-do ??

        loc_bl_ir = list(symbexec.ircfg.blocks)[i]

        bl_ir = symbexec.ircfg.get_block(loc_bl_ir)

        if is_conditional:

            [ jmp_reg_true, jmp_reg_false ] = jmp_regs

            if str(bl_ir).find("%s = %s\n\nIRDst =" % (str(jmp_reg_false), str(jmp_reg_true))) >= 0:

                loc_bl_ir_dest = loc_bl_ir

                break

        else:

            if str(bl_ir).find("IRDst = %s" % str(jmp_regs[0])) >= 0:
                loc_bl_ir_dest = loc_bl_ir         

    if loc_bl_ir_dest is None:

        LOG_ERROR("[%r]: Indirect jump register exists, but couldn't find an IR Block associated to a write attempt on block %r" % (__name__, hex(addr_bl)))

        return None

    # Now execute the inner path (which belongs to nested CFG)

    path_ir = symbexec.ircfg.find_path(loc_block_head, loc_bl_ir_dest)[0]

    # Now, execute all except the last one because
    # it modifies the jmp_reg_false to jmp_reg_true if it's a conditional jump

    if is_conditional:
        path_ir.pop()

    for bl_path_ir in path_ir:
        symbexec.execute(bl_path_ir)

    state = symbexec.get_state()

    for jmp_reg in jmp_regs:

        if jmp_reg not in state.symbols or not isinstance(state.symbols[jmp_reg], ExprInt):

            LOG_WARN("[%r]: Couldn't resolve indirect jump register(s) on block %r" % (__name__, hex(addr_bl)))

            return None

    return {
        "state": symbexec.get_state(),
        "successors": [state.symbols[jmp_reg] for jmp_reg in jmp_regs]
    }

def get_obfuscated_blocks(asmcfg):

    blocks_obf = []

    for block in asmcfg.blocks:

        if get_branch_regs(combine_calls(asmcfg, block)[1]) is not None:

            blocks_obf.append(block)

    return blocks_obf

def check_if_block_handled(asmcfg, offset):

    return any([ block.get_offsets()[0] == offset for block in asmcfg.blocks ])

def get_opposite_postfix(postfix):

    opposites = {

        "A": "BE",
        "B": "AE",
        "AE": "B",
        "BE": "A",
        "C": "NC",
        "NC": "C",
        "E": "NE",
        "NE": "E",
        "G": "LE",
        "LE": "G",
        "GE": "L",
        "L": "GE",
        "NO": "O",
        "O": "NO",
        "P": "NP",
        "NP": "P",
        "S": "NS",
        "NS": "S",
        "Z": "NZ",
        "NZ": "Z",
        "NA": "A",
        "NAE": "NB",
        "NB": "C",
        "NBE": "BE",
        "NG": "G",
        "NGE": "GE",
        "NL": "L",
        "NLE": "LE"

    }

    if postfix in opposites:
        return opposites[postfix]
    
    return None

def deobfuscate(asmcfg : AsmCFG, max_depth=None, depth=1):

    if (depth - 1) == max_depth: return None

    # Get obfuscated blocks

    blocks_obf = get_obfuscated_blocks(asmcfg)

    if len(blocks_obf) == 0:
        
        LOG_MESSAGE("[%r]: Nothing to deobfuscate." % __name__)

        return None

    LOG_MESSAGE("[%r]: Obfuscated block count on CFG is %i" % (__name__, len(blocks_obf)))

    for block_obf in blocks_obf:

        block_obf : AsmBlock

        addr_bl_obf = block_obf.get_offsets()[0]

        # Get following paths for block

        LOG_WARN("[%r]: Getting successors of block %r" % (__name__, hex(addr_bl_obf)))

        res = get_successors(asmcfg, block_obf) # to-do: Symbolic execution engine only executes on obfuscated block here. Previous block chain may hold required data for resolving!

        if res is None:
            
            LOG_ERROR("[%r]: Couldn't find any successors on block %r" % (__name__, hex(addr_bl_obf)))

            return None

        mem_next = block_obf.lines[-1].offset + block_obf.lines[-1].l
        
        # for _ln in block_obf.lines:

            # print("[%X]: %s - Length: %d" % ( _ln.offset, _ln, _ln.l ))

        is_conditional = len(res["successors"]) == 2

        if is_conditional:

            successor_true = res["successors"][0]
            successor_false = res["successors"][1]

            LOG_SUCCESS("[%r]: Successor (constraint = True) %r found on block %r" % (__name__, hex(int(successor_true)), hex(addr_bl_obf)))
            LOG_SUCCESS("[%r]: Successor (constraint = False) %r found on block %r" % (__name__, hex(int(successor_false)), hex(addr_bl_obf)))

            cfg_true = get_cfg(successor_true)
            cfg_false = get_cfg(successor_false)

            asmcfg.merge(cfg_true)
            asmcfg.merge(cfg_false)

            loc_key_block_true = list(cfg_true.blocks)[0].loc_key
            loc_key_block_false = list(cfg_false.blocks)[0].loc_key

            # Place direct jumps instead of indirect jumps to successors

            loc_key_to = None
            loc_key_next = None

            jmp_no_next = False # Indicates that neither 'true' or 'false' blocks of jump don't start with next offset 

            reg_on_true, reg_on_false = get_branch_regs(combine_calls(asmcfg, block_obf)[1])

            instr_jmp = block_obf.lines[-1]

            postfix = None

            for i in range(len(block_obf.lines) - 2, -1, -1):

                instr: instruction_x86 = block_obf.lines[i]

                if instr.name.startswith("CMOV") and instr.args[0] == reg_on_false:

                    postfix = instr.name[4:]

                    break

            if int(successor_true) == mem_next:
                
                postfix = get_opposite_postfix(postfix)
                
                loc_key_to = loc_key_block_false
                
                loc_key_next = loc_key_block_true

            else:

                loc_key_to = loc_key_block_true
                
                loc_key_next = loc_key_block_false

                if int(successor_false) != mem_next:

                    jmp_no_next = True

            if jmp_no_next:
                # ====================================
                # [0] CMOV(c) REG_ON_FALSE, REG_ON_TRUE
                # [1] JMP REG_ON_FALSE
                # ====================================
                # converted to:
                # ====================================
                # [0] J(c) REG_ON_TRUE
                # [1] JMP REG_ON_FALSE
                # ====================================

                # First, we need to make CMOV and JMP instructions adjacent

                for i in range(len(block_obf.lines) - 2, -1 -1):

                    instr: instruction_x86 = block_obf.lines[i]

                    if instr.name.startswith("CMOV") and instr.args[0] == reg_on_false:

                        block_obf.lines.pop(i)

                        block_obf.lines.insert(-1, instr)

                        break

                # Then, we need to re-assemble that block to fix instruction offsets

                # asmcfg.guess_blocks_size(mdis.arch)

                # assemble_block(mdis.arch, block_obf)

                # Now, all the offsets are correct; let's split the block at JMP instruction

                block_next = block_obf.split(block_obf.lines[-1].offset)

                asmcfg.add_block(block_next)

                # Now we have 2 blocks. First one will include conditional jump (on_true),
                # second one will include unconditional jump (on_false)

                instr_jmp = block_obf.lines[-1] # it's CMOV for now, gonna change it

                instr_jmp.name = "J" + postfix
                instr_jmp.args = [ ExprLoc(loc_key_to, 64) ]

                # Add constraints for the first block
                asmcfg.add_edge(block_obf.loc_key, loc_key_to, "c_to")
                asmcfg.add_edge(block_obf.loc_key, block_next.loc_key, "c_next")

                # Let's configure it for the second block as well
                instr_jmp = block_next.lines[-1]

                # instr_jmp.name = "JMP" # it's a JMP already
                instr_jmp.args[0] = ExprLoc(loc_key_next, 64)

                # Add constraint for the second block
                asmcfg.add_edge(block_next.loc_key, loc_key_next, "c_to")

                # Note:
                # loc_key_next usage was actually to indicate the next block loc_key.
                # But in this situation (no next jump in any of successors)
                # I used it to indicate 'on false' loc_key

            else:

                instr_jmp.name = "J" + postfix
                instr_jmp.args[0] = ExprLoc(loc_key_to, 64)

                # Add constraints
                asmcfg.add_edge(block_obf.loc_key, loc_key_to, "c_to")
                asmcfg.add_edge(block_obf.loc_key, loc_key_next, "c_next")

        else:
            
            successor = res["successors"][0]

            LOG_SUCCESS("[%r]: Successor %r found on block %r" % (__name__, hex(int(successor)), hex(addr_bl_obf)))

            cfg_next = get_cfg(successor)

            asmcfg.merge(cfg_next)

            loc_key_block_next = list(cfg_next.blocks)[0].loc_key

            # Place direct jumps instead of indirect jump to successor

            instr_jmp = block_obf.lines[-1]
            
            instr_jmp.args[0] = ExprLoc(loc_key_block_next, 64)

            if successor == mem_next:

                asmcfg.add_edge(block_obf.loc_key, loc_key_block_next, "c_next")

            else:

                asmcfg.add_edge(block_obf.loc_key, loc_key_block_next, "c_to")


    LOG_SUCCESS("[%r]: Resulting CFG: " % __name__, [ hex(bl.get_offsets()[0]) for bl in cfg.blocks ])

    LOG_SUCCESS("Control flow deobfuscation is completed. Depth: %i\n" % depth)

    depth += 1

    deobfuscate(cfg, max_depth, depth)

    return cfg


if __name__ == "__main__":
    
    LOG_SUCCESS("Main routine has started.\n")

    offset = 0x182489c60 # 0x18248b4a2

    cfg = get_cfg(offset)

    cfg_deobf = deobfuscate(cfg, 50)

    # addr = 0x181ff338c

    # [ cfg_res, list_pin ] = runOnBlock(addr)
    # cfg_res = fixChains(cfg_res, list_pin)

    for block in list(cfg_deobf.blocks):

        preds = cfg_deobf.predecessors(block.loc_key)

        for pred in preds:

            if cfg_deobf.edges2constraint[(pred, block.loc_key)] == "c_next":

                cfg_deobf.loc_db.unset_location_offset(block.loc_key)

                break

    cfg_deobf.graphviz().render("output")

    asm_res = asm_resolve_final(mdis.arch, cfg_deobf)