from miasm.analysis.sandbox import Sandbox_Win_x86_64
from miasm.core.locationdb import LocationDB
from miasm.analysis.dse import DSEPathConstraint
from miasm.os_dep.win_api_x86_32_seh import tib_address as TIB_ADDRESS
from miasm.jitter.csts import PAGE_READ, EXCEPT_ACCESS_VIOL
from miasm.jitter.jitload import Jitter

addr_base = 0x182489c60

addr_hook = 0x182489ceb

def create_page_buffer(size_page = 0x1000):
    buf = []
    for i in range(0, size_page):
        buf.append(0)
    return bytes(buf)

def configure_sandbox(file_name):

    loc_db = LocationDB()

    parser = Sandbox_Win_x86_64.parser()

    options = parser.parse_args()

    sandbox = Sandbox_Win_x86_64(fname=file_name, loc_db=loc_db, options=options)

    return sandbox


def handler_exception(jitter: Jitter):
    
    print("Invalid memory access occured at: %r" % hex(jitter.pc))

    jitter.vm.set_exception(0)

    print(dir(jitter.lifter))

    return False
    


sandbox = configure_sandbox("/home/unex/Dev/FiveM-Data/adhesive-v2.dll")

sandbox.jitter.lifter.do_all_segm = True

sandbox.jitter.cpu.GS = 0x1
sandbox.jitter.cpu.set_segm_base(sandbox.jitter.cpu.GS, TIB_ADDRESS)
sandbox.jitter.vm.add_memory_page(TIB_ADDRESS, PAGE_READ, create_page_buffer(), "GS Segment")

sandbox.jitter.add_exception_handler(EXCEPT_ACCESS_VIOL, handler_exception)

dse = DSEPathConstraint(sandbox.machine, sandbox.loc_db, DSEPathConstraint.PRODUCE_SOLUTION_PATH_COV)

# dse.add_handler(addr_hook, _callback)

sandbox.run(addr_base)