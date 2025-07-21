import ida_segment
import ida_nalt
import ida_auto
import ida_kernwin

from tenet.util.log import pmsg

def rebase_database_manually(delta, new_base_address):
    """
    Manually rebase the database by moving each segment individually.
    This is a robust fallback for when rebase_program fails.
    """


    # 1. Collect segment information
    segments_info = []
    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if seg:
            segments_info.append({
                'seg': seg,
                'name': ida_segment.get_segm_name(seg),
                'start_ea': seg.start_ea,
                'new_start': seg.start_ea + delta
            })

    # 2. Sort segments to prevent overlaps during the move.
    segments_info.sort(key=lambda s: s['start_ea'], reverse=delta > 0)
    
    # 3. Move each segment
    for seg_info in segments_info:
        seg = seg_info['seg']
        new_start = seg_info['new_start']
        seg_name = seg_info['name']
        
        # Try to move with flags=2 first (preserves info)
        if not ida_segment.move_segm(seg, new_start, 2):
            # Check if it moved despite the error code (IDA API quirk)
            updated_seg = ida_segment.getseg(new_start)
            if not (updated_seg and ida_segment.get_segm_name(updated_seg) == seg_name):
                ida_kernwin.warning(f"Manual rebase failed: could not move segment '{seg_name}'.")
                return False

    #pmsg("All segments moved successfully in manual rebase.")
    return True

def rebase_database(new_base_address):
    """
    Rebase the program using a two-phase approach:
    1. Attempt a fast, simple rebase with rebase_program.
    2. If that fails, use a more robust manual segment-moving algorithm.
    """
    current_base = ida_nalt.get_imagebase()

    if current_base == new_base_address:
        pmsg("Database is already based at the target address.")
        return True

    delta = new_base_address - current_base

    if not ida_kernwin.ask_yn(
        ida_kernwin.ASKBTN_YES,
        f"A new base address (0x{new_base_address:X}) was found in the trace log. "
        f"Would you like to rebase the database from 0x{current_base:X}?\n\n"
        "(This is a permanent operation)"
    ):
        pmsg("Rebase operation cancelled by user.")
        return False

    # --- Phase 1: Fast Rebase ---
    #pmsg("Phase 1: Attempting fast rebase with rebase_program...")
    flags = 4  # MSF_FIXONCE: Fix up the program connections, etc.
    if ida_segment.rebase_program(delta, flags) == 0:
        pass
        #pmsg("rebase_program returned error, but checking if it worked anyway...")

    # --- Verification ---
    if ida_nalt.get_imagebase() == new_base_address:
        #pmsg("Phase 1 successful. Rerunning analysis...")
        ida_auto.auto_wait()
        return True

    #pmsg("Phase 1 failed. The database imagebase was not changed.")
    
    # --- Phase 2: Manual Fallback Rebase ---
    #pmsg("Phase 2: Falling back to manual segment-by-segment rebase...")
    if not rebase_database_manually(delta, new_base_address):
        ida_kernwin.warning("Manual rebase also failed. The database may be in an inconsistent state.")
        return False
        
    ida_nalt.set_imagebase(new_base_address)
    #pmsg("Rerunning analysis after manual rebase...")
    ida_auto.auto_wait()

    if ida_nalt.get_imagebase() == new_base_address:
        return True

    ida_kernwin.warning(f"Rebase failed. Current base 0x{ida_nalt.get_imagebase():X} does not match target 0x{new_base_address:X}.")
    return False