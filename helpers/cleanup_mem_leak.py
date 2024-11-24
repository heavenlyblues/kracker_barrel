from multiprocessing.shared_memory import SharedMemory

leaked_name = "/psm_11a12201"  # Replace with the actual name from the warning
try:
    shm = SharedMemory(name=leaked_name)
    shm.close()  # Detach
    shm.unlink()  # Remove from the system
    print(f"Cleaned up leaked shared memory: {leaked_name}")
except FileNotFoundError:
    print(f"No such shared memory exists: {leaked_name}")
except Exception as e:
    print(f"Error cleaning up shared memory: {e}")