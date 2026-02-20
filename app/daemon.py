import os
import sys
from src.auth import reload_comanage

if __name__ == "__main__":
    if os.path.isfile("/app/reload"):
        print("reloading")
        result, status_code = reload_comanage()
        os.remove("/app/reload")
        print(f"reloaded {status_code} {result}")
    sys.exit(10)
