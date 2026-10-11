"""E2E fixture: delay a real worker so source snapshot races are observable."""

import time

from chirondb_ml_worker import main


time.sleep(2)
raise SystemExit(main())
